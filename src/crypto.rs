//! Stateless authenticated-encryption envelope variants behind one `Protocol` trait, for analyzing
//! the wire-size <-> security tradeoff of different primitive stacks. Every variant is STATELESS:
//! each message carries all the receiver needs to open it, with no shared counter to keep in sync.
//!
//! The crypto layer operates on whatever bytes it is handed; the driver appends an 8-byte
//! application replay nonce ONCE (see [`prepend_nonce`](crate::crypto::prepend_nonce)) before
//! sealing, so the message every variant protects is `app_nonce(8) || message` and the reported
//! overhead is pure crypto expansion, never payload. The variants differ only in the envelope:
//!
//!   SignAead       sign-then-encrypt, AEAD tag       (+ non-repudiation; biggest)
//!   SignStream     sign-then-encrypt, stream cipher  (+ non-repudiation, no tag)
//!   AeadOnly       AEAD tag, random IV               (conf + sym-auth; textbook)
//!   SivShortNonce  AEAD-SIV, 4-byte random nonce     (conf + sym-auth; compact)
//!   StreamSiv<N>   stream cipher + truncated HMAC; the tag doubles as the IV
//!   StreamOnly     stream cipher, random IV, no auth (conf only; malleable)
//!   StreamRaw      stream cipher, fixed IV, no auth  (broken; size-floor demo)
//!
//! THE CENTRAL TRADEOFFS (why the table looks the way it does)
//!
//! * Authentication needs a SECRET key. An unkeyed hash/checksum over the ciphertext catches
//!   accidental corruption but is trivially forged by an active attacker (who just recomputes it)
//!   -- so it is NOT integrity. Every authenticated variant here uses a keyed MAC (HMAC) or a
//!   signature.
//!
//! * A stream cipher needs a UNIQUE nonce per message, or its keystream repeats and `ct1 ^ ct2`
//!   leaks `pt1 ^ pt2` (see StreamRaw / the nonce-reuse demo). A nonce buried in the *plaintext*
//!   does NOT help -- it is XORed by the same keystream. The nonce has to drive the cipher's IV
//!   input.
//!
//! * Stateless => the bytes that reconstruct the IV must be ON THE WIRE. The SIV variants make the
//!   single truncated tag do double duty: it is both the integrity check AND the IV seed. One
//!   shipped value, but it ties the two strengths together -- N shipped bytes give BOTH ~2^-8N
//!   forgery resistance AND a ~2^(4N) keystream-reuse birthday bound (capped at the cipher's IV
//!   width). You cannot ship 6 bytes and still get a strong 12-byte IV; the unsent bytes are
//!   invisible to the receiver.
//!
//! * Misuse-resistant AEAD (AES-GCM-SIV) is the one escape hatch: a nonce collision there costs
//!   only an equality leak, not a keystream break, which is why SivShortNonce survives on a 4-byte
//!   nonce where a raw stream cipher cannot.

use std::io::{Read, Seek, SeekFrom, Write};
use std::marker::PhantomData;

use aead::generic_array::typenum::Unsigned;
use aead::{AeadCore, AeadInPlace, KeyInit, Nonce, Tag};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chacha20::ChaCha20;
use cipher::{KeyIvInit, StreamCipher};
use ed25519_dalek::{SIGNATURE_LENGTH, Signature, Signer, SigningKey, VerifyingKey};
use hkdf::Hkdf;
use hmac::{Hmac, KeyInit as _, Mac};
use rand_core::{OsRng, RngCore};
use sha2::Sha256;

/// Number of recent nonces retained for replay detection.
pub const NONCE_WINDOW: usize = 4;
/// Length of the application-layer replay nonce that the driver prepends before sealing. This nonce
/// is also stored in a file to detect replays.
pub const APP_NONCE_LEN: usize = 8;
const SHORT_NONCE_LEN: usize = 4; // random bytes shipped by SivShortNonce
const SIG_LEN: usize = SIGNATURE_LENGTH; // 64

// ============================================================================
// Errors + the unifying trait
// ============================================================================

#[derive(Debug, PartialEq)]
pub enum ProtoError {
    TooShort,
    Aead,
    Mac,
    Signature,
    NoncePresent,
    Io,
}

impl std::fmt::Display for ProtoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            ProtoError::TooShort => "input too short",
            ProtoError::Aead => "aead authentication failed",
            ProtoError::Mac => "mac verification failed",
            ProtoError::Signature => "signature verification failed",
            ProtoError::NoncePresent => "nonce already present (replay detected)",
            ProtoError::Io => "nonce-file i/o failed",
        })
    }
}
impl std::error::Error for ProtoError {}

pub trait Protocol {
    fn seal(&self, msg: &[u8]) -> Vec<u8>;
    fn open(&self, wire: &[u8]) -> Result<Vec<u8>, ProtoError>;
    fn name(&self) -> &'static str;
    /// Fixed per-message wire expansion in bytes (computed from the primitives,
    /// not measured). Constant because every cipher here is stream/CTR-based.
    fn overhead(&self) -> usize;
    fn guarantees(&self) -> &'static str;
}

// ============================================================================
// Shared primitives
// ============================================================================

fn derive_key(base_key: &[u8], label: &[u8]) -> [u8; 32] {
    let mut k = [0u8; 32];
    Hkdf::<Sha256>::new(None, base_key)
        .expand(label, &mut k)
        .expect("32 <= 255*32");
    k
}

pub fn derive_enc_key(base_key: &[u8]) -> [u8; 32] {
    derive_key(base_key, b"seal:enc-key:v1")
}

/// Separate HMAC key from the same base, distinct HKDF label (key separation).
pub fn derive_mac_key(base_key: &[u8]) -> [u8; 32] {
    derive_key(base_key, b"seal:mac-key:v1")
}

/// HMAC-SHA256 over `data`, truncated to the leftmost `n` bytes.
fn mac_tag(mac_key: &[u8], data: &[u8], n: usize) -> Vec<u8> {
    let mut m = Hmac::<Sha256>::new_from_slice(mac_key).expect("any key length");
    m.update(data);
    m.finalize().into_bytes()[..n].to_vec()
}

/// Constant-time verify of a left-truncated HMAC-SHA256 tag.
fn mac_verify(mac_key: &[u8], data: &[u8], tag: &[u8]) -> bool {
    let mut m = Hmac::<Sha256>::new_from_slice(mac_key).expect("any key length");
    m.update(data);
    m.verify_truncated_left(tag).is_ok()
}

fn aead_nonce_len<A: AeadCore>() -> usize {
    <A::NonceSize as Unsigned>::USIZE
}
fn aead_tag_len<A: AeadCore>() -> usize {
    <A::TagSize as Unsigned>::USIZE
}
pub fn stream_iv_len<S: KeyIvInit>() -> usize {
    <S::IvSize as Unsigned>::USIZE
}

/// AEAD seal with a caller-supplied nonce -> (ciphertext, tag), detached tag.
pub fn aead_seal_with_nonce<A: KeyInit + AeadCore + AeadInPlace>(
    key: &[u8],
    nonce: &[u8],
    pt: &[u8],
) -> (Vec<u8>, Vec<u8>) {
    let cipher = A::new_from_slice(key).expect("32-byte key");
    let mut buf = pt.to_vec();
    let tag = cipher
        .encrypt_in_place_detached(Nonce::<A>::from_slice(nonce), b"", &mut buf)
        .expect("encrypt");
    (buf, tag.to_vec())
}

/// AEAD seal with a fresh random IV -> (iv, ciphertext, tag).
fn aead_seal<A: KeyInit + AeadCore + AeadInPlace>(
    key: &[u8],
    pt: &[u8],
) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let mut iv = vec![0u8; aead_nonce_len::<A>()];
    OsRng.fill_bytes(&mut iv);
    let (ct, tag) = aead_seal_with_nonce::<A>(key, &iv, pt);
    (iv, ct, tag)
}

/// Zero-pad `short` up to the cipher's full nonce width. Entropy stays at `short.len()` bytes --
/// that's the point: small wire cost, birthday-bounded collisions, which are non-catastrophic ONLY
/// under a misuse-resistant AEAD.
fn expand_short_nonce(len: usize, short: &[u8]) -> Vec<u8> {
    let mut n = vec![0u8; len];
    n[..short.len()].copy_from_slice(short);
    n
}

/// Synthetic IV for the SIV stream variants: take the `n`-byte tag and zero-pad its first `min(n,
/// iv_len)` bytes up to the cipher's full IV width. The IV therefore carries only `min(n, iv_len)`
/// bytes of entropy -- which is the whole point: shipping fewer tag bytes directly weakens
/// nonce-collision resistance, because the receiver can only rebuild the IV from wire bytes.
fn siv_iv<S: KeyIvInit>(tag: &[u8], n: usize) -> Vec<u8> {
    let iv_len = stream_iv_len::<S>();
    expand_short_nonce(iv_len, &tag[..n.min(iv_len)])
}

fn aead_open<A: KeyInit + AeadCore + AeadInPlace>(
    key: &[u8],
    iv: &[u8],
    ct: &[u8],
    tag: &[u8],
) -> Result<Vec<u8>, ProtoError> {
    let cipher = A::new_from_slice(key).expect("32-byte key");
    let mut buf = ct.to_vec();
    cipher
        .decrypt_in_place_detached(
            Nonce::<A>::from_slice(iv),
            b"",
            &mut buf,
            Tag::<A>::from_slice(tag),
        )
        .map_err(|_| ProtoError::Aead)?;
    Ok(buf)
}

/// Raw stream cipher (no integrity) -> (iv, ciphertext). `open` is the same XOR.
fn stream_seal<S: KeyIvInit + StreamCipher>(key: &[u8], pt: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let mut iv = vec![0u8; stream_iv_len::<S>()];
    OsRng.fill_bytes(&mut iv);
    let mut buf = pt.to_vec();
    let mut c = S::new_from_slices(key, &iv).expect("key/iv length");
    c.apply_keystream(&mut buf);
    (iv, buf)
}

fn stream_open<S: KeyIvInit + StreamCipher>(key: &[u8], iv: &[u8], ct: &[u8]) -> Vec<u8> {
    let mut buf = ct.to_vec();
    let mut c = S::new_from_slices(key, iv).expect("key/iv length");
    c.apply_keystream(&mut buf);
    buf
}

/// Application-layer framing: append an 8-byte replay nonce to the message. Called ONCE by the
/// driver before any crypto -- the `Protocol` impls treat the result as an opaque message and never
/// add a nonce of their own. (In the SIV variants this nonce is load-bearing: it is what makes the
/// synthetic IV differ between otherwise-identical messages. Elsewhere it is inert payload.)
pub fn prepend_nonce(msg: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(APP_NONCE_LEN + msg.len());
    let mut nonce = [0u8; APP_NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);
    buf.extend_from_slice(&nonce);
    buf.extend_from_slice(msg);
    buf
}

/// Verify the trailing ed25519 signature over the rest, returning the message
/// with only the SIGNATURE stripped. Any app nonce is part of the message
/// (folded in by the caller) and is left intact.
fn verify_and_unsign(vk: &VerifyingKey, plaintext: &[u8]) -> Result<Vec<u8>, ProtoError> {
    if plaintext.len() < SIG_LEN {
        return Err(ProtoError::TooShort);
    }
    let sig_start = plaintext.len() - SIG_LEN;
    let signed = &plaintext[..sig_start];
    let sig_bytes: [u8; SIG_LEN] = plaintext[sig_start..].try_into().unwrap();
    vk.verify_strict(signed, &Signature::from_bytes(&sig_bytes))
        .map_err(|_| ProtoError::Signature)?;
    Ok(signed.to_vec())
}

pub fn to_base64(data: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(data)
}

/// Check the `/tmp/nonce` ring buffer for `nonce`; return `Err(NoncePresent)` if found,
/// otherwise record it and return `Ok(())`.
///
/// On-disk layout: 33 bytes of ChaCha20-encrypted ring buffer. Fixed zero IV is safe because
/// the derived key is unique per session. Plaintext layout: `[head: u8][slot_0..slot_N-1]`.
pub fn check_and_record_nonce(nonce: &[u8], base_key: &[u8]) -> Result<(), ProtoError> {
    let n = nonce.len();
    let file_len = 1 + NONCE_WINDOW * n;
    let file_key = derive_key(base_key, b"nonce-file:key:v1");
    let iv = vec![0u8; stream_iv_len::<ChaCha20>()];

    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .open("/tmp/nonce")
        .map_err(|_| ProtoError::Io)?;

    let mut ring = vec![0u8; file_len];
    if file.read(&mut ring).map_err(|_| ProtoError::Io)? == file_len {
        ring = stream_open::<ChaCha20>(&file_key, &iv, &ring);
    }

    let head = (ring[0] as usize) % NONCE_WINDOW;

    for i in 0..NONCE_WINDOW {
        if &ring[1 + i * n..1 + (i + 1) * n] == nonce {
            return Err(ProtoError::NoncePresent);
        }
    }

    ring[1 + head * n..1 + (head + 1) * n].copy_from_slice(nonce);
    ring[0] = ((head + 1) % NONCE_WINDOW) as u8;

    file.seek(SeekFrom::Start(0)).map_err(|_| ProtoError::Io)?;
    file.write_all(&stream_open::<ChaCha20>(&file_key, &iv, &ring))
        .map_err(|_| ProtoError::Io)?;
    Ok(())
}

// ============================================================================
// Variant 1: SignAead  (sign-then-encrypt, AEAD)
//
// Cost/benefit: the most expensive (+100B here) -- random IV + AEAD tag + a 64-byte ed25519
// signature. Buys the full guarantee set: confidentiality, integrity, symmetric auth, AND
// non-repudiation (a third party can prove who sent it). Worth it only when non-repudiation is
// actually needed; otherwise the 64-byte signature is dead weight and AeadOnly gives the same
// secrecy. ============================================================================

pub struct SignAead<A> {
    enc_key: [u8; 32],
    signing: SigningKey,
    verifying: VerifyingKey,
    _p: PhantomData<A>,
}
impl<A> SignAead<A> {
    pub fn new(base_key: &[u8], signing: SigningKey) -> Self {
        let verifying = signing.verifying_key();
        Self {
            enc_key: derive_enc_key(base_key),
            signing,
            verifying,
            _p: PhantomData,
        }
    }
}
impl<A: KeyInit + AeadCore + AeadInPlace> Protocol for SignAead<A> {
    fn seal(&self, msg: &[u8]) -> Vec<u8> {
        let mut buf = msg.to_vec();
        let sig = self.signing.sign(msg); // over the message
        buf.extend_from_slice(&sig.to_bytes());
        let (iv, ct, tag) = aead_seal::<A>(&self.enc_key, &buf);
        [iv, ct, tag].concat()
    }
    fn open(&self, wire: &[u8]) -> Result<Vec<u8>, ProtoError> {
        let (iv_len, tag_len) = (aead_nonce_len::<A>(), aead_tag_len::<A>());
        if wire.len() < iv_len + tag_len + SIG_LEN {
            return Err(ProtoError::TooShort);
        }
        let iv = &wire[..iv_len];
        let tag = &wire[wire.len() - tag_len..];
        let ct = &wire[iv_len..wire.len() - tag_len];
        let pt = aead_open::<A>(&self.enc_key, iv, ct, tag)?;
        verify_and_unsign(&self.verifying, &pt)
    }
    fn name(&self) -> &'static str {
        "SignAead"
    }
    fn overhead(&self) -> usize {
        aead_nonce_len::<A>() + SIG_LEN + aead_tag_len::<A>()
    }
    fn guarantees(&self) -> &'static str {
        "conf + integrity + sym-auth + non-repudiation"
    }
}

// ============================================================================
// Variant 2: SignStream  (sign-then-encrypt, raw stream cipher, no tag)
//
// Cost/benefit: drops the AEAD tag vs SignAead and leans on the signature alone for integrity,
// saving the 16 tag bytes -- but still pays the 64-byte signature, so it is only marginally
// smaller. Downside: integrity is verified ONLY after decrypting the whole message (no cheap
// pre-decrypt reject of garbage). Non-repudiation without a symmetric tag.
// ============================================================================

pub struct SignStream<S> {
    enc_key: [u8; 32],
    signing: SigningKey,
    verifying: VerifyingKey,
    _p: PhantomData<S>,
}
impl<S> SignStream<S> {
    pub fn new(base_key: &[u8], signing: SigningKey) -> Self {
        let verifying = signing.verifying_key();
        Self {
            enc_key: derive_enc_key(base_key),
            signing,
            verifying,
            _p: PhantomData,
        }
    }
}
impl<S: KeyIvInit + StreamCipher> Protocol for SignStream<S> {
    fn seal(&self, msg: &[u8]) -> Vec<u8> {
        let mut buf = msg.to_vec();
        let sig = self.signing.sign(msg);
        buf.extend_from_slice(&sig.to_bytes());
        let (iv, ct) = stream_seal::<S>(&self.enc_key, &buf);
        [iv, ct].concat()
    }
    fn open(&self, wire: &[u8]) -> Result<Vec<u8>, ProtoError> {
        let iv_len = stream_iv_len::<S>();
        if wire.len() < iv_len + SIG_LEN {
            return Err(ProtoError::TooShort);
        }
        let pt = stream_open::<S>(&self.enc_key, &wire[..iv_len], &wire[iv_len..]);
        // Integrity here comes ONLY from the signature (checked post-decrypt).
        verify_and_unsign(&self.verifying, &pt)
    }
    fn name(&self) -> &'static str {
        "SignStream"
    }
    fn overhead(&self) -> usize {
        stream_iv_len::<S>() + SIG_LEN
    }
    fn guarantees(&self) -> &'static str {
        "conf + integrity + non-repudiation (no pre-decrypt reject)"
    }
}

// ============================================================================
// Variant 3: AeadOnly  (AEAD, random IV, no signature)
//
// Cost/benefit: the textbook stateless choice -- conf + integrity + symmetric auth with a full
// random IV shipped on the wire. No non-repudiation (anyone holding the key can forge, so the
// receiver can't prove the sender). Robust and simple; the price is a full-width IV (12B) + tag
// (16B) every message, with no nonce-management assumptions required of the caller.
// ============================================================================

pub struct AeadOnly<A> {
    enc_key: [u8; 32],
    _p: PhantomData<A>,
}
impl<A> AeadOnly<A> {
    pub fn new(base_key: &[u8]) -> Self {
        Self {
            enc_key: derive_enc_key(base_key),
            _p: PhantomData,
        }
    }
}
impl<A: KeyInit + AeadCore + AeadInPlace> Protocol for AeadOnly<A> {
    fn seal(&self, msg: &[u8]) -> Vec<u8> {
        let (iv, ct, tag) = aead_seal::<A>(&self.enc_key, msg);
        [iv, ct, tag].concat()
    }
    fn open(&self, wire: &[u8]) -> Result<Vec<u8>, ProtoError> {
        let (iv_len, tag_len) = (aead_nonce_len::<A>(), aead_tag_len::<A>());
        if wire.len() < iv_len + tag_len {
            return Err(ProtoError::TooShort);
        }
        let iv = &wire[..iv_len];
        let tag = &wire[wire.len() - tag_len..];
        let ct = &wire[iv_len..wire.len() - tag_len];
        aead_open::<A>(&self.enc_key, iv, ct, tag)
    }
    fn name(&self) -> &'static str {
        "AeadOnly"
    }
    fn overhead(&self) -> usize {
        aead_nonce_len::<A>() + aead_tag_len::<A>()
    }
    fn guarantees(&self) -> &'static str {
        "conf + integrity + sym-auth (no non-repudiation)"
    }
}

// ============================================================================
// Variant 4: StreamOnly  (raw stream cipher, random IV, no auth)
//
// Cost/benefit: confidentiality only. Ships a full random IV but NO tag, so it is malleable -- an
// attacker flips ciphertext bits and the receiver can't tell (see the tamper test, which it
// silently accepts). Cheaper than any authenticated variant only because it omits the one thing (a
// tag) that makes a channel safe against active tampering. Useful as the "conf, no integrity"
// baseline to measure the cost of authentication against.
// ============================================================================

pub struct StreamOnly<S> {
    enc_key: [u8; 32],
    _p: PhantomData<S>,
}
impl<S> StreamOnly<S> {
    pub fn new(base_key: &[u8]) -> Self {
        Self {
            enc_key: derive_enc_key(base_key),
            _p: PhantomData,
        }
    }
}
impl<S: KeyIvInit + StreamCipher> Protocol for StreamOnly<S> {
    fn seal(&self, msg: &[u8]) -> Vec<u8> {
        let (iv, ct) = stream_seal::<S>(&self.enc_key, msg);
        [iv, ct].concat()
    }
    fn open(&self, wire: &[u8]) -> Result<Vec<u8>, ProtoError> {
        let iv_len = stream_iv_len::<S>();
        if wire.len() < iv_len {
            return Err(ProtoError::TooShort);
        }
        // No integrity: this returns whatever the keystream produces, tampered
        // or not.
        Ok(stream_open::<S>(
            &self.enc_key,
            &wire[..iv_len],
            &wire[iv_len..],
        ))
    }
    fn name(&self) -> &'static str {
        "StreamOnly"
    }
    fn overhead(&self) -> usize {
        stream_iv_len::<S>()
    }
    fn guarantees(&self) -> &'static str {
        "conf only (malleable, no replay defense)"
    }
}

// ============================================================================
// Variant 5: StreamRaw  (raw stream cipher, fixed zero IV, no auth)
//
// Nothing goes on the wire except the ciphertext itself -- same length as the message, 0 overhead.
// The IV is all-zeros every message, so every seal uses the same keystream. Sending two messages
// under the same key XORs their plaintexts into the observable wire difference. Purely illustrative
// of the minimum possible wire cost; do not use for real traffic.
// ============================================================================

pub struct StreamRaw<S> {
    enc_key: [u8; 32],
    _p: PhantomData<S>,
}
impl<S> StreamRaw<S> {
    pub fn new(base_key: &[u8]) -> Self {
        Self {
            enc_key: derive_enc_key(base_key),
            _p: PhantomData,
        }
    }
}
impl<S: KeyIvInit + StreamCipher> Protocol for StreamRaw<S> {
    fn seal(&self, msg: &[u8]) -> Vec<u8> {
        let iv = vec![0u8; stream_iv_len::<S>()];
        let mut buf = msg.to_vec();
        S::new_from_slices(&self.enc_key, &iv)
            .expect("key/iv length")
            .apply_keystream(&mut buf);
        buf
    }
    fn open(&self, wire: &[u8]) -> Result<Vec<u8>, ProtoError> {
        let iv = vec![0u8; stream_iv_len::<S>()];
        let mut buf = wire.to_vec();
        S::new_from_slices(&self.enc_key, &iv)
            .expect("key/iv length")
            .apply_keystream(&mut buf);
        Ok(buf)
    }
    fn name(&self) -> &'static str {
        "StreamRaw"
    }
    fn overhead(&self) -> usize {
        0
    }
    fn guarantees(&self) -> &'static str {
        "conf only (fixed nonce; full keystream reuse every message)"
    }
}

// ============================================================================
// Variant 6: SivShortNonce  (short random nonce, zero-padded to full width)
//
// Stateless (no counter to desync). Ships SHORT_NONCE_LEN random bytes and zero-pads them to the
// cipher's nonce width. Collisions occur on the birthday bound of the SHORT space (~2^16 messages
// for 4 bytes), so this is sound ONLY with a misuse-resistant AEAD (AES-GCM-SIV), where a collision
// costs an equality leak rather than a confidentiality break. Do not instantiate with a plain AEAD.
// ============================================================================

pub struct SivShortNonce<A> {
    enc_key: [u8; 32],
    _p: PhantomData<A>,
}
impl<A> SivShortNonce<A> {
    pub fn new(base_key: &[u8]) -> Self {
        Self {
            enc_key: derive_enc_key(base_key),
            _p: PhantomData,
        }
    }
}
impl<A: KeyInit + AeadCore + AeadInPlace> Protocol for SivShortNonce<A> {
    fn seal(&self, msg: &[u8]) -> Vec<u8> {
        let mut short = [0u8; SHORT_NONCE_LEN];
        OsRng.fill_bytes(&mut short);
        let nonce = expand_short_nonce(aead_nonce_len::<A>(), &short);
        let (ct, tag) = aead_seal_with_nonce::<A>(&self.enc_key, &nonce, msg);
        [short.to_vec(), ct, tag].concat() // ship only the SHORT bytes
    }
    fn open(&self, wire: &[u8]) -> Result<Vec<u8>, ProtoError> {
        let tag_len = aead_tag_len::<A>();
        if wire.len() < SHORT_NONCE_LEN + tag_len {
            return Err(ProtoError::TooShort);
        }
        let short = &wire[..SHORT_NONCE_LEN];
        let body = &wire[SHORT_NONCE_LEN..];
        let ct = &body[..body.len() - tag_len];
        let tag = &body[body.len() - tag_len..];
        let nonce = expand_short_nonce(aead_nonce_len::<A>(), short);
        aead_open::<A>(&self.enc_key, &nonce, ct, tag)
    }
    fn name(&self) -> &'static str {
        "SivShortN"
    }
    fn overhead(&self) -> usize {
        SHORT_NONCE_LEN + aead_tag_len::<A>()
    }
    fn guarantees(&self) -> &'static str {
        "conf + integrity + sym-auth; 4B random nonce (collision = equality leak)"
    }
}

// ============================================================================
// Variant 7: StreamSiv  (stateless: synthetic IV derived from a truncated MAC)
//
// MAC-then-encrypt over whatever message it is handed (the driver has already folded in the app
// nonce). The HMAC is taken over the PLAINTEXT and the N bytes we ship do double duty: they are the
// integrity tag AND the seed for the cipher's IV. No counter to keep in sync (fully stateless).
//
// Why MAC the PLAINTEXT, not the ciphertext: the tag doubles as the IV, and an IV derived from the
// ciphertext would be circular (ct needs the IV, the IV would need MAC(ct), MAC(ct) needs ct). And
// it stays KEYED (HMAC) -- an unkeyed hash here would be forgeable and give no integrity at all.
//
// Per-message uniqueness comes entirely from the message: the synthetic IV is HMAC(msg)[..iv_len],
// so two messages encrypt differently only because their plaintexts differ. That difference is
// supplied by the app nonce the driver appended; re-seal a byte-identical message and the wire
// bytes repeat (deterministic; equality leak) -- which is exactly why the nonce must be there.
//
// The IV seed is the shipped tag, zero-padded up to the cipher's IV width when N < that width (12
// for ChaCha20). Because the receiver can only rebuild the IV from bytes that are ON THE WIRE, the
// N shipped bytes bound BOTH properties:
//
//   forgery resistance       ~ 2^(-8N)
//   keystream-reuse birthday ~ 2^(4N)         (capped at 2^48 once N >= 12)
//
// So you cannot "compute 12 bytes but send 6 and keep a strong IV": the unsent bytes are invisible
// to the receiver. (A misuse-resistant AEAD escapes this; a raw stream cipher cannot.)
// ============================================================================

pub struct StreamSiv<S, const N: usize> {
    enc_key: [u8; 32],
    mac_key: [u8; 32],
    label: &'static str,
    _p: PhantomData<S>,
}
impl<S, const N: usize> StreamSiv<S, N> {
    pub fn new(base_key: &[u8], label: &'static str) -> Self {
        Self {
            enc_key: derive_enc_key(base_key),
            mac_key: derive_mac_key(base_key),
            label,
            _p: PhantomData,
        }
    }
}
impl<S: KeyIvInit + StreamCipher, const N: usize> Protocol for StreamSiv<S, N> {
    fn seal(&self, msg: &[u8]) -> Vec<u8> {
        let tag = mac_tag(&self.mac_key, msg, N); // MAC over the message
        let iv = siv_iv::<S>(&tag, N); // synthetic IV, zero-padded if N < iv_len
        let mut ct = msg.to_vec();
        S::new_from_slices(&self.enc_key, &iv)
            .expect("key/iv length")
            .apply_keystream(&mut ct);
        let mut wire = tag;
        wire.extend_from_slice(&ct); // tag || ct
        wire
    }
    fn open(&self, wire: &[u8]) -> Result<Vec<u8>, ProtoError> {
        if wire.len() < N {
            return Err(ProtoError::TooShort);
        }
        let (tag, ct) = wire.split_at(N);
        let iv = siv_iv::<S>(tag, N);
        let mut buf = ct.to_vec();
        S::new_from_slices(&self.enc_key, &iv)
            .expect("key/iv length")
            .apply_keystream(&mut buf); // recover plaintext
        // Recompute the MAC over the recovered plaintext; constant-time check
        // that its leading N bytes equal the tag we used as the IV seed. A flip
        // in either the tag or the ciphertext breaks this.
        if !mac_verify(&self.mac_key, &buf, tag) {
            return Err(ProtoError::Mac);
        }
        Ok(buf)
    }
    fn name(&self) -> &'static str {
        self.label
    }
    fn overhead(&self) -> usize {
        N
    }
    fn guarantees(&self) -> &'static str {
        "conf + integrity (sym-auth); stateless SIV; N-byte tag also seeds IV"
    }
}
