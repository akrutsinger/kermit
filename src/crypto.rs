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

// use aead::KeyInit;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chacha20::ChaCha20;
use cipher::{IvSizeUser, KeyIvInit, StreamCipher};
use hkdf::Hkdf;
use hmac::{Hmac, KeyInit, Mac};
use rand_core::{OsRng, RngCore};
use sha2::Sha256;

/// Number of recent nonces retained for replay detection.
pub const NONCE_WINDOW: usize = 4;
/// Length of the application-layer replay nonce that the driver prepends before sealing. This nonce
/// is also stored in a file to detect replays.
pub const APP_NONCE_LEN: usize = 8;

// ============================================================================
// Errors + the unifying trait
// ============================================================================

#[derive(Debug, PartialEq)]
pub enum ProtoError {
    TooShort,
    Mac,
    NoncePresent,
    Io,
}

#[cfg(debug_assertions)]
impl std::fmt::Display for ProtoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            ProtoError::TooShort => "input too short",
            ProtoError::Mac => "mac verification failed",
            ProtoError::NoncePresent => "nonce already present (replay detected)",
            ProtoError::Io => "nonce-file i/o failed",
        })
    }
}
#[cfg(debug_assertions)]
impl std::error::Error for ProtoError {}

pub trait Protocol {
    fn seal(&self, msg: &[u8]) -> Vec<u8>;
    fn open(&self, wire: &[u8]) -> Result<Vec<u8>, ProtoError>;
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
    let iv_len = S::iv_size();
    expand_short_nonce(iv_len, &tag[..n.min(iv_len)])
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
    let iv = vec![0u8; ChaCha20::iv_size()];

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
    _p: PhantomData<S>,
}
impl<S, const N: usize> StreamSiv<S, N> {
    pub fn new(base_key: &[u8]) -> Self {
        Self {
            enc_key: derive_enc_key(base_key),
            mac_key: derive_mac_key(base_key),
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
    fn overhead(&self) -> usize {
        N
    }
    fn guarantees(&self) -> &'static str {
        "conf + integrity (sym-auth); stateless SIV; N-byte tag also seeds IV"
    }
}
