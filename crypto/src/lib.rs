//! A stateless authenticated-encryption envelope: [`StreamAead`].
//!
//! Stateless means each message carries everything the receiver needs to open it; there is no
//! shared counter or session state to keep in sync. [`Protocol::seal`] turns a message into wire
//! bytes and [`Protocol::open`] reverses it, rejecting anything that fails authentication.
//!
//! # The envelope
//!
//! [`StreamAead<S, NONCE_LEN, TAG_LEN>`] is encrypt-then-MAC with an explicit per-message nonce.
//! `seal` draws a fresh random `NONCE_LEN`-byte nonce, uses it as the stream cipher's IV
//! (zero-padded to the cipher's IV width), encrypts, then MACs `nonce ‖ ciphertext`. The wire
//! layout is `nonce(NONCE_LEN) ‖ tag(TAG_LEN) ‖ ciphertext` and the crypto overhead is `NONCE_LEN +
//! TAG_LEN` bytes. `S` is the stream cipher (e.g. ChaCha20); `NONCE_LEN` and `TAG_LEN` are
//! independent width knobs.
//!
//! # Usage
//!
//! The crypto layer produces and parses the wire nonce; the driver only checks it for replays:
//!
//! ```ignore
//! let proto = StreamAead::<ChaCha20, 8, 4>::new(base_key)?;
//! let wire  = proto.seal(message)?;               // -> nonce ‖ tag ‖ ciphertext
//! // ...send `wire`, then on the receiver...
//! let (nonce, message) = proto.open(&wire)?;       // verify tag, decrypt (or Err)
//! // reject replays, gated behind open(); the ring is persisted by the platform layer
//! common::with_locked_ring(|ring| check_and_record_nonce(ring, &nonce, base_key))?;
//! ```
//!
//! Callers that cannot allocate (embedded) use [`StreamAead::seal_into`] and
//! [`StreamAead::open_into`], which write into caller-owned buffers instead of returning `Vec`s;
//! [`StreamAead::OVERHEAD`] sizes them. The `Vec`-returning [`Protocol`] methods above are thin
//! wrappers over that core.
//!
//! # Why it is shaped this way
//!
//! * Authentication needs a secret key. An unkeyed hash over the ciphertext catches accidental
//!   corruption, but an active attacker can just recompute it, so it provides no integrity.
//!   `StreamAead` uses a keyed MAC (HMAC-SHA256).
//!
//! * A stream cipher needs a unique nonce per message, or its keystream repeats and `ct1 ^ ct2`
//!   leaks `pt1 ^ pt2`. The explicit nonce drives the cipher's IV directly, so byte-identical
//!   messages still encrypt differently.
//!
//! * Encrypt-then-MAC over `nonce ‖ ciphertext` lets the receiver verify before it decrypts, so the
//!   cipher never runs on unauthenticated bytes. The nonce is in the MAC input, so an attacker
//!   cannot swap the cleartext nonce to steer decryption without invalidating the tag.
//!
//! * `NONCE_LEN` and `TAG_LEN` are decoupled. `NONCE_LEN` governs keystream-reuse resistance (a
//!   random `NONCE_LEN`-byte nonce collides at the ~2^(4*NONCE_LEN) birthday bound); `TAG_LEN`
//!   governs forgery resistance (~2^(8*TAG_LEN)). Size each against its own threat; neither pays
//!   for the other. The default `NONCE_LEN = 8` gives a ~2^32 keystream-reuse bound — ample below
//!   ~2^16 messages, the scale this protocol targets.
//!
//! * `StreamAead` is randomized, not deterministic: the fresh nonce makes re-sealing the same
//!   message produce different wire bytes, so there is no equality leak.

#![cfg_attr(not(test), no_std)]

extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;
use core::marker::PhantomData;

use chacha20::ChaCha20;
use cipher::{KeyIvInit, StreamCipher};
use getrandom::fill;
use hkdf::Hkdf;
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;

/// Number of recent nonces retained for replay detection.
pub const NONCE_WINDOW: usize = 4;

/// ChaCha20 (IETF variant) uses a 96-bit nonce.
const CHACHA20_NONCE_LEN: usize = 12;

// Errors and the unifying trait.

#[derive(Debug, PartialEq)]
pub enum ProtoError {
    TooShort,
    BufferTooSmall,
    Mac,
    NoncePresent,
    Io,
    Init,
}

impl core::fmt::Display for ProtoError {
    fn fmt(&self, _f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        #[cfg(debug_assertions)]
        match self {
            ProtoError::TooShort => _f.write_str("input too short")?,
            ProtoError::BufferTooSmall => _f.write_str("output buffer too small")?,
            ProtoError::Mac => _f.write_str("mac verification failed")?,
            ProtoError::NoncePresent => _f.write_str("nonce already present (replay detected)")?,
            ProtoError::Io => _f.write_str("i/o error")?,
            ProtoError::Init => _f.write_str("crypto primitive init failed")?,
        }
        Ok(())
    }
}

impl core::error::Error for ProtoError {}

/// Lets `check_and_record_nonce` run inside `common::with_locked_ring`, whose own storage failures
/// surface as `ProtoError::Io`.
impl From<common::IoError> for ProtoError {
    fn from(_: common::IoError) -> Self {
        ProtoError::Io
    }
}

/// The seal/open envelope interface: turn a message into authenticated wire bytes and back.
pub trait Protocol {
    /// Turn `msg` into wire bytes: draw a fresh nonce, encrypt, then MAC. Returns
    /// `nonce ‖ tag ‖ ciphertext`.
    fn seal(&self, msg: &[u8]) -> Result<Vec<u8>, ProtoError>;
    /// Verify and decrypt `wire`, returning `(nonce, plaintext)`. The nonce is returned because the
    /// driver needs it for replay detection (see [`check_and_record_nonce`]).
    fn open(&self, wire: &[u8]) -> Result<(Vec<u8>, Vec<u8>), ProtoError>;
}

// Shared primitives.

fn derive_key(base_key: &[u8], label: &[u8]) -> Result<[u8; 32], ProtoError> {
    let mut k = [0u8; 32];
    Hkdf::<Sha256>::new(None, base_key)
        .expand(label, &mut k)
        .map_err(|_| ProtoError::Init)?;
    Ok(k)
}

/// Separate encryption key from the same base, distinct HKDF label (key separation).
pub fn derive_enc_key(base_key: &[u8]) -> Result<[u8; 32], ProtoError> {
    derive_key(base_key, b"seal:enc-key:v1")
}

/// Separate HMAC key from the same base, distinct HKDF label (key separation).
pub fn derive_mac_key(base_key: &[u8]) -> Result<[u8; 32], ProtoError> {
    derive_key(base_key, b"seal:mac-key:v1")
}

/// HMAC-SHA256 over the concatenation of `parts`, writing the leftmost `out.len()` bytes of the tag
/// into `out`. Taking the parts as a slice lets callers MAC `nonce ‖ ct` without a joined buffer,
/// and writing into `out` keeps it allocation-free. `out.len()` must be `<= 32` (the digest width).
fn compute_tag_into(mac_key: &[u8], parts: &[&[u8]], out: &mut [u8]) -> Result<(), ProtoError> {
    let mut m = Hmac::<Sha256>::new_from_slice(mac_key).map_err(|_| ProtoError::Init)?;
    for part in parts {
        m.update(part);
    }
    let full = m.finalize().into_bytes();
    out.copy_from_slice(&full[..out.len()]);
    Ok(())
}

/// Constant-time verify of a left-truncated HMAC-SHA256 tag over the concatenation of `parts`.
fn verify_tag(mac_key: &[u8], parts: &[&[u8]], tag: &[u8]) -> Result<(), ProtoError> {
    let mut m = Hmac::<Sha256>::new_from_slice(mac_key).map_err(|_| ProtoError::Init)?;
    for part in parts {
        m.update(part);
    }
    m.verify_truncated_left(tag).map_err(|_| ProtoError::Mac)
}

/// Widest stream-cipher IV the stack-buffer paths size for (XChaCha20 is 24; ChaCha20 is 12).
/// `StreamAead::new` rejects any cipher whose `iv_size()` exceeds this.
const MAX_IV_LEN: usize = 24;

/// Zero-pad `short` into a stack buffer wide enough for any supported cipher's IV; callers slice it
/// to the cipher's actual `iv_size()`. Entropy stays at `short.len()` bytes, the rest zero, which
/// keeps the wire cost small at the cost of birthday-bounded nonce collisions.
fn stack_iv(short: &[u8]) -> [u8; MAX_IV_LEN] {
    let mut iv = [0u8; MAX_IV_LEN];
    iv[..short.len()].copy_from_slice(short);
    iv
}

/// XOR `buf` in place with the keystream from cipher `S`. Used where a heap allocation for a new
/// buffer would be wasteful (e.g. the nonce ring buffer in `check_and_record_nonce`).
fn stream_xor_in_place<S: KeyIvInit + StreamCipher>(
    key: &[u8],
    iv: &[u8],
    buf: &mut [u8],
) -> Result<(), ProtoError> {
    S::new_from_slices(key, iv)
        .map_err(|_| ProtoError::Init)?
        .apply_keystream(buf);
    Ok(())
}

/// Check the nonce `ring` for `nonce`; return `Err(NoncePresent)` if found, otherwise record it and
/// return `Ok(())`. The slot size follows `nonce.len()`, so the same length must be used for the
/// lifetime of a given `base_key`'s ring (it is fixed by the `StreamAead` `NONCE_LEN` parameter).
///
/// Pure: `ring` is the stored bytes (empty the first time), and the caller persists whatever is
/// left in it -- normally by calling this inside `common::with_locked_ring`, which holds the lock
/// across the whole read-check-write. Stored layout: `1 + NONCE_WINDOW * nonce.len()` bytes of
/// ChaCha20-encrypted ring buffer. Fixed zero IV is safe because the derived key is unique per
/// session. Plaintext layout: `[head: u8][slot_0..slot_N-1]`.
pub fn check_and_record_nonce(
    ring: &mut Vec<u8>,
    nonce: &[u8],
    base_key: &[u8],
) -> Result<(), ProtoError> {
    let n = nonce.len();
    let file_len = 1 + NONCE_WINDOW * n;
    let file_key = derive_key(base_key, b"nonce-file:key:v1")?;
    let iv = [0u8; CHACHA20_NONCE_LEN];

    // A ring of the expected length is prior (encrypted) content to decrypt; anything else (a new or
    // malformed store) starts from a zero ring.
    if ring.len() == file_len {
        stream_xor_in_place::<ChaCha20>(&file_key, &iv, ring)?;
    } else {
        ring.clear();
        ring.resize(file_len, 0);
    }

    let head = (ring[0] as usize) % NONCE_WINDOW;

    for i in 0..NONCE_WINDOW {
        if &ring[1 + i * n..1 + (i + 1) * n] == nonce {
            return Err(ProtoError::NoncePresent);
        }
    }

    ring[1 + head * n..1 + (head + 1) * n].copy_from_slice(nonce);
    ring[0] = ((head + 1) % NONCE_WINDOW) as u8;

    stream_xor_in_place::<ChaCha20>(&file_key, &iv, ring)
}

/// Stateless authenticated-encryption envelope: encrypt-then-MAC with an explicit random nonce.
///
/// The MAC covers `nonce ‖ ciphertext` (encrypt-then-MAC), the composition with the strongest
/// generic-composition guarantees: the receiver authenticates before decrypting, so the cipher
/// never touches unauthenticated bytes, and the nonce is bound into the tag so it cannot be
/// swapped.
///
/// The forgery bound of ~2^-8*TAG_LEN is exercised, not just asserted: `forge_chosen_plaintext` in
/// the tests mounts a black-box chosen-plaintext forgery using only the `open` oracle plus one
/// known plaintext, landing an attacker-chosen message in ~2^8*TAG_LEN tries. That is why a small
/// TAG_LEN is weak against an attacker who can hammer the oracle, and why picking TAG_LEN is a
/// threat-model decision.
pub struct StreamAead<S, const NONCE_LEN: usize, const TAG_LEN: usize> {
    enc_key: [u8; 32],
    mac_key: [u8; 32],
    _p: PhantomData<S>,
}

impl<S: KeyIvInit + StreamCipher, const NONCE_LEN: usize, const TAG_LEN: usize>
    StreamAead<S, NONCE_LEN, TAG_LEN>
{
    /// Wire overhead added to every message: the `nonce ‖ tag` prefix. A sealed message is
    /// `OVERHEAD + msg.len()` bytes; size the output of [`seal_into`](Self::seal_into) with it.
    pub const OVERHEAD: usize = NONCE_LEN + TAG_LEN;

    pub fn new(base_key: &[u8]) -> Result<Self, ProtoError> {
        // TAG_LEN is the truncated-HMAC width; HMAC-SHA256 yields 32 bytes, so a larger TAG_LEN
        // would slice past the digest and panic in `compute_tag_into`. NONCE_LEN must be non-empty.
        // Both are wrapped in `const` so an out-of-range value is a compile-time error rather than
        // a runtime panic.
        const {
            assert!(
                TAG_LEN >= 1 && TAG_LEN <= 32,
                "StreamAead TAG_LEN must be in 1..=32"
            )
        };
        const { assert!(NONCE_LEN >= 1, "StreamAead NONCE_LEN must be >= 1") };

        // The nonce is zero-padded up to the cipher's IV width in a MAX_IV_LEN stack buffer, so the
        // nonce can be no wider than the IV width and the IV width no wider than MAX_IV_LEN.
        // `iv_size` is not const-evaluable, so these are runtime checks.
        let iv_size = S::iv_size();
        if iv_size > MAX_IV_LEN || NONCE_LEN > iv_size {
            return Err(ProtoError::Init);
        }

        Ok(Self {
            enc_key: derive_enc_key(base_key)?,
            mac_key: derive_mac_key(base_key)?,
            _p: PhantomData,
        })
    }

    /// Draw a fresh nonce and seal `msg` into `out` as `nonce ‖ tag ‖ ciphertext`, returning the
    /// total byte length written. Allocation-free counterpart to [`Protocol::seal`]: `out` must
    /// hold at least `OVERHEAD + msg.len()` bytes or this returns [`ProtoError::BufferTooSmall`].
    pub fn seal_into(&self, msg: &[u8], out: &mut [u8]) -> Result<usize, ProtoError> {
        let mut nonce = [0u8; NONCE_LEN];
        fill(&mut nonce).map_err(|_| ProtoError::Init)?;
        self.seal_into_with_nonce(nonce, msg, out)
    }

    /// Core of `seal_into` with the nonce supplied by the caller. Tests use it directly to pin a
    /// deterministic wire vector.
    fn seal_into_with_nonce(
        &self,
        nonce: [u8; NONCE_LEN],
        msg: &[u8],
        out: &mut [u8],
    ) -> Result<usize, ProtoError> {
        let total = Self::OVERHEAD + msg.len();
        if out.len() < total {
            return Err(ProtoError::BufferTooSmall);
        }

        let (nonce_out, rest) = out[..total].split_at_mut(NONCE_LEN);
        let (tag_out, ct_out) = rest.split_at_mut(TAG_LEN);

        nonce_out.copy_from_slice(&nonce);
        ct_out.copy_from_slice(msg);
        let iv = stack_iv(&nonce);
        S::new_from_slices(&self.enc_key, &iv[..S::iv_size()])
            .map_err(|_| ProtoError::Init)?
            .apply_keystream(ct_out);

        // Encrypt-then-MAC: authenticate the nonce and the ciphertext.
        compute_tag_into(&self.mac_key, &[&*nonce_out, &*ct_out], tag_out)?;
        Ok(total)
    }

    /// Verify and decrypt `wire`, writing the plaintext into `out`. Returns the nonce (borrowed
    /// from `wire`, for replay detection) and the plaintext length. Allocation-free counterpart to
    /// [`Protocol::open`]: `out` must hold at least `wire.len() - OVERHEAD` bytes.
    pub fn open_into<'w>(
        &self,
        wire: &'w [u8],
        out: &mut [u8],
    ) -> Result<(&'w [u8], usize), ProtoError> {
        if wire.len() < Self::OVERHEAD {
            return Err(ProtoError::TooShort);
        }
        let nonce = &wire[..NONCE_LEN];
        let tag = &wire[NONCE_LEN..Self::OVERHEAD];
        let ct = &wire[Self::OVERHEAD..];
        if out.len() < ct.len() {
            return Err(ProtoError::BufferTooSmall);
        }

        // Encrypt-then-MAC: verify before touching the cipher, so a forgery never reaches decrypt.
        verify_tag(&self.mac_key, &[nonce, ct], tag)?;

        let pt = &mut out[..ct.len()];
        pt.copy_from_slice(ct);
        let iv = stack_iv(nonce);
        S::new_from_slices(&self.enc_key, &iv[..S::iv_size()])
            .map_err(|_| ProtoError::Init)?
            .apply_keystream(pt);
        Ok((nonce, ct.len()))
    }

    /// Allocating `seal` with the nonce supplied by the caller, used only by tests to pin a
    /// deterministic wire vector.
    #[cfg(test)]
    fn seal_with_nonce(&self, nonce: [u8; NONCE_LEN], msg: &[u8]) -> Result<Vec<u8>, ProtoError> {
        let mut wire = vec![0u8; Self::OVERHEAD + msg.len()];
        self.seal_into_with_nonce(nonce, msg, &mut wire)?;
        Ok(wire)
    }
}

impl<S: KeyIvInit + StreamCipher, const NONCE_LEN: usize, const TAG_LEN: usize> Protocol
    for StreamAead<S, NONCE_LEN, TAG_LEN>
{
    fn seal(&self, msg: &[u8]) -> Result<Vec<u8>, ProtoError> {
        let mut wire = vec![0u8; Self::OVERHEAD + msg.len()];
        self.seal_into(msg, &mut wire)?;
        Ok(wire)
    }

    fn open(&self, wire: &[u8]) -> Result<(Vec<u8>, Vec<u8>), ProtoError> {
        if wire.len() < Self::OVERHEAD {
            return Err(ProtoError::TooShort);
        }
        let mut pt = vec![0u8; wire.len() - Self::OVERHEAD];
        let (nonce, _) = self.open_into(wire, &mut pt)?;
        Ok((nonce.to_vec(), pt))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chacha20::ChaCha20;
    use common::dbgprintln;

    const KEY: &[u8] = b"kermit-crypto-unit-test-base-key";
    const MSG: &[u8] = b"hello, kermit!";
    const NONCE_LEN: usize = 8;
    const TAG_LEN: usize = 4;

    fn proto() -> StreamAead<ChaCha20, NONCE_LEN, TAG_LEN> {
        StreamAead::<ChaCha20, NONCE_LEN, TAG_LEN>::new(KEY).unwrap()
    }

    #[test]
    fn round_trip() {
        let p = proto();
        let wire = p.seal(MSG).unwrap();
        assert_eq!(wire.len(), NONCE_LEN + TAG_LEN + MSG.len());
        let (nonce, pt) = p.open(&wire).unwrap();
        assert_eq!(nonce.len(), NONCE_LEN);
        assert_eq!(pt, MSG);
    }

    #[test]
    fn into_round_trip() {
        // The allocation-free path over caller-owned buffers round-trips, and the nonce it returns
        // is the wire prefix the replay check needs.
        type P = StreamAead<ChaCha20, NONCE_LEN, TAG_LEN>;
        let p = proto();

        let mut wire = [0u8; P::OVERHEAD + MSG.len()];
        let n = p.seal_into(MSG, &mut wire).unwrap();
        assert_eq!(n, wire.len());

        let mut pt = [0u8; MSG.len()];
        let (nonce, len) = p.open_into(&wire, &mut pt).unwrap();
        assert_eq!(nonce, &wire[..NONCE_LEN]);
        assert_eq!(&pt[..len], MSG);
    }

    #[test]
    fn seal_into_rejects_small_buffer() {
        type P = StreamAead<ChaCha20, NONCE_LEN, TAG_LEN>;
        let p = proto();
        let mut too_small = [0u8; P::OVERHEAD + MSG.len() - 1];
        assert_eq!(
            p.seal_into(MSG, &mut too_small),
            Err(ProtoError::BufferTooSmall)
        );
    }

    #[test]
    fn tamper_rejected() {
        let p = proto();
        let mut wire = p.seal(MSG).unwrap();
        *wire.last_mut().unwrap() ^= 0x01;
        assert_eq!(p.open(&wire), Err(ProtoError::Mac));
    }

    #[test]
    fn nonce_swap_rejected() {
        // The nonce is in the MAC input, so flipping a cleartext-nonce byte fails the gate rather
        // than silently steering decryption to a different keystream.
        let p = proto();
        let mut wire = p.seal(MSG).unwrap();
        wire[0] ^= 0x01;
        assert_eq!(p.open(&wire), Err(ProtoError::Mac));
    }

    #[test]
    fn too_short() {
        let p = proto();
        assert_eq!(
            p.open(&[0u8; NONCE_LEN + TAG_LEN - 1]),
            Err(ProtoError::TooShort)
        );
    }

    #[test]
    fn unique_per_seal() {
        // A fresh random nonce per seal means the same message encrypts differently every time: no
        // equality leak.
        let p = proto();
        assert_ne!(p.seal(MSG).unwrap(), p.seal(MSG).unwrap());
    }

    /// Mount the chosen-plaintext forgery against `StreamAead<ChaCha20, NONCE_LEN, TAG_LEN>` and
    /// return how many tag guesses were tried before the victim accepted our chosen message. This
    /// is not a blind forgery that accepts unpredictable garbage: it gets a message of the
    /// attacker's choosing accepted without the keys.
    ///
    /// It needs one captured message whose plaintext is known, plus the `open` accept/reject
    /// oracle.
    ///
    /// Because it is a stream cipher, ct = pt XOR keystream(iv), so a known (pt, ct) pair yields
    /// the keystream for that nonce. Reusing the captured nonce reuses that keystream, letting the
    /// attacker encrypt an arbitrary chosen plaintext of the same length under it. All that is left
    /// is the TAG_LEN-byte MAC over `nonce ‖ ct`: its correct value is fixed but unknown, so the
    /// attacker brute-forces the tag field until `open` accepts. Expected work is ~2^8*TAG_LEN,
    /// isolating TAG_LEN as the sole forgery knob: practical for TAG_LEN=1 (~256) and TAG_LEN=2
    /// (~65k), slow for TAG_LEN=3 (~16M), infeasible for TAG_LEN>=4.
    ///
    /// The attack never references enc_key/mac_key/compute_tag; it only calls `seal` (to model
    /// capturing a legit message) and `open` (the victim's decrypt).
    fn forge_chosen_plaintext<const NONCE_LEN: usize, const TAG_LEN: usize>() -> u64 {
        let p = StreamAead::<ChaCha20, NONCE_LEN, TAG_LEN>::new(KEY).unwrap();

        // (1) Legit capture. `legit_pt` is the known plaintext.
        let legit_pt = b"pay alice 5 coins";
        let wire = p.seal(legit_pt).unwrap();
        let nonce = &wire[..NONCE_LEN];
        let ct = &wire[NONCE_LEN + TAG_LEN..];

        // (2) Recover the keystream for this nonce: ks = ct XOR pt.
        let ks: Vec<u8> = ct.iter().zip(legit_pt).map(|(c, m)| c ^ m).collect();

        // (3) The message the attacker wants accepted, same length as the legit one so the
        // recovered keystream lines up. Encrypting it under the reused nonce fixes the ciphertext,
        // so the only unknown left is the tag.
        let forged_pt = b"PAY EVE 999 coins";
        assert_eq!(forged_pt.len(), legit_pt.len());
        assert_ne!(&forged_pt[..], &legit_pt[..]);
        let ct_forged: Vec<u8> = forged_pt.iter().zip(&ks).map(|(m, k)| m ^ k).collect();

        // Brute-force the TAG_LEN-byte tag field. The correct tag is a single fixed value, so
        // exhausting the 2^8*TAG_LEN space is guaranteed to hit it.
        let cap: u64 = 1u64 << (8 * TAG_LEN as u64);
        for guess in 0..cap {
            let tag_bytes = &guess.to_le_bytes()[..TAG_LEN];
            let mut wire_forged = Vec::with_capacity(NONCE_LEN + TAG_LEN + ct_forged.len());
            wire_forged.extend_from_slice(nonce);
            wire_forged.extend_from_slice(tag_bytes);
            wire_forged.extend_from_slice(&ct_forged);

            if let Ok((_n, pt)) = p.open(&wire_forged) {
                // The oracle accepted our chosen, meaningful plaintext, not garbage.
                assert_eq!(pt, forged_pt);
                return guess;
            }
        }
        panic!("no {TAG_LEN}-byte tag found in {cap} tries");
    }

    #[test]
    fn one_byte_tag_chosen_plaintext_forgery() {
        let tries = forge_chosen_plaintext::<8, 1>();
        dbgprintln!("TAG_LEN=1 chosen-plaintext forgery succeeded after {tries} tries");
    }

    #[test]
    fn two_byte_tag_chosen_plaintext_forgery() {
        let tries = forge_chosen_plaintext::<8, 2>();
        dbgprintln!("TAG_LEN=2 chosen-plaintext forgery succeeded after {tries} tries");
    }

    // ~16M tries (~2^24): correct but slow, so it is opt-in. Run with:
    //   cargo test -p crypto --release three_byte_tag -- --ignored --nocapture
    #[test]
    #[ignore = "brute-forces ~2^24 candidates; run explicitly"]
    fn three_byte_tag_chosen_plaintext_forgery() {
        let tries = forge_chosen_plaintext::<8, 3>();
        dbgprintln!("TAG_LEN=3 chosen-plaintext forgery succeeded after {tries} tries");
    }

    // ~4B tries (~2^32): correct but slow, so it is opt-in. Run with:
    //   cargo test -p crypto --release four_byte_tag -- --ignored --nocapture
    #[test]
    #[ignore = "brute-forces ~2^32 candidates; run explicitly"]
    fn four_byte_tag_chosen_plaintext_forgery() {
        let tries = forge_chosen_plaintext::<8, 4>();
        dbgprintln!("TAG_LEN=4 chosen-plaintext forgery succeeded after {tries} tries");
    }

    #[test]
    fn replay_check_accepts_first_seen_nonce() {
        let key = b"replay-test-key-first-seen-0000";
        let mut ring = Vec::new();
        assert!(check_and_record_nonce(&mut ring, &[1u8; 8], key).is_ok());
    }

    #[test]
    fn replay_check_rejects_immediate_replay() {
        let key = b"replay-test-key-immediate-00000";
        let nonce = [2u8; 8];
        let mut ring = Vec::new();
        assert!(check_and_record_nonce(&mut ring, &nonce, key).is_ok());
        assert_eq!(
            check_and_record_nonce(&mut ring, &nonce, key),
            Err(ProtoError::NoncePresent)
        );
    }

    #[test]
    fn replay_check_wraps_and_evicts_oldest() {
        let key = b"replay-test-key-wraparound-0000";
        // Start at 1: an all-zero nonce would be indistinguishable from a fresh, never-written ring
        // slot (both are all-zero bytes), which isn't what this test means to exercise.
        let nonces: Vec<[u8; 8]> = (1..=NONCE_WINDOW + 1).map(|i| [i as u8; 8]).collect();
        let mut ring = Vec::new();
        for nonce in &nonces {
            assert!(check_and_record_nonce(&mut ring, nonce, key).is_ok());
        }
        // NONCE_WINDOW + 1 distinct nonces have been recorded, so the first one has been evicted by
        // wraparound; it's accepted again instead of rejected as a replay.
        assert!(check_and_record_nonce(&mut ring, &nonces[0], key).is_ok());
    }

    #[test]
    fn wire_format_snapshot() {
        // Golden vector pinning the on-wire bytes for the fixed KEY/MSG/NONCE_LEN/TAG_LEN above,
        // with a fixed nonce injected so the output is deterministic (nonce(8) ‖ tag(4) ‖ ct(14)).
        // Regenerate intentionally if the envelope changes.
        let p = proto();
        let nonce = [0x11u8; NONCE_LEN];
        let expected: [u8; NONCE_LEN + TAG_LEN + MSG.len()] = [
            0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x03, 0x95, 0x88, 0x55, 0xf4, 0xbd,
            0x0a, 0x9a, 0xe2, 0xf4, 0x2c, 0x10, 0xdf, 0xcf, 0x57, 0x9a, 0x2b, 0x9b,
        ];
        assert_eq!(p.seal_with_nonce(nonce, MSG).unwrap(), expected);
    }
}
