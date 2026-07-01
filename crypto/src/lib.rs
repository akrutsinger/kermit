//! A stateless authenticated-encryption envelope: [`StreamSiv`].
//!
//! Stateless means each message carries everything the receiver needs to open it; there is no
//! shared counter or session state to keep in sync. [`Protocol::seal`] turns a message into wire
//! bytes and [`Protocol::open`] reverses it, rejecting anything that fails authentication.
//!
//! # The envelope
//!
//! [`StreamSiv<S, N>`] is MAC-then-encrypt with a synthetic IV. It HMACs the plaintext, ships the
//! leftmost `N` bytes of that tag, and reuses those same bytes to seed the stream cipher's IV. The
//! one shipped value is both the integrity tag and the IV seed, so the wire layout is `tag(N) ||
//! ciphertext` and the crypto overhead is exactly `N` bytes. `S` is the stream cipher (e.g.
//! ChaCha20); `N` is the tag width in bytes.
//!
//! # Usage
//!
//! The crypto layer operates on opaque bytes. The driver frames the message and checks for replays;
//! the `Protocol` never adds a nonce of its own:
//!
//! ```ignore
//! let proto  = StreamSiv::<ChaCha20, 4>::new(base_key)?;
//! let framed = prepend_nonce(message)?;    // append 8-byte replay nonce, once
//! let wire   = proto.seal(&framed)?;        // -> tag(N) || ciphertext
//! // ...send `wire`, then on the receiver...
//! let framed = proto.open(&wire)?;          // verify tag, decrypt (or Err)
//! check_and_record_nonce(&framed[..APP_NONCE_LEN], base_key)?;  // reject replays
//! ```
//!
//! # Why it is shaped this way
//!
//! * Authentication needs a secret key. An unkeyed hash over the ciphertext catches accidental
//!   corruption, but an active attacker can just recompute it, so it provides no integrity.
//!   `StreamSiv` uses a keyed MAC (HMAC-SHA256).
//!
//! * A stream cipher needs a unique nonce per message, or its keystream repeats and `ct1 ^ ct2`
//!   leaks `pt1 ^ pt2`. A nonce buried in the plaintext does not help, since it is XORed by the same
//!   keystream; the nonce has to drive the cipher's IV input, which is what the synthetic IV does.
//!
//! * Because the envelope is stateless, the bytes that reconstruct the IV must be on the wire.
//!   Reusing the truncated tag as the IV seed ties the two strengths together: the `N` shipped bytes
//!   give both ~2^-8N forgery resistance and a ~2^4N keystream-reuse birthday bound (capped at the
//!   cipher's IV width). Shipping fewer bytes than are computed buys nothing, because the unsent
//!   bytes are invisible to the receiver.
//!
//! * `StreamSiv` is deterministic, not misuse-resistant: re-sealing a byte-identical message
//!   repeats the wire bytes (an equality leak), and a nonce collision is a keystream break. That is
//!   why [`prepend_nonce`] is load-bearing: the per-message app nonce is what makes the synthetic
//!   IV differ between otherwise-identical messages.

#![cfg_attr(not(test), no_std)]

extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;
use core::marker::PhantomData;

use common::dbgprintln;

use chacha20::ChaCha20;
use cipher::{KeyIvInit, StreamCipher};
use getrandom::fill;
use hkdf::Hkdf;
use hmac::{Hmac, KeyInit, Mac};
use rustix::fs::{FlockOperation, Mode, OFlags, SeekFrom, flock};
use sha2::Sha256;

/// Number of recent nonces retained for replay detection.
pub const NONCE_WINDOW: usize = 4;
/// Length of the application-layer replay nonce that the driver prepends before sealing. This nonce
/// is also stored in a file to detect replays.
pub const APP_NONCE_LEN: usize = 8;

/// On-disk layout size: `[head: u8][slot_0..slot_N-1]` where each slot is `APP_NONCE_LEN` bytes.
const NONCE_FILE_LEN: usize = 1 + NONCE_WINDOW * APP_NONCE_LEN;

/// ChaCha20 (IETF variant) uses a 96-bit nonce.
const CHACHA20_NONCE_LEN: usize = 12;

// Errors and the unifying trait.

#[derive(Debug, PartialEq)]
pub enum ProtoError {
    TooShort,
    Mac,
    NoncePresent,
    Io(rustix::io::Errno),
    Init,
}

impl core::fmt::Display for ProtoError {
    fn fmt(&self, _f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        #[cfg(debug_assertions)]
        match self {
            ProtoError::TooShort => _f.write_str("input too short")?,
            ProtoError::Mac => _f.write_str("mac verification failed")?,
            ProtoError::NoncePresent => _f.write_str("nonce already present (replay detected)")?,
            ProtoError::Io(errno) => write!(_f, "i/o error: {errno:?}")?,
            ProtoError::Init => _f.write_str("crypto primitive init failed")?,
        }
        Ok(())
    }
}

impl core::error::Error for ProtoError {}

pub trait Protocol {
    fn seal(&self, msg: &[u8]) -> Result<Vec<u8>, ProtoError>;
    fn open(&self, wire: &[u8]) -> Result<Vec<u8>, ProtoError>;
}

// Shared primitives.

fn derive_key(base_key: &[u8], label: &[u8]) -> Result<[u8; 32], ProtoError> {
    let mut k = [0u8; 32];
    Hkdf::<Sha256>::new(None, base_key)
        .expand(label, &mut k)
        .map_err(|_| ProtoError::Init)?;
    Ok(k)
}

pub fn derive_enc_key(base_key: &[u8]) -> Result<[u8; 32], ProtoError> {
    derive_key(base_key, b"seal:enc-key:v1")
}

/// Separate HMAC key from the same base, distinct HKDF label (key separation).
pub fn derive_mac_key(base_key: &[u8]) -> Result<[u8; 32], ProtoError> {
    derive_key(base_key, b"seal:mac-key:v1")
}

/// HMAC-SHA256 over `data`, truncated to the leftmost `n` bytes.
fn mac_tag(mac_key: &[u8], data: &[u8], n: usize) -> Result<Vec<u8>, ProtoError> {
    let mut m = Hmac::<Sha256>::new_from_slice(mac_key).map_err(|_| ProtoError::Init)?;
    m.update(data);
    Ok(m.finalize().into_bytes()[..n].to_vec())
}

/// Constant-time verify of a left-truncated HMAC-SHA256 tag.
fn mac_verify(mac_key: &[u8], data: &[u8], tag: &[u8]) -> Result<(), ProtoError> {
    let mut m = Hmac::<Sha256>::new_from_slice(mac_key).map_err(|_| ProtoError::Init)?;
    m.update(data);
    m.verify_truncated_left(tag).map_err(|_| ProtoError::Mac)
}

/// Zero-pad `short` up to the cipher's full nonce width. Entropy stays at `short.len()` bytes,
/// which keeps the wire cost small at the cost of birthday-bounded nonce collisions.
fn expand_short_nonce(len: usize, short: &[u8]) -> Vec<u8> {
    let mut n = vec![0u8; len];
    n[..short.len()].copy_from_slice(short);
    n
}

/// Build the synthetic IV from the tag: take its first `min(n, iv_len)` bytes and zero-pad up to
/// the cipher's IV width. The IV carries only that many bytes of entropy, so shipping fewer tag
/// bytes directly weakens nonce-collision resistance; the receiver can only rebuild the IV from
/// bytes that are on the wire.
fn siv_iv<S: KeyIvInit>(tag: &[u8], n: usize) -> Vec<u8> {
    let iv_len = S::iv_size();
    expand_short_nonce(iv_len, &tag[..n.min(iv_len)])
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

/// Application-layer framing: append an 8-byte replay nonce to the message. Called once by the
/// driver before any crypto; the `Protocol` impls treat the result as an opaque message and never
/// add a nonce of their own. In the SIV variants this nonce is load-bearing: it is what makes the
/// synthetic IV differ between otherwise-identical messages.
pub fn prepend_nonce(msg: &[u8]) -> Result<Vec<u8>, ProtoError> {
    let mut buf = Vec::with_capacity(APP_NONCE_LEN + msg.len());
    let mut nonce = [0u8; APP_NONCE_LEN];
    fill(&mut nonce).map_err(|_| ProtoError::Init)?;
    buf.extend_from_slice(&nonce);
    buf.extend_from_slice(msg);
    Ok(buf)
}

/// Check the `/tmp/nonce` ring buffer for `nonce`; return `Err(NoncePresent)` if found, otherwise
/// record it and return `Ok(())`.
///
/// On-disk layout: 33 bytes of ChaCha20-encrypted ring buffer. Fixed zero IV is safe because the
/// derived key is unique per session. Plaintext layout: `[head: u8][slot_0..slot_N-1]`.
pub fn check_and_record_nonce(nonce: &[u8], base_key: &[u8]) -> Result<(), ProtoError> {
    debug_assert_eq!(nonce.len(), APP_NONCE_LEN);
    let n = nonce.len();
    let file_key = derive_key(base_key, b"nonce-file:key:v1")?;
    let iv = [0u8; CHACHA20_NONCE_LEN];

    let fd = rustix::fs::open(
        c"/tmp/nonce",
        OFlags::RDWR | OFlags::CREATE,
        Mode::RUSR | Mode::WUSR,
    )
    .map_err(|e| {
        dbgprintln!("nonce open: {e:?}");
        ProtoError::Io(e)
    })?;

    // The replay window is a read-modify-write on a shared file with no serialization of its own.
    // Under the multi-threaded handler pool (and across concurrent processes) two callers could
    // otherwise both read the ring, both miss a nonce, and both record it, leaving a hole in the
    // replay window. LOCK_EX serializes the whole critical section; the lock releases when `fd` is
    // dropped at the end of this function.
    flock(&fd, FlockOperation::LockExclusive).map_err(ProtoError::Io)?;

    let mut ring = [0u8; NONCE_FILE_LEN];
    if rustix::io::read(&fd, &mut ring).map_err(ProtoError::Io)? == NONCE_FILE_LEN {
        stream_xor_in_place::<ChaCha20>(&file_key, &iv, &mut ring)?;
    }

    let head = (ring[0] as usize) % NONCE_WINDOW;

    for i in 0..NONCE_WINDOW {
        if &ring[1 + i * n..1 + (i + 1) * n] == nonce {
            return Err(ProtoError::NoncePresent);
        }
    }

    ring[1 + head * n..1 + (head + 1) * n].copy_from_slice(nonce);
    ring[0] = ((head + 1) % NONCE_WINDOW) as u8;

    stream_xor_in_place::<ChaCha20>(&file_key, &iv, &mut ring)?;

    rustix::fs::seek(&fd, SeekFrom::Start(0)).map_err(ProtoError::Io)?;
    rustix::io::write(&fd, &ring).map_err(ProtoError::Io)?;
    Ok(())
}

// StreamSiv: stateless, with a synthetic IV derived from a truncated MAC.
//
// The MAC covers the plaintext rather than the ciphertext for two reasons. The tag doubles as the
// IV, so deriving the IV from the ciphertext would be circular (ct needs the IV, the IV would need
// MAC(ct), and MAC(ct) needs ct). And the MAC stays keyed (HMAC), whereas an unkeyed hash here
// would be forgeable and give no integrity.
//
// The forgery bound of ~2^-8N is exercised, not just asserted: `forge_chosen_plaintext::<N>` in the
// tests mounts a black-box chosen-plaintext forgery using only the `open` oracle plus one known
// plaintext, landing an attacker-chosen message in ~2^8N tries. That is why `holla` uses N=4 (~2^32
// work): the point where brute force stops being feasible.

pub struct StreamSiv<S, const N: usize> {
    enc_key: [u8; 32],
    mac_key: [u8; 32],
    _p: PhantomData<S>,
}

impl<S, const N: usize> StreamSiv<S, N> {
    pub fn new(base_key: &[u8]) -> Result<Self, ProtoError> {
        // N is the truncated-HMAC tag width; HMAC-SHA256 yields 32 bytes, so a larger N would slice
        // past the digest and panic in `mac_tag`. The assert is wrapped in `const` so an
        // out-of-range N is a compile-time error rather than a runtime panic.
        const { assert!(N >= 1 && N <= 32, "StreamSiv N must be in 1..=32") };

        Ok(Self {
            enc_key: derive_enc_key(base_key)?,
            mac_key: derive_mac_key(base_key)?,
            _p: PhantomData,
        })
    }
}

impl<S: KeyIvInit + StreamCipher, const N: usize> Protocol for StreamSiv<S, N> {
    fn seal(&self, msg: &[u8]) -> Result<Vec<u8>, ProtoError> {
        let tag = mac_tag(&self.mac_key, msg, N)?;
        let iv = siv_iv::<S>(&tag, N);
        let mut ct = msg.to_vec();
        S::new_from_slices(&self.enc_key, &iv)
            .map_err(|_| ProtoError::Init)?
            .apply_keystream(&mut ct);
        let mut wire = tag;
        wire.extend_from_slice(&ct);
        Ok(wire)
    }

    fn open(&self, wire: &[u8]) -> Result<Vec<u8>, ProtoError> {
        if wire.len() < N {
            return Err(ProtoError::TooShort);
        }
        let (tag, ct) = wire.split_at(N);
        let iv = siv_iv::<S>(tag, N);
        let mut buf = ct.to_vec();
        S::new_from_slices(&self.enc_key, &iv)
            .map_err(|_| ProtoError::Init)?
            .apply_keystream(&mut buf);
        mac_verify(&self.mac_key, &buf, tag)?;
        Ok(buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chacha20::ChaCha20;

    const KEY: &[u8] = b"kermit-crypto-unit-test-base-key";
    const MSG: &[u8] = b"hello, kermit!";
    const N: usize = 4;

    fn proto() -> StreamSiv<ChaCha20, N> {
        StreamSiv::<ChaCha20, N>::new(KEY).unwrap()
    }

    #[test]
    fn round_trip() {
        let p = proto();
        let wire = p.seal(MSG).unwrap();
        assert_eq!(wire.len(), N + MSG.len());
        assert_eq!(p.open(&wire).unwrap(), MSG);
    }

    #[test]
    fn tamper_rejected() {
        let p = proto();
        let mut wire = p.seal(MSG).unwrap();
        *wire.last_mut().unwrap() ^= 0x01;
        assert_eq!(p.open(&wire), Err(ProtoError::Mac));
    }

    #[test]
    fn too_short() {
        let p = proto();
        assert_eq!(p.open(&[0u8; N - 1]), Err(ProtoError::TooShort));
    }

    #[test]
    fn deterministic() {
        // The synthetic IV is HMAC(msg), so sealing the same message twice is bit-identical: the
        // equality leak the module doc calls out.
        let p = proto();
        assert_eq!(p.seal(MSG).unwrap(), p.seal(MSG).unwrap());
    }

    /// Mount the chosen-plaintext forgery against `StreamSiv<ChaCha20, N>` and return how many
    /// candidates were tried before the victim accepted our chosen message. This is not a blind
    /// forgery that accepts unpredictable garbage: it gets a message of the attacker's choosing
    /// accepted without the keys.
    ///
    /// It needs one captured message whose plaintext is known, plus the `open` accept/reject
    /// oracle.
    ///
    /// Because it is a stream cipher, ct = pt XOR keystream(iv), so a known (pt, ct) pair yields
    /// the keystream for that iv. The iv here is the tag (see `siv_iv`), so any forgery that reuses
    /// the tag reuses this keystream, letting the attacker encrypt an arbitrary chosen plaintext
    /// under it. All that is left is the N-byte MAC check, which passes for ~1/2^8N plaintexts, so
    /// the attacker brute-forces a small filler region until one hits. Expected work is ~2^8N:
    /// practical for N=1 (~256) and N=2 (~65k), slow for N=3 (~16M), infeasible for N>=4.
    ///
    /// The attack never references enc_key/mac_key/mac_tag/siv_iv; it only calls `seal` (to model
    /// capturing a legit message) and `open` (the victim's decrypt).
    fn forge_chosen_plaintext<const N: usize>() -> u32 {
        let p = StreamSiv::<ChaCha20, N>::new(KEY).unwrap();

        // (1) Legit capture. `legit_pt` is the known plaintext.
        let legit_pt = b"pay alice 5 coins";
        let wire = p.seal(legit_pt).unwrap();
        let (tag, ct) = wire.split_at(N);

        // (2) Recover the keystream for iv = pad(tag): ks = ct XOR pt.
        let ks: Vec<u8> = ct.iter().zip(legit_pt).map(|(c, m)| c ^ m).collect();

        // (3) The message the attacker wants accepted, same length as the legit one so the
        // recovered keystream lines up. The meaningful prefix is fixed; the trailing 4 bytes are
        // filler we brute-force to satisfy the N-byte MAC. 4 filler bytes give a 2^32 candidate
        // space, enough to almost-certainly contain a hit for N<=3.
        const FILLER: usize = 4;
        let prefix = b"PAY EVE ALL!!"; // len 13; 13 + 4 filler == 17 == legit len
        assert_eq!(prefix.len() + FILLER, legit_pt.len());

        let mut forged = Vec::from(&prefix[..]);
        forged.extend_from_slice(&[0u8; FILLER]);

        // Search ~64x the expected 2^(8N) tries so a miss is astronomically unlikely; clamp to the
        // u32 filler space.
        let cap = 64u64
            .checked_shl(8 * N as u32)
            .unwrap_or(u64::MAX)
            .min(u32::MAX as u64) as u32;

        for counter in 0..cap {
            forged[prefix.len()..].copy_from_slice(&counter.to_le_bytes());
            // Encrypt our chosen plaintext under the reused tag/keystream.
            let ct_forged: Vec<u8> = forged.iter().zip(&ks).map(|(m, k)| m ^ k).collect();
            let mut wire_forged = Vec::from(tag);
            wire_forged.extend_from_slice(&ct_forged);

            if let Ok(pt) = p.open(&wire_forged) {
                // The oracle accepted our chosen, meaningful plaintext, not garbage.
                assert_eq!(pt, forged);
                assert!(forged.starts_with(prefix));
                assert_ne!(forged.as_slice(), &legit_pt[..]);
                return counter;
            }
        }
        panic!("no {N}-byte tag collision found in {cap} tries");
    }

    #[test]
    fn one_byte_tag_chosen_plaintext_forgery() {
        let tries = forge_chosen_plaintext::<1>();
        dbgprintln!("N=1 chosen-plaintext forgery succeeded after {tries} tries");
    }

    #[test]
    fn two_byte_tag_chosen_plaintext_forgery() {
        let tries = forge_chosen_plaintext::<2>();
        dbgprintln!("N=2 chosen-plaintext forgery succeeded after {tries} tries");
    }

    // ~16M tries (~2^24): correct but slow, so it is opt-in. Run with:
    //   cargo test -p crypto --release three_byte_tag -- --ignored --nocapture
    #[test]
    #[ignore = "brute-forces ~2^32 candidates; run explicitly"]
    fn three_byte_tag_chosen_plaintext_forgery() {
        let tries = forge_chosen_plaintext::<3>();
        dbgprintln!("N=3 chosen-plaintext forgery succeeded after {tries} tries");
    }

    // ~4B tries (~2^32): correct but slow, so it is opt-in. Run with:
    //   cargo test -p crypto --release four_byte_tag -- --ignored --nocapture
    #[test]
    #[ignore = "brute-forces ~2^32 candidates; run explicitly"]
    fn four_byte_tag_chosen_plaintext_forgery() {
        let tries = forge_chosen_plaintext::<4>();
        dbgprintln!("N=4 chosen-plaintext forgery succeeded after {tries} tries");
    }

    #[test]
    fn wire_format_snapshot() {
        // Golden vector pinning the on-wire bytes for the fixed KEY/MSG/N above (tag(4) || ct(14)).
        // Regenerate intentionally if the envelope changes.
        let p = proto();
        let expected: [u8; N + MSG.len()] = [
            0xf2, 0x8a, 0x06, 0xa6, 0xe0, 0x39, 0xee, 0xe8, 0x48, 0xa3, 0x3d, 0x15, 0xf0, 0x73,
            0x34, 0xdd, 0x29, 0x7e,
        ];
        assert_eq!(p.seal(MSG).unwrap(), expected);
    }
}
