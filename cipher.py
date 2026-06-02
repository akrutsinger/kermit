#!/usr/bin/env python3
"""StreamSiv: a tiny stateless authenticated stream cipher.

A Python port of the Rust `StreamSiv` in src/crypto.rs. MAC-then-encrypt with a
synthetic IV -- the truncated HMAC tag does double duty as both the integrity
check and the cipher's IV:

    tag  = HMAC-SHA256(mac_key, msg)[:n]      # n bytes -- the integrity tag
    iv   = tag[:12] zero-padded to 12 bytes   # the same bytes seed the IV
    ct   = ChaCha20(enc_key, iv, msg)
    wire = tag || ct                          # overhead is exactly n bytes

`n` (how many tag bytes to prepend) is the caller's knob. Fewer bytes = smaller
wire, but it weakens BOTH forgery resistance (~2^-8n) AND the keystream-reuse
birthday bound (~2^4n messages), since the receiver can only rebuild the IV from
bytes that are on the wire. n must be 1..=32; 12 gives a full-width IV.

Should be wire-compatible with the Rust version given the same 32-byte base key
(same HKDF labels, HMAC truncation, and RFC 8439 ChaCha20 parameters).

Requires: pip install cryptography
"""

import hashlib
import hmac
import os

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms

_IV_LEN = 12  # ChaCha20 (RFC 8439) nonce width


def _hkdf_sha256(ikm: bytes, info: bytes, length: int = 32) -> bytes:
    """RFC 5869 HKDF-SHA256 with the default all-zero salt -- matches the Rust
    `Hkdf::<Sha256>::new(None, ikm).expand(info, ..)`."""
    salt = b"\x00" * hashlib.sha256().digest_size
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()  # extract
    okm, block, counter = b"", b"", 1  # expand
    while len(okm) < length:
        block = hmac.new(prk, block + info + bytes([counter]), hashlib.sha256).digest()
        okm += block
        counter += 1
    return okm[:length]


def _chacha20(key: bytes, iv12: bytes, data: bytes) -> bytes:
    """RFC 8439 ChaCha20. `cryptography` wants a 16-byte nonce: a 4-byte
    little-endian block counter (we start at 0) followed by the 12-byte nonce."""
    nonce16 = b"\x00\x00\x00\x00" + iv12
    enc = Cipher(algorithms.ChaCha20(key, nonce16), mode=None).encryptor()
    return enc.update(data) + enc.finalize()


class SivCipher:
    def __init__(self, base_key: bytes | None = None, n: int = 12):
        if base_key is None:
            base_key = os.urandom(32)  # fresh random key for quick demos
        self.enc_key = _hkdf_sha256(base_key, b"seal:enc-key:v1")
        self.mac_key = _hkdf_sha256(base_key, b"seal:mac-key:v1")
        self.n = n

    def seal(self, msg: bytes) -> bytes:
        tag = hmac.new(self.mac_key, msg, hashlib.sha256).digest()[: self.n]
        ct = _chacha20(self.enc_key, self._siv_iv(tag), msg)
        return tag + ct  # wire = tag || ct

    def open(self, wire: bytes) -> bytes:
        if len(wire) < self.n:
            raise ValueError("input too short")
        tag, ct = wire[: self.n], wire[self.n :]
        msg = _chacha20(
            self.enc_key, self._siv_iv(tag), ct
        )  # ChaCha20 is its own inverse
        expected = hmac.new(self.mac_key, msg, hashlib.sha256).digest()[: self.n]
        if not hmac.compare_digest(expected, tag):
            raise ValueError("mac verification failed")
        return msg

    def _siv_iv(self, tag: bytes) -> bytes:
        seed = tag[: min(self.n, _IV_LEN)]
        return seed + b"\x00" * (_IV_LEN - len(seed))  # zero-pad to the IV width
