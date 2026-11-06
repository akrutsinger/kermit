#!/usr/bin/env python3
"""StreamAead: a tiny stateless authenticated-encryption envelope.

A Python port of the Rust `crypto::StreamAead<ChaCha20, NONCE_LEN, TAG_LEN>` in
crypto/src/lib.rs. Encrypt-then-MAC with an explicit random per-message nonce:

    nonce = random(nonce_len)                         # fresh per message
    iv    = nonce zero-padded to 12 bytes             # ChaCha20's IV width
    ct    = ChaCha20(enc_key, iv, msg)
    tag   = HMAC-SHA256(mac_key, nonce || ct)[:tag_len]
    wire  = nonce || tag || ct                        # overhead: nonce_len + tag_len

`open` verifies the tag before decrypting, so the cipher never runs on
unauthenticated bytes, and returns the nonce for the caller's replay check.
`nonce_len` governs keystream-reuse resistance (~2^(4*nonce_len) birthday bound)
and `tag_len` governs forgery resistance (~2^-(8*tag_len)); the defaults (8, 4)
match `listen`.

Wire-compatible with the Rust version given the same base key: same HKDF labels,
HMAC truncation and RFC 8439 ChaCha20 parameters.

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


class StreamAead:
    def __init__(
        self, base_key: bytes | None = None, nonce_len: int = 8, tag_len: int = 4
    ):
        if not 1 <= tag_len <= 32:
            raise ValueError("tag_len must be in 1..=32")
        if not 1 <= nonce_len <= _IV_LEN:
            raise ValueError(f"nonce_len must be in 1..={_IV_LEN}")
        if base_key is None:
            base_key = os.urandom(32)  # fresh random key for quick demos
        self.enc_key = _hkdf_sha256(base_key, b"seal:enc-key:v1")
        self.mac_key = _hkdf_sha256(base_key, b"seal:mac-key:v1")
        self.nonce_len = nonce_len
        self.tag_len = tag_len

    @property
    def overhead(self) -> int:
        """Bytes added to every message: the `nonce || tag` prefix."""
        return self.nonce_len + self.tag_len

    def seal(self, msg: bytes) -> bytes:
        """Return `nonce || tag || ciphertext` under a fresh random nonce."""
        return self.seal_with_nonce(os.urandom(self.nonce_len), msg)

    def seal_with_nonce(self, nonce: bytes, msg: bytes) -> bytes:
        """`seal` with a caller-supplied nonce, for deterministic test vectors.
        Never reuse a nonce under the same key."""
        if len(nonce) != self.nonce_len:
            raise ValueError(f"nonce must be {self.nonce_len} bytes")
        ct = _chacha20(self.enc_key, self._iv(nonce), msg)
        return nonce + self._tag(nonce, ct) + ct

    def open(self, wire: bytes) -> tuple[bytes, bytes]:
        """Verify and decrypt `wire`, returning `(nonce, plaintext)`. The nonce is
        returned for the caller's replay check."""
        if len(wire) < self.overhead:
            raise ValueError("input too short")
        nonce = wire[: self.nonce_len]
        tag = wire[self.nonce_len : self.overhead]
        ct = wire[self.overhead :]
        # Encrypt-then-MAC: verify before touching the cipher.
        if not hmac.compare_digest(self._tag(nonce, ct), tag):
            raise ValueError("mac verification failed")
        return nonce, _chacha20(self.enc_key, self._iv(nonce), ct)  # its own inverse

    def _tag(self, nonce: bytes, ct: bytes) -> bytes:
        return hmac.new(self.mac_key, nonce + ct, hashlib.sha256).digest()[: self.tag_len]

    @staticmethod
    def _iv(nonce: bytes) -> bytes:
        return nonce + b"\x00" * (_IV_LEN - len(nonce))  # zero-pad to the IV width
