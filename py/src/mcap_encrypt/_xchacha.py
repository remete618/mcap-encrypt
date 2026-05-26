"""XChaCha20-Poly1305 AEAD — compatibility shim.

cryptography >= 42 removed XChaCha20Poly1305 because OpenSSL does not natively
expose it. We fall back to pynacl (libsodium bindings) which implement the same
construction (IETF draft, 24-byte nonce, 32-byte key, 16-byte Poly1305 tag).

The public class matches the cryptography 41 API surface used by this library:
    aead = XChaCha20Poly1305(key)
    ciphertext = aead.encrypt(nonce, plaintext, aad)   # len = len(plaintext) + 16
    plaintext  = aead.decrypt(nonce, ciphertext, aad)  # raises on auth failure
"""
from __future__ import annotations


try:
    from cryptography.hazmat.primitives.ciphers.aead import XChaCha20Poly1305  # noqa: F401
except ImportError:
    from nacl.bindings import (
        crypto_aead_xchacha20poly1305_ietf_decrypt as _nacl_dec,
        crypto_aead_xchacha20poly1305_ietf_encrypt as _nacl_enc,
    )

    class XChaCha20Poly1305:  # type: ignore[no-redef]
        """XChaCha20-Poly1305 backed by libsodium (pynacl)."""

        def __init__(self, key: bytes) -> None:
            self._key = bytes(key)

        def encrypt(self, nonce: bytes, data: bytes, aad: bytes | None) -> bytes:
            return bytes(_nacl_enc(bytes(data), aad or b"", bytes(nonce), self._key))

        def decrypt(self, nonce: bytes, data: bytes, aad: bytes | None) -> bytes:
            try:
                return bytes(_nacl_dec(bytes(data), aad or b"", bytes(nonce), self._key))
            except Exception as exc:
                raise ValueError(f"XChaCha20Poly1305 decryption failed: {exc}") from exc
