"""Key generation, wrapping, unwrapping, and fingerprinting.

Supported key types:
  - RSA-4096: PKCS8 private, SPKI public. Key wrapping: RSA-OAEP-SHA256.
  - X25519: PKCS8 private, SPKI public. Key wrapping: X25519-HKDF-XChaCha20Poly1305.

Key ID: hex(SHA-256(SPKI DER of public key)).
"""
from __future__ import annotations

import hashlib
import hmac as _hmac
import secrets
import struct
from typing import Tuple

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives.asymmetric.rsa import (
    RSAPrivateKey,
    RSAPublicKey,
    generate_private_key as _rsa_gen,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from ._xchacha import XChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_X25519_OID_BYTES = b"\x06\x03\x2b\x65\x6e"  # OID 1.3.101.110 in DER
_X25519_HKDF_INFO = b"mcap-encrypt x25519 v1"
_XCHACHA20_NONCE_SIZE = 24  # bytes
_XCHACHA20_KEY_SIZE = 32  # bytes
_WRAPPED_KEY_X25519_SIZE = 32 + 24 + 48  # ephem_pub + nonce + ciphertext

# ---------------------------------------------------------------------------
# Key generation
# ---------------------------------------------------------------------------


def generate_key_pair() -> Tuple[str, str]:
    """Generate RSA-4096 key pair.

    Returns (public_pem, private_pem) as PEM strings.
    Public: SPKI / BEGIN PUBLIC KEY.
    Private: PKCS8 / BEGIN PRIVATE KEY.
    """
    priv = _rsa_gen(public_exponent=65537, key_size=4096)
    pub_pem = priv.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")
    priv_pem = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("ascii")
    return pub_pem, priv_pem


def generate_x25519_key_pair() -> Tuple[str, str]:
    """Generate X25519 key pair.

    Returns (public_pem, private_pem) as PEM strings.
    Public: SPKI / BEGIN PUBLIC KEY (44-byte DER with OID 1.3.101.110).
    Private: PKCS8 / BEGIN PRIVATE KEY (48-byte DER with OID 1.3.101.110).
    """
    priv = X25519PrivateKey.generate()
    pub_pem = priv.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")
    priv_pem = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("ascii")
    return pub_pem, priv_pem


# ---------------------------------------------------------------------------
# PEM parsing
# ---------------------------------------------------------------------------


def _load_public_key_from_pem(pem: str) -> RSAPublicKey | X25519PublicKey:
    """Load an RSA or X25519 public key from a PEM string."""
    key = serialization.load_pem_public_key(pem.encode("ascii"))
    if not isinstance(key, (RSAPublicKey, X25519PublicKey)):
        raise ValueError(
            f"unsupported public key type {type(key).__name__}; "
            "expected RSA or X25519"
        )
    return key  # type: ignore[return-value]


def _load_private_key_from_pem(pem: str) -> RSAPrivateKey | X25519PrivateKey:
    """Load an RSA or X25519 private key from a PEM string."""
    key = serialization.load_pem_private_key(pem.encode("ascii"), password=None)
    if not isinstance(key, (RSAPrivateKey, X25519PrivateKey)):
        raise ValueError(
            f"unsupported private key type {type(key).__name__}; "
            "expected RSA or X25519"
        )
    return key  # type: ignore[return-value]


def _is_x25519_spki(der: bytes) -> bool:
    """Return True if SPKI DER contains the X25519 OID bytes."""
    return _X25519_OID_BYTES in der


# ---------------------------------------------------------------------------
# Key fingerprint
# ---------------------------------------------------------------------------


def spki_fingerprint(public_key: RSAPublicKey | X25519PublicKey) -> str:
    """Return hex(SHA-256(SPKI DER)) of a public key."""
    der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    digest = hashlib.sha256(der).digest()
    return digest.hex()


# ---------------------------------------------------------------------------
# RSA key wrapping
# ---------------------------------------------------------------------------


# Minimum RSA modulus size accepted for key wrapping. Format v3+ assumes
# RSA-4096; smaller keys would silently weaken file strength below documented
# guarantees.
MIN_RSA_KEY_BITS = 4096


def wrap_key_rsa(sym_key: bytes, public_key: RSAPublicKey) -> bytes:
    """Wrap *sym_key* with RSA-OAEP-SHA256.

    Raises ValueError if the RSA modulus is smaller than MIN_RSA_KEY_BITS.
    """
    if public_key.key_size < MIN_RSA_KEY_BITS:
        raise ValueError(
            f"RSA public key is {public_key.key_size} bits; minimum is {MIN_RSA_KEY_BITS} bits"
        )
    return public_key.encrypt(
        sym_key,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


def unwrap_key_rsa(wrapped: bytes, private_key: RSAPrivateKey) -> bytes:
    """Unwrap *wrapped* with RSA-OAEP-SHA256."""
    return private_key.decrypt(
        wrapped,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


# ---------------------------------------------------------------------------
# X25519 key wrapping
# ---------------------------------------------------------------------------


def _derive_x25519_kek(shared_secret: bytes) -> bytes:
    """Derive a 32-byte KEK from an X25519 shared secret using HKDF-SHA256.

    salt=None (not b'') to match the Go and TypeScript implementations.
    """
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=_X25519_HKDF_INFO,
    )
    return hkdf.derive(shared_secret)


def wrap_key_x25519(sym_key: bytes, recipient_pub: X25519PublicKey) -> bytes:
    """Wrap *sym_key* using ephemeral X25519 ECDH + HKDF-SHA256 + XChaCha20-Poly1305.

    Wire format: ephem_pub(32) || nonce(24) || ciphertext(32+16=48) = 104 bytes.
    """
    ephem_priv = X25519PrivateKey.generate()
    ephem_pub_bytes = ephem_priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    shared = ephem_priv.exchange(recipient_pub)
    kek = _derive_x25519_kek(shared)

    nonce = secrets.token_bytes(_XCHACHA20_NONCE_SIZE)
    # XChaCha20Poly1305 uses 24-byte nonces.
    aead = XChaCha20Poly1305(kek)
    ciphertext = aead.encrypt(nonce, sym_key, None)

    result = ephem_pub_bytes + nonce + ciphertext
    # Zero sensitive material
    kek_arr = bytearray(kek)
    for i in range(len(kek_arr)):
        kek_arr[i] = 0
    return result


def unwrap_key_x25519(wrapped: bytes, private_key: X25519PrivateKey) -> bytes:
    """Unwrap a symmetric key wrapped with wrap_key_x25519.

    Expects wrapped = ephem_pub(32) || nonce(24) || ciphertext(48).
    """
    min_len = 32 + _XCHACHA20_NONCE_SIZE + _XCHACHA20_KEY_SIZE + 16
    if len(wrapped) < min_len:
        raise ValueError(
            f"wrapped key too short for X25519 ({len(wrapped)} bytes, need {min_len})"
        )
    ephem_pub_bytes = wrapped[:32]
    nonce = wrapped[32 : 32 + _XCHACHA20_NONCE_SIZE]
    ciphertext = wrapped[32 + _XCHACHA20_NONCE_SIZE :]

    ephem_pub = X25519PublicKey.from_public_bytes(ephem_pub_bytes)
    shared = private_key.exchange(ephem_pub)
    kek = _derive_x25519_kek(shared)

    aead = XChaCha20Poly1305(kek)
    try:
        plain = aead.decrypt(nonce, ciphertext, None)
    except Exception as exc:
        raise ValueError("X25519 key unwrap failed: authentication error") from exc
    finally:
        kek_arr = bytearray(kek)
        for i in range(len(kek_arr)):
            kek_arr[i] = 0
    return plain


# ---------------------------------------------------------------------------
# WrappedKeyData
# ---------------------------------------------------------------------------

_WRAPPED_KEY_VERSION = 3
_WRAPPED_KEY_VERSION_V2 = 2
_FILE_ID_SIZE = 16


class WrappedKeyData:
    """Binary payload stored inside the wrapped-key Attachment record."""

    __slots__ = ("version", "file_id", "key_id", "algorithm", "kek_algorithm", "wrapped_key")

    def __init__(
        self,
        version: int,
        file_id: bytes,
        key_id: str,
        algorithm: str,
        kek_algorithm: str,
        wrapped_key: bytes,
    ) -> None:
        self.version = version
        self.file_id = file_id
        self.key_id = key_id
        self.algorithm = algorithm
        self.kek_algorithm = kek_algorithm
        self.wrapped_key = wrapped_key

    def encode(self) -> bytes:
        """Serialise to binary."""
        out = bytearray()
        out += struct.pack("<B", _WRAPPED_KEY_VERSION)  # always write current version
        out += self.file_id
        _put_str(out, self.key_id)
        _put_str(out, self.algorithm)
        _put_str(out, self.kek_algorithm)
        _put_bytes(out, self.wrapped_key)
        return bytes(out)

    @staticmethod
    def decode(data: bytes) -> "WrappedKeyData":
        """Parse from binary. Raises ValueError on malformed input."""
        if len(data) < 1:
            raise ValueError("empty wrapped key data")
        ver = data[0]
        if ver not in (_WRAPPED_KEY_VERSION, _WRAPPED_KEY_VERSION_V2):
            raise ValueError(
                f"unsupported wrapped key version {ver} "
                f"(want {_WRAPPED_KEY_VERSION_V2} or {_WRAPPED_KEY_VERSION})"
            )
        if len(data) < 1 + _FILE_ID_SIZE:
            raise ValueError("truncated: too short for file_id")
        file_id = bytes(data[1 : 1 + _FILE_ID_SIZE])
        off = 1 + _FILE_ID_SIZE

        def get_str(o: int) -> Tuple[str, int]:
            if o + 4 > len(data):
                raise ValueError(f"truncated reading string length at offset {o}")
            (n,) = struct.unpack_from("<I", data, o)
            o += 4
            if o + n > len(data):
                raise ValueError(f"truncated reading string data at offset {o}")
            return data[o : o + n].decode("utf-8"), o + n

        def get_bytes(o: int) -> Tuple[bytes, int]:
            if o + 4 > len(data):
                raise ValueError(f"truncated reading bytes length at offset {o}")
            (n,) = struct.unpack_from("<I", data, o)
            o += 4
            if o + n > len(data):
                raise ValueError(f"truncated reading bytes data at offset {o}")
            return bytes(data[o : o + n]), o + n

        key_id, off = get_str(off)
        algorithm, off = get_str(off)
        kek_algorithm, off = get_str(off)
        wrapped_key, off = get_bytes(off)

        if algorithm != "xchacha20poly1305":
            raise ValueError(
                f"unsupported encryption algorithm {algorithm!r} "
                "(want xchacha20poly1305)"
            )
        if kek_algorithm not in ("rsa-oaep-sha256", "x25519-hkdf-xchacha20poly1305"):
            raise ValueError(f"unsupported key-wrapping algorithm {kek_algorithm!r}")

        return WrappedKeyData(
            version=ver,
            file_id=file_id,
            key_id=key_id,
            algorithm=algorithm,
            kek_algorithm=kek_algorithm,
            wrapped_key=wrapped_key,
        )


def _put_str(buf: bytearray, s: str) -> None:
    b = s.encode("utf-8")
    buf += struct.pack("<I", len(b))
    buf += b


def _put_bytes(buf: bytearray, data: bytes) -> None:
    buf += struct.pack("<I", len(data))
    buf += data


# ---------------------------------------------------------------------------
# Manifest HMAC
# ---------------------------------------------------------------------------


def compute_manifest_hmac(sym_key: bytes, chunk_count: int, file_id: bytes) -> bytes:
    """HMAC-SHA256(key=sym_key, msg=chunk_count_le8 || file_id)."""
    import hashlib as _hashlib
    count_bytes = struct.pack("<Q", chunk_count)
    mac = _hmac.new(sym_key, count_bytes + file_id, _hashlib.sha256)
    return mac.digest()


# ---------------------------------------------------------------------------
# Unwrap dispatcher
# ---------------------------------------------------------------------------


def unwrap_sym_key(
    wkd: WrappedKeyData,
    private_key: RSAPrivateKey | X25519PrivateKey,
) -> bytes:
    """Unwrap the symmetric key in *wkd* using *private_key*.

    Raises ValueError if the key type does not match the kek_algorithm.
    """
    if wkd.kek_algorithm == "rsa-oaep-sha256":
        if not isinstance(private_key, RSAPrivateKey):
            raise ValueError(
                f"key is {type(private_key).__name__} but slot uses rsa-oaep-sha256"
            )
        return unwrap_key_rsa(wkd.wrapped_key, private_key)
    elif wkd.kek_algorithm == "x25519-hkdf-xchacha20poly1305":
        if not isinstance(private_key, X25519PrivateKey):
            raise ValueError(
                f"key is {type(private_key).__name__} but slot uses "
                "x25519-hkdf-xchacha20poly1305"
            )
        return unwrap_key_x25519(wkd.wrapped_key, private_key)
    else:
        raise ValueError(f"unsupported kek_algorithm {wkd.kek_algorithm!r}")


# ---------------------------------------------------------------------------
# Wrap dispatcher
# ---------------------------------------------------------------------------


def wrap_sym_key_for_recipient(
    sym_key: bytes,
    public_key_pem: str,
) -> Tuple[WrappedKeyData, str]:
    """Wrap *sym_key* for a single recipient specified by their PEM public key.

    Returns (WrappedKeyData, key_id).
    """
    pub = _load_public_key_from_pem(public_key_pem)
    key_id = spki_fingerprint(pub)

    if isinstance(pub, RSAPublicKey):
        wrapped = wrap_key_rsa(sym_key, pub)
        kek_alg = "rsa-oaep-sha256"
    elif isinstance(pub, X25519PublicKey):
        wrapped = wrap_key_x25519(sym_key, pub)
        kek_alg = "x25519-hkdf-xchacha20poly1305"
    else:
        raise ValueError(f"unsupported public key type {type(pub).__name__}")

    return (
        WrappedKeyData(
            version=_WRAPPED_KEY_VERSION,
            file_id=b"",  # caller fills in file_id
            key_id=key_id,
            algorithm="xchacha20poly1305",
            kek_algorithm=kek_alg,
            wrapped_key=wrapped,
        ),
        key_id,
    )
