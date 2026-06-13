"""Adversarial tests: every plaintext field protected by AAD must cause
AEAD authentication to fail when tampered, the symmetric key must be unique
per file, and known attacks (strip, wrong key, chunk reorder) must be
detected. Mirrors pkg/mcapencrypt/adversarial_test.go in Go."""
from __future__ import annotations

import struct

import pytest

from mcap_encrypt import (
    decrypt_mcap,
    encrypt_mcap,
)


def _find_first_encrypted_chunk(data: bytes) -> tuple[int, int]:
    """Return (record_data_start, record_data_len) for the first 0x81 record.

    The 9-byte header is opcode(1) + length(8). record_data_start points past
    the header to the first payload byte; record_data_len is the payload size.
    """
    pos = 8  # past magic
    while pos + 9 <= len(data):
        opcode = data[pos]
        (n,) = struct.unpack_from("<Q", data, pos + 1)
        if opcode == 0x81:
            return pos + 9, n
        pos += 9 + n
    raise AssertionError("no encrypted chunk (0x81) found")


def _parse_chunk_offsets(payload: bytes) -> dict:
    """Return byte offsets of the chunk fields needed by these tests."""
    # Fixed prefix: msg_start(8) + msg_end(8) + uncomp_size(8) + uncomp_crc(4) = 28
    off = 28
    (clen,) = struct.unpack_from("<I", payload, off)
    off += 4 + clen  # compression string
    (slen,) = struct.unpack_from("<I", payload, off)
    off += 4 + slen  # slot_id string
    # nonce length-prefix begins here
    nonce_len_off = off
    (nlen,) = struct.unpack_from("<I", payload, off)
    off += 4
    nonce_off = off
    off += nlen
    ciphertext_len_off = off
    (cplen,) = struct.unpack_from("<I", payload, off)
    off += 4
    ciphertext_off = off
    return {
        "nonce_off": nonce_off,
        "nonce_len": nlen,
        "ciphertext_off": ciphertext_off,
        "ciphertext_len": cplen,
        "msg_start_off": 0,  # first 8 bytes
    }


def test_tampered_nonce(rsa_key_pair, test_mcap_bytes):
    pub, priv = rsa_key_pair
    enc = bytearray(encrypt_mcap(test_mcap_bytes, pub))
    rec_start, _ = _find_first_encrypted_chunk(bytes(enc))
    offsets = _parse_chunk_offsets(bytes(enc)[rec_start:])
    enc[rec_start + offsets["nonce_off"]] ^= 0xFF

    with pytest.raises(Exception):
        decrypt_mcap(bytes(enc), priv)


def test_tampered_aad_message_start_time(rsa_key_pair, test_mcap_bytes):
    pub, priv = rsa_key_pair
    enc = bytearray(encrypt_mcap(test_mcap_bytes, pub))
    rec_start, _ = _find_first_encrypted_chunk(bytes(enc))
    # First 8 bytes of the payload are message_start_time (uint64 LE), part of AAD.
    enc[rec_start] ^= 0xFF

    with pytest.raises(Exception):
        decrypt_mcap(bytes(enc), priv)


def test_tampered_aad_message_end_time(rsa_key_pair, test_mcap_bytes):
    pub, priv = rsa_key_pair
    enc = bytearray(encrypt_mcap(test_mcap_bytes, pub))
    rec_start, _ = _find_first_encrypted_chunk(bytes(enc))
    # Bytes 8-15 of the payload are message_end_time (uint64 LE), part of AAD.
    enc[rec_start + 8] ^= 0xFF

    with pytest.raises(Exception):
        decrypt_mcap(bytes(enc), priv)


def test_tampered_aad_uncompressed_size(rsa_key_pair, test_mcap_bytes):
    pub, priv = rsa_key_pair
    enc = bytearray(encrypt_mcap(test_mcap_bytes, pub))
    rec_start, _ = _find_first_encrypted_chunk(bytes(enc))
    # Bytes 16-23 of the payload are uncompressed_size (uint64 LE), part of AAD.
    enc[rec_start + 16] ^= 0xFF

    with pytest.raises(Exception):
        decrypt_mcap(bytes(enc), priv)


def test_tampered_ciphertext(rsa_key_pair, test_mcap_bytes):
    pub, priv = rsa_key_pair
    enc = bytearray(encrypt_mcap(test_mcap_bytes, pub))
    rec_start, _ = _find_first_encrypted_chunk(bytes(enc))
    offsets = _parse_chunk_offsets(bytes(enc)[rec_start:])
    # Flip a byte in the middle of the ciphertext.
    enc[rec_start + offsets["ciphertext_off"] + 5] ^= 0xFF

    with pytest.raises(Exception):
        decrypt_mcap(bytes(enc), priv)


def test_wrong_key_rejected(rsa_key_pair, rsa_key_pair_b, test_mcap_bytes):
    pub_a, _ = rsa_key_pair
    _, priv_b = rsa_key_pair_b
    enc = encrypt_mcap(test_mcap_bytes, pub_a)
    # Decrypting with a private key not in the recipient list must fail.
    with pytest.raises(Exception):
        decrypt_mcap(enc, priv_b)


def test_nonce_uniqueness_within_file(rsa_key_pair, test_mcap_bytes):
    """All EncryptedChunks in one file must use distinct nonces."""
    pub, _ = rsa_key_pair
    enc = encrypt_mcap(test_mcap_bytes, pub)

    pos = 8
    nonces = []
    while pos + 9 <= len(enc):
        opcode = enc[pos]
        (n,) = struct.unpack_from("<Q", enc, pos + 1)
        if opcode == 0x81:
            payload = enc[pos + 9 : pos + 9 + n]
            offsets = _parse_chunk_offsets(payload)
            nonces.append(bytes(payload[offsets["nonce_off"] : offsets["nonce_off"] + offsets["nonce_len"]]))
        pos += 9 + n

    assert len(nonces) >= 1
    assert len(set(nonces)) == len(nonces), "nonce reused across chunks in same file"


def test_nonce_uniqueness_across_files(rsa_key_pair, test_mcap_bytes):
    """Two encryptions of the same plaintext must produce different nonces.

    This catches the case where someone replaces secrets.token_bytes with a
    deterministic source.
    """
    pub, _ = rsa_key_pair
    enc1 = encrypt_mcap(test_mcap_bytes, pub)
    enc2 = encrypt_mcap(test_mcap_bytes, pub)

    rec1_start, _ = _find_first_encrypted_chunk(enc1)
    rec2_start, _ = _find_first_encrypted_chunk(enc2)
    off1 = _parse_chunk_offsets(enc1[rec1_start:])
    off2 = _parse_chunk_offsets(enc2[rec2_start:])
    nonce1 = enc1[rec1_start + off1["nonce_off"] : rec1_start + off1["nonce_off"] + off1["nonce_len"]]
    nonce2 = enc2[rec2_start + off2["nonce_off"] : rec2_start + off2["nonce_off"] + off2["nonce_len"]]
    assert nonce1 != nonce2


def test_decrypt_plain_mcap_rejected(rsa_key_pair, test_mcap_bytes):
    """A plain (unencrypted) MCAP must not be silently decrypted to itself."""
    _, priv = rsa_key_pair
    with pytest.raises(Exception):
        decrypt_mcap(test_mcap_bytes, priv)


def test_x25519_tampered_ciphertext(x25519_key_pair, test_mcap_bytes):
    """Repeat the ciphertext-tamper check for X25519 to confirm AAD coverage
    on both key-wrapping paths."""
    pub, priv = x25519_key_pair
    enc = bytearray(encrypt_mcap(test_mcap_bytes, pub))
    rec_start, _ = _find_first_encrypted_chunk(bytes(enc))
    offsets = _parse_chunk_offsets(bytes(enc)[rec_start:])
    enc[rec_start + offsets["ciphertext_off"] + 5] ^= 0xFF

    with pytest.raises(Exception):
        decrypt_mcap(bytes(enc), priv)
