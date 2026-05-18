"""Tests for optional metadata encryption (MetadataMode feature)."""
from __future__ import annotations

import struct
import pytest

from mcap_encrypt import encrypt_mcap, decrypt_mcap, generate_key_pair


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _build_mcap_with_metadata(name: str, kv: dict[str, str]) -> bytes:
    """Return a minimal chunked MCAP with one Metadata record."""
    from mcap_encrypt._records import (
        write_magic, write_record,
        OP_HEADER, OP_SCHEMA, OP_CHANNEL, OP_CHUNK,
        OP_METADATA, OP_DATA_END, OP_FOOTER,
    )
    out = bytearray()
    out += write_magic()

    # Header: profile="" library="" (two empty strings = 4-byte zero each)
    out += write_record(OP_HEADER, b"\x00\x00\x00\x00\x00\x00\x00\x00")

    # Schema
    schema_name_b = b"sensor"
    enc_b = b"json"
    data_b = b"{}"
    schema_pay = bytearray()
    schema_pay += struct.pack("<H", 1)               # id
    schema_pay += struct.pack("<I", len(schema_name_b)) + schema_name_b
    schema_pay += struct.pack("<I", len(enc_b)) + enc_b
    schema_pay += struct.pack("<I", len(data_b)) + data_b
    out += write_record(OP_SCHEMA, bytes(schema_pay))

    # Channel
    topic_b = b"/sensor"
    enc2_b = b"json"
    chan_pay = bytearray()
    chan_pay += struct.pack("<H", 1)                  # channel id
    chan_pay += struct.pack("<H", 1)                  # schema id
    chan_pay += struct.pack("<I", len(topic_b)) + topic_b
    chan_pay += struct.pack("<I", len(enc2_b)) + enc2_b
    chan_pay += struct.pack("<I", 0)                  # metadata count = 0
    out += write_record(OP_CHANNEL, bytes(chan_pay))

    # Message (inside a Chunk)
    msg_pay = bytearray()
    msg_pay += struct.pack("<H", 1)                   # channel_id
    msg_pay += struct.pack("<I", 0)                   # sequence
    msg_pay += struct.pack("<QQ", 1_000_000, 1_000_000)  # log_time, publish_time
    msg_pay += b'{"v":1}'
    inner = write_record(0x05, bytes(msg_pay))

    chunk_pay = bytearray()
    chunk_pay += struct.pack("<QQQ", 1_000_000, 1_000_000, len(inner))  # timestamps + uncomp_size
    chunk_pay += struct.pack("<I", 0)  # crc
    chunk_pay += struct.pack("<I", 0)  # compression name len = 0 (no compression)
    chunk_pay += struct.pack("<Q", len(inner))
    chunk_pay += inner
    out += write_record(OP_CHUNK, bytes(chunk_pay))

    # Metadata record
    meta_pay = bytearray()
    name_b = name.encode("utf-8")
    meta_pay += struct.pack("<I", len(name_b)) + name_b
    meta_pay += struct.pack("<I", len(kv))
    for k, v in kv.items():
        k_b, v_b = k.encode("utf-8"), v.encode("utf-8")
        meta_pay += struct.pack("<I", len(k_b)) + k_b
        meta_pay += struct.pack("<I", len(v_b)) + v_b
    out += write_record(OP_METADATA, bytes(meta_pay))

    out += write_record(OP_DATA_END, struct.pack("<I", 0))
    out += write_record(OP_FOOTER, struct.pack("<QQI", 0, 0, 0))
    out += write_magic()
    return bytes(out)


def _extract_metadata_records(mcap_bytes: bytes) -> list[tuple[str, dict[str, str]]]:
    """Return list of (name, kv) tuples from OP_METADATA records in a flat MCAP."""
    from mcap_encrypt._records import OP_METADATA, iter_records
    results = []
    for opcode, payload in iter_records(mcap_bytes, start=8):
        if opcode != OP_METADATA:
            continue
        if len(payload) < 4:
            continue
        (n,) = struct.unpack_from("<I", payload)
        name = payload[4 : 4 + n].decode("utf-8")
        off = 4 + n
        (count,) = struct.unpack_from("<I", payload, off)
        off += 4
        kv: dict[str, str] = {}
        for _ in range(count):
            (kn,) = struct.unpack_from("<I", payload, off)
            off += 4
            k = payload[off : off + kn].decode("utf-8")
            off += kn
            (vn,) = struct.unpack_from("<I", payload, off)
            off += 4
            v = payload[off : off + vn].decode("utf-8")
            off += vn
            kv[k] = v
        results.append((name, kv))
    return results


@pytest.fixture(scope="module")
def rsa_keys():
    return generate_key_pair()


@pytest.fixture(scope="module")
def test_mcap():
    return _build_mcap_with_metadata("robot_info", {"serial": "SN-42", "site": "lab"})


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_metadata_plaintext_default(rsa_keys, test_mcap):
    """Default mode passes metadata unchanged."""
    pub, priv = rsa_keys
    enc = encrypt_mcap(test_mcap, pub)
    dec = decrypt_mcap(enc, priv)
    recs = _extract_metadata_records(dec)
    assert len(recs) == 1
    assert recs[0][0] == "robot_info"
    assert recs[0][1]["serial"] == "SN-42"


def test_metadata_encrypt_round_trip(rsa_keys, test_mcap):
    """encrypt mode: name visible in encrypted file, map restored on decrypt."""
    pub, priv = rsa_keys
    enc = encrypt_mcap(test_mcap, pub, metadata="encrypt")

    # Name must appear in the encrypted file.
    assert b"robot_info" in enc, "metadata name should be visible in encrypt mode"
    # Map value must NOT appear.
    assert b"SN-42" not in enc, "metadata value must not be visible in encrypt mode"
    # OP_ENCRYPTED_METADATA (0x83) must be present.
    assert bytes([0x83]) in enc

    dec = decrypt_mcap(enc, priv)
    recs = _extract_metadata_records(dec)
    assert len(recs) == 1
    assert recs[0][0] == "robot_info"
    assert recs[0][1]["serial"] == "SN-42"
    assert recs[0][1]["site"] == "lab"


def test_metadata_encrypt_all_round_trip(rsa_keys, test_mcap):
    """encrypt-all mode: both name and map invisible; full round-trip."""
    pub, priv = rsa_keys
    enc = encrypt_mcap(test_mcap, pub, metadata="encrypt-all")

    # Neither name nor value should be visible.
    assert b"robot_info" not in enc, "metadata name must not appear in encrypt-all mode"
    assert b"SN-42" not in enc
    # OP_ENCRYPTED_METADATA (0x83) must be present.
    assert bytes([0x83]) in enc

    dec = decrypt_mcap(enc, priv)
    recs = _extract_metadata_records(dec)
    assert len(recs) == 1
    assert recs[0][0] == "robot_info"
    assert recs[0][1]["serial"] == "SN-42"


def test_metadata_encrypt_ciphertext_tamper(rsa_keys, test_mcap):
    """Flipping a byte in an encrypt-mode file causes AEAD failure on decrypt."""
    pub, priv = rsa_keys
    enc = bytearray(encrypt_mcap(test_mcap, pub, metadata="encrypt"))
    enc[len(enc) // 2] ^= 0xFF
    with pytest.raises(ValueError):
        decrypt_mcap(bytes(enc), priv)


def test_metadata_encrypt_all_ciphertext_tamper(rsa_keys, test_mcap):
    """Flipping a byte in an encrypt-all-mode file causes AEAD failure."""
    pub, priv = rsa_keys
    enc = bytearray(encrypt_mcap(test_mcap, pub, metadata="encrypt-all"))
    enc[len(enc) // 2] ^= 0xFF
    with pytest.raises(ValueError):
        decrypt_mcap(bytes(enc), priv)


def test_metadata_invalid_mode(rsa_keys, test_mcap):
    """An invalid metadata mode raises a clear ValueError."""
    pub, _ = rsa_keys
    with pytest.raises(ValueError, match="metadata must be"):
        encrypt_mcap(test_mcap, pub, metadata="banana")
