"""Shared fixtures: key pairs and a minimal test MCAP built from raw binary."""
from __future__ import annotations

import struct
import pytest

from mcap_encrypt import generate_key_pair, generate_x25519_key_pair


# ---------------------------------------------------------------------------
# MCAP binary helpers (no external mcap library)
# ---------------------------------------------------------------------------

MCAP_MAGIC = b"\x89MCAP0\r\n"


def _write_record(opcode: int, payload: bytes) -> bytes:
    return struct.pack("<BQ", opcode, len(payload)) + payload


def _write_string(s: str) -> bytes:
    b = s.encode("utf-8")
    return struct.pack("<I", len(b)) + b


def _write_prefixed_bytes(data: bytes) -> bytes:
    return struct.pack("<I", len(data)) + data


def make_test_mcap() -> bytes:
    """Build a minimal chunked MCAP with one message, entirely from raw binary.

    Structure:
      magic
      Header (profile="test", library="")
      Schema (id=1, name="sensor", encoding="json", data=b"{}")
      Channel (id=1, schema_id=1, topic="/sensor", message_encoding="json", metadata={})
      Chunk containing one Message (channel=1, seq=0, log_time=1000000, data=b'{"v":1}')
      DataEnd
      Footer
      magic
    """
    buf = bytearray()
    buf += MCAP_MAGIC

    # Header: profile + library (both strings)
    hdr = _write_string("test") + _write_string("")
    buf += _write_record(0x01, hdr)

    # Schema: id(u16) + name(str) + encoding(str) + data(prefixed bytes)
    schema_data = b"{}"
    schema = (
        struct.pack("<H", 1)
        + _write_string("sensor")
        + _write_string("json")
        + _write_prefixed_bytes(schema_data)
    )
    buf += _write_record(0x03, schema)

    # Channel: id(u16) + schema_id(u16) + topic(str) + message_encoding(str) + metadata(map)
    channel = (
        struct.pack("<HH", 1, 1)
        + _write_string("/sensor")
        + _write_string("json")
        + struct.pack("<I", 0)  # empty metadata map
    )
    buf += _write_record(0x04, channel)

    # Message payload: channel_id(u16) + sequence(u32) + log_time(u64) + publish_time(u64) + data
    msg_data = b'{"v":1}'
    msg_payload = (
        struct.pack("<HI", 1, 0)
        + struct.pack("<QQ", 1_000_000, 1_000_000)
        + msg_data
    )
    msg_record = _write_record(0x05, msg_payload)

    # Chunk: msg_start(u64) + msg_end(u64) + uncomp_size(u64) + uncomp_crc(u32)
    #        + compression(str) + records_size(u64) + records(bytes)
    comp_str = _write_string("")
    chunk_payload = (
        struct.pack("<QQQ", 1_000_000, 1_000_000, len(msg_record))
        + struct.pack("<I", 0)  # crc = 0
        + comp_str
        + struct.pack("<Q", len(msg_record))
        + msg_record
    )
    buf += _write_record(0x06, chunk_payload)

    # DataEnd: data_section_crc = 0
    buf += _write_record(0x0F, struct.pack("<I", 0))

    # Footer: summary_start=0, summary_offset_start=0, summary_crc=0
    buf += _write_record(0x02, struct.pack("<QQI", 0, 0, 0))

    buf += MCAP_MAGIC
    return bytes(buf)


# ---------------------------------------------------------------------------
# Pytest fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="session")
def rsa_key_pair():
    """RSA-4096 key pair: (public_pem, private_pem)."""
    return generate_key_pair()


@pytest.fixture(scope="session")
def x25519_key_pair():
    """X25519 key pair: (public_pem, private_pem)."""
    return generate_x25519_key_pair()


@pytest.fixture(scope="session")
def rsa_key_pair_b():
    """Second RSA-4096 key pair for multi-recipient and rotation tests."""
    return generate_key_pair()


@pytest.fixture(scope="session")
def x25519_key_pair_b():
    """Second X25519 key pair for rotation tests."""
    return generate_x25519_key_pair()


@pytest.fixture(scope="session")
def test_mcap_bytes():
    """Minimal chunked MCAP bytes for use in all tests."""
    return make_test_mcap()
