"""MCAP record framing and opcode constants.

Every MCAP record: opcode (1 byte) + length (uint64 LE) + payload.
Magic: \\x89MCAP0\\r\\n (8 bytes), appears at start and end of file.
"""
from __future__ import annotations

import struct
from typing import Generator, Tuple

# ---------------------------------------------------------------------------
# Magic
# ---------------------------------------------------------------------------

MCAP_MAGIC = b"\x89MCAP0\r\n"

# ---------------------------------------------------------------------------
# Opcodes
# ---------------------------------------------------------------------------

OP_HEADER = 0x01
OP_FOOTER = 0x02
OP_SCHEMA = 0x03
OP_CHANNEL = 0x04
OP_MESSAGE = 0x05
OP_CHUNK = 0x06
OP_CHUNK_INDEX = 0x08
OP_ATTACHMENT = 0x09
OP_STATISTICS = 0x0A
OP_METADATA = 0x0C
OP_SUMMARY_OFFSET = 0x0E
OP_DATA_END = 0x0F

# Custom opcodes
OP_ENCRYPTED_CHUNK = 0x81
OP_ENCRYPTED_ATTACHMENT = 0x82

# Maximum allowed record payload size (4 GiB). Guards against hostile input.
_MAX_RECORD_SIZE = 1 << 32

# ---------------------------------------------------------------------------
# Record framing
# ---------------------------------------------------------------------------


def read_magic(data: bytes, offset: int = 0) -> None:
    """Verify the 8-byte MCAP magic starting at *offset*. Raises ValueError on mismatch."""
    if len(data) < offset + 8:
        raise ValueError("truncated: not enough bytes for MCAP magic")
    if data[offset : offset + 8] != MCAP_MAGIC:
        raise ValueError("not an MCAP file (bad magic bytes)")


def write_magic() -> bytes:
    return MCAP_MAGIC


def read_record(data: bytes, offset: int) -> Tuple[int, bytes, int]:
    """Read one record from *data* at *offset*.

    Returns (opcode, payload_bytes, new_offset).
    Raises ValueError on truncation or oversized length.
    Raises StopIteration when *offset* is at end of data.
    """
    if offset >= len(data):
        raise StopIteration
    if offset + 9 > len(data):
        raise ValueError(f"truncated record header at offset {offset}")
    opcode = data[offset]
    (length,) = struct.unpack_from("<Q", data, offset + 1)
    if length > _MAX_RECORD_SIZE:
        raise ValueError(
            f"record length {length} at offset {offset} exceeds maximum "
            f"allowed size ({_MAX_RECORD_SIZE} bytes)"
        )
    end = offset + 9 + length
    if end > len(data):
        raise ValueError(
            f"truncated record at offset {offset}: declared {length} bytes, "
            f"only {len(data) - offset - 9} available"
        )
    payload = data[offset + 9 : end]
    return opcode, payload, end


def iter_records(data: bytes, start: int = 0) -> Generator[Tuple[int, bytes], None, None]:
    """Yield (opcode, payload) pairs from *data* starting at *start*.

    Iteration stops at EOF, StopIteration, or a truncated record header
    (e.g., the 8-byte trailing magic at the end of the file).
    """
    offset = start
    while offset < len(data):
        try:
            opcode, payload, offset = read_record(data, offset)
            yield opcode, payload
        except StopIteration:
            break
        except ValueError:
            # Truncated record or trailing magic bytes; stop iteration.
            break


def write_record(opcode: int, payload: bytes) -> bytes:
    """Serialise one MCAP record: opcode + uint64 length + payload."""
    hdr = struct.pack("<BQ", opcode, len(payload))
    return hdr + payload


# ---------------------------------------------------------------------------
# Attachment record helpers
# ---------------------------------------------------------------------------


def encode_attachment(
    log_time: int,
    create_time: int,
    name: str,
    media_type: str,
    data: bytes,
) -> bytes:
    """Encode an MCAP Attachment record payload (opcode 0x09).

    Layout:
        log_time    uint64 LE
        create_time uint64 LE
        name        string (uint32 len + utf8)
        media_type  string (uint32 len + utf8)
        data_size   uint64 LE
        data        raw bytes
        crc         uint32 LE (always 0)
    """
    name_b = name.encode("utf-8")
    mt_b = media_type.encode("utf-8")
    out = bytearray()
    out += struct.pack("<QQ", log_time, create_time)
    out += struct.pack("<I", len(name_b))
    out += name_b
    out += struct.pack("<I", len(mt_b))
    out += mt_b
    out += struct.pack("<Q", len(data))
    out += data
    out += struct.pack("<I", 0)  # CRC = 0
    return bytes(out)


def decode_attachment(payload: bytes) -> Tuple[int, int, str, str, bytes]:
    """Decode an MCAP Attachment record payload.

    Returns (log_time, create_time, name, media_type, data).
    """
    if len(payload) < 20:
        raise ValueError(f"attachment payload too short ({len(payload)} bytes)")
    offset = 0
    log_time, create_time = struct.unpack_from("<QQ", payload, offset)
    offset += 16

    def read_str(off: int) -> Tuple[str, int]:
        if off + 4 > len(payload):
            raise ValueError(f"truncated string length at offset {off}")
        (n,) = struct.unpack_from("<I", payload, off)
        off += 4
        if off + n > len(payload):
            raise ValueError(f"truncated string data at offset {off}")
        s = payload[off : off + n].decode("utf-8")
        return s, off + n

    name, offset = read_str(offset)
    media_type, offset = read_str(offset)

    if offset + 8 > len(payload):
        raise ValueError("truncated before data_size field")
    (data_size,) = struct.unpack_from("<Q", payload, offset)
    offset += 8
    if offset + data_size > len(payload):
        raise ValueError(
            f"attachment data_size {data_size} exceeds remaining bytes "
            f"({len(payload) - offset})"
        )
    att_data = payload[offset : offset + data_size]
    return log_time, create_time, name, media_type, att_data
