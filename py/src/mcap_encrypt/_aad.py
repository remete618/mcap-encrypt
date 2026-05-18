"""AEAD additional data builders for chunks and attachments.

AAD is assembled exactly as specified in FORMAT.md to ensure interoperability
with the Go and TypeScript implementations.
"""
from __future__ import annotations

import struct


def chunk_aad(
    file_id: bytes,
    chunk_idx: int,
    slot_id: str,
    compression: str,
    uncompressed_size: int,
    uncompressed_crc: int,
    message_start_time: int,
    message_end_time: int,
) -> bytes:
    """Build the AEAD additional data for one EncryptedChunk.

    Layout:
        file_id             bytes[16]    (no length prefix)
        chunk_index         uint64 LE
        slot_id             string       (uint32 len + utf8)
        compression         string       (uint32 len + utf8)
        uncompressed_size   uint64 LE
        uncompressed_crc    uint32 LE
        message_start_time  uint64 LE
        message_end_time    uint64 LE
    """
    slot_b = slot_id.encode("utf-8")
    comp_b = compression.encode("utf-8")
    out = bytearray()
    out += file_id
    out += struct.pack("<Q", chunk_idx)
    out += struct.pack("<I", len(slot_b))
    out += slot_b
    out += struct.pack("<I", len(comp_b))
    out += comp_b
    out += struct.pack("<Q", uncompressed_size)
    out += struct.pack("<I", uncompressed_crc)
    out += struct.pack("<Q", message_start_time)
    out += struct.pack("<Q", message_end_time)
    return bytes(out)


def attachment_aad(
    file_id: bytes,
    name: str,
    media_type: str,
    log_time: int,
    create_time: int,
) -> bytes:
    """Build the AEAD additional data for one EncryptedAttachment.

    Layout:
        file_id     bytes[16]    (no length prefix)
        name        string       (uint32 len + utf8)
        media_type  string       (uint32 len + utf8)
        log_time    uint64 LE
        create_time uint64 LE
    """
    name_b = name.encode("utf-8")
    mt_b = media_type.encode("utf-8")
    out = bytearray()
    out += file_id
    out += struct.pack("<I", len(name_b))
    out += name_b
    out += struct.pack("<I", len(mt_b))
    out += mt_b
    out += struct.pack("<Q", log_time)
    out += struct.pack("<Q", create_time)
    return bytes(out)
