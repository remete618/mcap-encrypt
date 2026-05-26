"""Inspect an MCAP file (encrypted or plain) without decrypting.

Public API: inspect_mcap(input_bytes) -> InspectResult
"""
from __future__ import annotations

import dataclasses
import struct

from ._keys import WrappedKeyData
from ._records import (
    OP_ATTACHMENT,
    OP_ENCRYPTED_ATTACHMENT,
    OP_ENCRYPTED_CHUNK,
    OP_FOOTER,
    decode_attachment,
    iter_records,
    read_magic,
)

_ATTACHMENT_NAME = "mcap_encryption_key"
_ATTACHMENT_MEDIA_TYPE = "application/x-mcap-wrapped-key"
_MANIFEST_NAME = "mcap_encryption_manifest"
_MANIFEST_MEDIA_TYPE = "application/x-mcap-manifest"


@dataclasses.dataclass
class RecipientInfo:
    """Metadata about one wrapped-key slot."""
    key_id: str
    kek_alg: str
    algorithm: str


@dataclasses.dataclass
class InspectResult:
    """Metadata extracted from an MCAP file without decryption."""
    is_encrypted: bool
    format_version: int
    file_id: bytes | None
    chunk_count: int
    encrypted_chunk_count: int
    encrypted_attachment_count: int
    compression: str
    recipients: list[RecipientInfo]


def inspect_mcap(input_bytes: bytes) -> InspectResult:
    """Scan an MCAP file and return metadata without decrypting.

    Args:
        input_bytes: Raw MCAP bytes (encrypted or plain).

    Returns:
        InspectResult with all available metadata.

    Raises:
        ValueError: If not a valid MCAP file.
    """
    read_magic(input_bytes)

    result = InspectResult(
        is_encrypted=False,
        format_version=0,
        file_id=None,
        chunk_count=0,
        encrypted_chunk_count=0,
        encrypted_attachment_count=0,
        compression="",
        recipients=[],
    )
    compression_set = False

    for opcode, payload in iter_records(input_bytes, start=8):
        if opcode == OP_FOOTER:
            break

        if opcode == OP_ATTACHMENT:
            try:
                _, _, name, media_type, att_data = decode_attachment(payload)
            except ValueError:
                continue

            if name == _ATTACHMENT_NAME and media_type == _ATTACHMENT_MEDIA_TYPE:
                try:
                    wkd = WrappedKeyData.decode(att_data)
                except ValueError:
                    continue
                result.is_encrypted = True
                if result.file_id is None:
                    result.file_id = wkd.file_id
                    result.format_version = wkd.version
                result.recipients.append(
                    RecipientInfo(
                        key_id=wkd.key_id,
                        kek_alg=wkd.kek_algorithm,
                        algorithm=wkd.algorithm,
                    )
                )

            elif name == _MANIFEST_NAME and media_type == _MANIFEST_MEDIA_TYPE:
                if len(att_data) >= 8:
                    (count,) = struct.unpack_from("<Q", att_data)
                    result.chunk_count = count

        elif opcode == OP_ENCRYPTED_CHUNK:
            result.is_encrypted = True
            result.encrypted_chunk_count += 1
            if not compression_set:
                # Peek at compression string: fixed header = 3*8 + 4 = 28 bytes,
                # then uint32 compression length + bytes.
                fixed = 28
                if len(payload) >= fixed + 4:
                    (comp_len,) = struct.unpack_from("<I", payload, fixed)
                    end = fixed + 4 + comp_len
                    if end <= len(payload) and comp_len <= 64:
                        result.compression = payload[fixed + 4 : end].decode("utf-8", errors="replace")
                        compression_set = True

        elif opcode == OP_ENCRYPTED_ATTACHMENT:
            result.is_encrypted = True
            result.encrypted_attachment_count += 1

    return result
