"""Encrypt a chunked MCAP file using XChaCha20-Poly1305 + RSA/X25519 key wrapping.

Public API: encrypt_mcap(input_bytes, public_keys) -> bytes
"""
from __future__ import annotations

import secrets
import struct
import time
from typing import Union

from ._xchacha import XChaCha20Poly1305

from ._aad import attachment_aad, chunk_aad
from ._keys import (
    WrappedKeyData,
    _FILE_ID_SIZE,
    _WRAPPED_KEY_VERSION,
    _load_public_key_from_pem,
    compute_manifest_hmac,
    spki_fingerprint,
    wrap_key_rsa,
    wrap_key_x25519,
)
from ._records import (
    OP_ATTACHMENT,
    OP_CHANNEL,
    OP_CHUNK,
    OP_CHUNK_INDEX,
    OP_DATA_END,
    OP_ENCRYPTED_ATTACHMENT,
    OP_ENCRYPTED_CHUNK,
    OP_FOOTER,
    OP_HEADER,
    OP_METADATA,
    OP_SCHEMA,
    OP_STATISTICS,
    OP_SUMMARY_OFFSET,
    decode_attachment,
    encode_attachment,
    iter_records,
    read_magic,
    write_magic,
    write_record,
)
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey

# -------------------------------------------------------------------------
# Constants
# -------------------------------------------------------------------------

_SLOT_ID = "key-1"
_XCHACHA20_KEY_SIZE = 32
_XCHACHA20_NONCE_SIZE = 24
_MANIFEST_PAYLOAD_SIZE = 8 + 32  # chunk_count + HMAC-SHA256

_ATTACHMENT_NAME = "mcap_encryption_key"
_ATTACHMENT_MEDIA_TYPE = "application/x-mcap-wrapped-key"
_MANIFEST_NAME = "mcap_encryption_manifest"
_MANIFEST_MEDIA_TYPE = "application/x-mcap-manifest"


# -------------------------------------------------------------------------
# Internal helpers
# -------------------------------------------------------------------------


def _encode_chunk_record(
    message_start_time: int,
    message_end_time: int,
    uncompressed_size: int,
    uncompressed_crc: int,
    compression: str,
    slot_id: str,
    nonce: bytes,
    encrypted_data: bytes,
) -> bytes:
    """Encode an EncryptedChunk record payload (opcode 0x81)."""
    comp_b = compression.encode("utf-8")
    slot_b = slot_id.encode("utf-8")
    out = bytearray()
    out += struct.pack("<QQQ", message_start_time, message_end_time, uncompressed_size)
    out += struct.pack("<I", uncompressed_crc)
    out += struct.pack("<I", len(comp_b))
    out += comp_b
    out += struct.pack("<I", len(slot_b))
    out += slot_b
    out += struct.pack("<I", len(nonce))
    out += nonce
    out += struct.pack("<I", len(encrypted_data))
    out += encrypted_data
    return bytes(out)


def _encode_encrypted_attachment(
    name: str,
    media_type: str,
    log_time: int,
    create_time: int,
    nonce: bytes,
    encrypted_data: bytes,
) -> bytes:
    """Encode an EncryptedAttachment record payload (opcode 0x82)."""
    name_b = name.encode("utf-8")
    mt_b = media_type.encode("utf-8")
    out = bytearray()
    out += struct.pack("<I", len(name_b))
    out += name_b
    out += struct.pack("<I", len(mt_b))
    out += mt_b
    out += struct.pack("<QQ", log_time, create_time)
    out += struct.pack("<I", len(nonce))
    out += nonce
    out += struct.pack("<I", len(encrypted_data))
    out += encrypted_data
    return bytes(out)


def _parse_chunk_payload(payload: bytes):
    """Parse a standard Chunk record (opcode 0x06).

    Returns (message_start_time, message_end_time, uncompressed_size,
             uncompressed_crc, compression, records_bytes).
    """
    if len(payload) < 28:
        raise ValueError(f"chunk payload too short ({len(payload)} bytes)")
    off = 0
    msg_start, msg_end, uncomp_size = struct.unpack_from("<QQQ", payload, off)
    off += 24
    (uncomp_crc,) = struct.unpack_from("<I", payload, off)
    off += 4

    # compression string
    if off + 4 > len(payload):
        raise ValueError("truncated chunk: missing compression length")
    (comp_len,) = struct.unpack_from("<I", payload, off)
    off += 4
    if off + comp_len > len(payload):
        raise ValueError("truncated chunk: missing compression string")
    compression = payload[off : off + comp_len].decode("utf-8")
    off += comp_len

    # records_size (uint64 LE)
    if off + 8 > len(payload):
        raise ValueError("truncated chunk: missing records_size")
    (records_size,) = struct.unpack_from("<Q", payload, off)
    off += 8

    if off + records_size > len(payload):
        raise ValueError(
            f"truncated chunk: records_size={records_size}, available={len(payload)-off}"
        )
    records = payload[off : off + int(records_size)]
    return msg_start, msg_end, uncomp_size, uncomp_crc, compression, records


def _encrypt_chunk(
    payload: bytes,
    sym_key: bytes,
    file_id: bytes,
    chunk_idx: int,
) -> tuple[bytes, dict]:
    """Encrypt one Chunk record payload.

    Returns (encrypted_chunk_payload_bytes, metadata_dict) where metadata_dict
    contains: msg_start, msg_end, compression, compressed_size, uncomp_size.
    """
    msg_start, msg_end, uncomp_size, uncomp_crc, compression, records = _parse_chunk_payload(
        payload
    )

    nonce = secrets.token_bytes(_XCHACHA20_NONCE_SIZE)
    aad = chunk_aad(
        file_id=file_id,
        chunk_idx=chunk_idx,
        slot_id=_SLOT_ID,
        compression=compression,
        uncompressed_size=uncomp_size,
        uncompressed_crc=uncomp_crc,
        message_start_time=msg_start,
        message_end_time=msg_end,
    )
    aead = XChaCha20Poly1305(sym_key)
    ciphertext = aead.encrypt(nonce, bytes(records), aad)

    ec_payload = _encode_chunk_record(
        message_start_time=msg_start,
        message_end_time=msg_end,
        uncompressed_size=uncomp_size,
        uncompressed_crc=uncomp_crc,
        compression=compression,
        slot_id=_SLOT_ID,
        nonce=nonce,
        encrypted_data=ciphertext,
    )
    meta = {
        "msg_start": msg_start,
        "msg_end": msg_end,
        "compression": compression,
        "compressed_size": len(ciphertext),
        "uncomp_size": uncomp_size,
    }
    return ec_payload, meta


def _encrypt_attachment_data(
    att_data: bytes,
    sym_key: bytes,
    file_id: bytes,
    name: str,
    media_type: str,
    log_time: int,
    create_time: int,
) -> bytes:
    """Encrypt one attachment. Returns the EncryptedAttachment payload bytes."""
    nonce = secrets.token_bytes(_XCHACHA20_NONCE_SIZE)
    aad = attachment_aad(
        file_id=file_id,
        name=name,
        media_type=media_type,
        log_time=log_time,
        create_time=create_time,
    )
    aead = XChaCha20Poly1305(sym_key)
    ciphertext = aead.encrypt(nonce, att_data, aad)
    return _encode_encrypted_attachment(
        name=name,
        media_type=media_type,
        log_time=log_time,
        create_time=create_time,
        nonce=nonce,
        encrypted_data=ciphertext,
    )


def _build_wrapped_key_attachment(
    wkd: WrappedKeyData,
    now: int,
) -> bytes:
    """Encode a wrapped-key Attachment record (opcode 0x09) payload."""
    return encode_attachment(now, 0, _ATTACHMENT_NAME, _ATTACHMENT_MEDIA_TYPE, wkd.encode())


def _build_summary(
    schema_records: list[bytes],
    channel_records: list[bytes],
    chunk_metas: list[dict],
    summary_start: int,
) -> tuple[bytes, int]:
    """Build the summary section.

    Returns (summary_bytes, summary_offset_start).
    chunk_metas entries: {file_offset, record_len, msg_start, msg_end,
                          compression, compressed_size, uncomp_size}
    """
    out = bytearray()

    def emit(opcode: int, data: bytes) -> None:
        out.extend(write_record(opcode, data))

    groups: list[tuple[int, int, int]] = []  # (opcode, abs_start, abs_len)

    def group_start() -> int:
        return summary_start + len(out)

    # Schema group
    gs = group_start()
    for sr in schema_records:
        emit(OP_SCHEMA, sr)
    if (gl := summary_start + len(out) - gs) > 0:
        groups.append((OP_SCHEMA, gs, gl))

    # Channel group
    gc = group_start()
    for cr in channel_records:
        emit(OP_CHANNEL, cr)
    if (gl := summary_start + len(out) - gc) > 0:
        groups.append((OP_CHANNEL, gc, gl))

    # Statistics
    gst = group_start()
    global_start = chunk_metas[0]["msg_start"] if chunk_metas else 0
    global_end = chunk_metas[0]["msg_end"] if chunk_metas else 0
    for m in chunk_metas[1:]:
        if m["msg_start"] < global_start:
            global_start = m["msg_start"]
        if m["msg_end"] > global_end:
            global_end = m["msg_end"]
    stats = bytearray()
    stats += struct.pack("<Q", 0)  # message_count (unknown)
    stats += struct.pack("<H", len(schema_records))  # schema_count
    stats += struct.pack("<I", len(channel_records))  # channel_count
    stats += struct.pack("<I", 0)  # attachment_count
    stats += struct.pack("<I", 0)  # metadata_count
    stats += struct.pack("<I", len(chunk_metas))  # chunk_count
    stats += struct.pack("<Q", global_start)  # message_start_time
    stats += struct.pack("<Q", global_end)  # message_end_time
    stats += struct.pack("<I", 0)  # channel_message_counts (empty map)
    emit(OP_STATISTICS, bytes(stats))
    groups.append((OP_STATISTICS, gst, summary_start + len(out) - gst))

    # ChunkIndex records
    gci = group_start()
    for m in chunk_metas:
        comp_b = m["compression"].encode("utf-8")
        ci = bytearray()
        ci += struct.pack("<Q", m["msg_start"])
        ci += struct.pack("<Q", m["msg_end"])
        ci += struct.pack("<Q", m["file_offset"])
        ci += struct.pack("<Q", m["record_len"])
        ci += struct.pack("<I", 0)  # message_index_offsets: empty
        ci += struct.pack("<Q", 0)  # message_index_length: 0
        ci += struct.pack("<I", len(comp_b))
        ci += comp_b
        ci += struct.pack("<Q", m["compressed_size"])
        ci += struct.pack("<Q", m["uncomp_size"])
        emit(OP_CHUNK_INDEX, bytes(ci))
    if (gl := summary_start + len(out) - gci) > 0:
        groups.append((OP_CHUNK_INDEX, gci, gl))

    # SummaryOffset records
    summary_offset_start = summary_start + len(out)
    for opcode, abs_start, abs_len in groups:
        so = struct.pack("<BQQ", opcode, abs_start, abs_len)
        emit(OP_SUMMARY_OFFSET, so)

    return bytes(out), summary_offset_start


# -------------------------------------------------------------------------
# Public API
# -------------------------------------------------------------------------


def encrypt_mcap(
    input_bytes: bytes,
    public_keys: Union[str, list[str]],
) -> bytes:
    """Encrypt a chunked MCAP file.

    Args:
        input_bytes: Raw bytes of a standard (unencrypted) chunked MCAP file.
        public_keys: One or more PEM public keys (RSA or X25519). Each recipient
            can independently decrypt the file with their corresponding private key.

    Returns:
        Encrypted MCAP as bytes.

    Raises:
        ValueError: If input is already encrypted, not a valid MCAP, has no chunks,
            or public_keys is empty.
    """
    if isinstance(public_keys, str):
        public_keys = [public_keys]
    if not public_keys:
        raise ValueError("at least one public key is required")

    # Validate magic.
    read_magic(input_bytes)

    # Check for already-encrypted input.
    for opcode, _ in iter_records(input_bytes, start=8):
        if opcode in (OP_ENCRYPTED_CHUNK, OP_ENCRYPTED_ATTACHMENT):
            raise ValueError(
                "input is already encrypted (contains EncryptedChunk or "
                "EncryptedAttachment records); decrypt first"
            )

    # Generate symmetric key and file ID.
    sym_key = bytearray(secrets.token_bytes(_XCHACHA20_KEY_SIZE))
    file_id = secrets.token_bytes(_FILE_ID_SIZE)
    now = int(time.time() * 1e9)

    # Build wrapped-key attachments for each recipient.
    wkd_list: list[WrappedKeyData] = []
    for i, pub_pem in enumerate(public_keys):
        try:
            pub = _load_public_key_from_pem(pub_pem)
        except Exception as exc:
            raise ValueError(f"load public key {i + 1}: {exc}") from exc

        key_id = spki_fingerprint(pub)
        if isinstance(pub, RSAPublicKey):
            wrapped = wrap_key_rsa(bytes(sym_key), pub)
            kek_alg = "rsa-oaep-sha256"
        elif isinstance(pub, X25519PublicKey):
            wrapped = wrap_key_x25519(bytes(sym_key), pub)
            kek_alg = "x25519-hkdf-xchacha20poly1305"
        else:
            raise ValueError(f"unsupported public key type {type(pub).__name__} for recipient {i + 1}")

        wkd = WrappedKeyData(
            version=_WRAPPED_KEY_VERSION,
            file_id=file_id,
            key_id=key_id,
            algorithm="xchacha20poly1305",
            kek_algorithm=kek_alg,
            wrapped_key=wrapped,
        )
        wkd_list.append(wkd)

    # -----------------------------------------------------------------------
    # Pass 1: collect schema and channel records (deduped by ID).
    # -----------------------------------------------------------------------
    schema_records: list[bytes] = []  # raw payloads
    channel_records: list[bytes] = []
    seen_schema_ids: set[int] = set()
    seen_channel_ids: set[int] = set()
    header_payload: bytes | None = None

    for opcode, payload in iter_records(input_bytes, start=8):
        if opcode == OP_FOOTER:
            break
        elif opcode == OP_HEADER:
            header_payload = payload
        elif opcode == OP_SCHEMA:
            if len(payload) >= 2:
                (sid,) = struct.unpack_from("<H", payload)
                if sid not in seen_schema_ids:
                    seen_schema_ids.add(sid)
                    schema_records.append(payload)
        elif opcode == OP_CHANNEL:
            if len(payload) >= 2:
                (cid,) = struct.unpack_from("<H", payload)
                if cid not in seen_channel_ids:
                    seen_channel_ids.add(cid)
                    channel_records.append(payload)

    # -----------------------------------------------------------------------
    # Pass 2: build encrypted output.
    # Output layout:
    #   magic
    #   Header
    #   Schema records (plaintext)
    #   Channel records (plaintext)
    #   WrappedKey Attachment records
    #   Manifest Attachment placeholder (patched later)
    #   EncryptedChunk / EncryptedAttachment records
    #   DataEnd
    #   Summary section
    #   Footer
    #   magic
    # -----------------------------------------------------------------------
    out = bytearray()

    def emit(opcode: int, payload: bytes) -> int:
        """Append a record and return the byte offset before writing."""
        off = len(out)
        out.extend(write_record(opcode, payload))
        return off

    out += write_magic()

    # Header
    if header_payload is not None:
        emit(OP_HEADER, header_payload)
    else:
        # Minimal header: profile="" library=""
        emit(OP_HEADER, b"\x00\x00\x00\x00\x00\x00\x00\x00")

    # Schema and Channel records
    for sr in schema_records:
        emit(OP_SCHEMA, sr)
    for cr in channel_records:
        emit(OP_CHANNEL, cr)

    # Wrapped-key Attachment records
    for wkd in wkd_list:
        emit(OP_ATTACHMENT, _build_wrapped_key_attachment(wkd, now))

    # Manifest placeholder. We will patch the data field in-place after
    # counting chunks. We need to know the exact byte offset of the data bytes.
    # Attachment payload layout:
    #   log_time(8) create_time(8) name_len(4) name(N) mt_len(4) mt(M) data_size(8) data(40) crc(4)
    manifest_placeholder = bytes(_MANIFEST_PAYLOAD_SIZE)
    manifest_att_payload = encode_attachment(
        now, 0, _MANIFEST_NAME, _MANIFEST_MEDIA_TYPE, manifest_placeholder
    )
    # Offset of the manifest record's opcode within `out`:
    manifest_record_start = len(out)
    emit(OP_ATTACHMENT, manifest_att_payload)
    # The manifest data starts at:
    #   manifest_record_start
    #   + 9 (record header: opcode + uint64 length)
    #   + 8 (log_time) + 8 (create_time)
    #   + 4 + len(_MANIFEST_NAME)  (name)
    #   + 4 + len(_MANIFEST_MEDIA_TYPE)  (media_type)
    #   + 8 (data_size)
    _manifest_data_offset = (
        manifest_record_start
        + 9
        + 8 + 8
        + 4 + len(_MANIFEST_NAME.encode("utf-8"))
        + 4 + len(_MANIFEST_MEDIA_TYPE.encode("utf-8"))
        + 8
    )

    # Iterate records from the input and encrypt chunks and attachments.
    chunk_idx = 0
    chunk_has_been_seen = False

    # chunk_metas: metadata for the summary section ChunkIndex records.
    chunk_metas: list[dict] = []

    for opcode, payload in iter_records(input_bytes, start=8):
        if opcode == OP_CHUNK:
            chunk_has_been_seen = True
            try:
                ec_payload, ec_meta = _encrypt_chunk(payload, bytes(sym_key), file_id, chunk_idx)
            except ValueError as exc:
                raise ValueError(f"encrypt chunk {chunk_idx}: {exc}") from exc

            file_offset = len(out)
            record_bytes = write_record(OP_ENCRYPTED_CHUNK, ec_payload)
            record_len = len(record_bytes)
            out += record_bytes

            chunk_metas.append({
                "file_offset": file_offset,
                "record_len": record_len,
                "msg_start": ec_meta["msg_start"],
                "msg_end": ec_meta["msg_end"],
                "compression": ec_meta["compression"],
                "compressed_size": ec_meta["compressed_size"],
                "uncomp_size": ec_meta["uncomp_size"],
            })
            chunk_idx += 1

        elif opcode == OP_ATTACHMENT:
            try:
                log_time, create_time, name, media_type, att_data = decode_attachment(payload)
            except ValueError as exc:
                raise ValueError(f"parse attachment: {exc}") from exc
            # Skip any pre-existing encryption framework attachments.
            if (name == _ATTACHMENT_NAME and media_type == _ATTACHMENT_MEDIA_TYPE) or \
               (name == _MANIFEST_NAME and media_type == _MANIFEST_MEDIA_TYPE):
                continue
            # Encrypt user attachment.
            ea_payload = _encrypt_attachment_data(
                att_data=att_data,
                sym_key=bytes(sym_key),
                file_id=file_id,
                name=name,
                media_type=media_type,
                log_time=log_time,
                create_time=create_time,
            )
            emit(OP_ENCRYPTED_ATTACHMENT, ea_payload)

        elif opcode == OP_FOOTER:
            # Stop at the footer; trailing magic follows and is not a record.
            break

        elif opcode in (
            OP_HEADER, OP_SCHEMA, OP_CHANNEL,
            OP_CHUNK_INDEX, OP_STATISTICS, OP_SUMMARY_OFFSET,
            OP_DATA_END,
        ):
            # Skip: Header already written; schema/channel already written;
            # index records are invalid after chunk replacement; DataEnd we regenerate.
            continue

        elif opcode == OP_METADATA:
            emit(OP_METADATA, payload)

    if not chunk_has_been_seen:
        # Zero sym_key before raising.
        for i in range(len(sym_key)):
            sym_key[i] = 0
        raise ValueError(
            "input MCAP contains no Chunk records; "
            "only chunked MCAPs can be encrypted"
        )

    # -----------------------------------------------------------------------
    # Patch the manifest placeholder with the real chunk count + HMAC.
    # -----------------------------------------------------------------------
    manifest_payload = bytearray(_MANIFEST_PAYLOAD_SIZE)
    struct.pack_into("<Q", manifest_payload, 0, chunk_idx)
    hmac_bytes = compute_manifest_hmac(bytes(sym_key), chunk_idx, file_id)
    manifest_payload[8:] = hmac_bytes
    out[_manifest_data_offset : _manifest_data_offset + _MANIFEST_PAYLOAD_SIZE] = manifest_payload

    # -----------------------------------------------------------------------
    # DataEnd
    # -----------------------------------------------------------------------
    emit(OP_DATA_END, struct.pack("<I", 0))

    # -----------------------------------------------------------------------
    # Summary section
    # -----------------------------------------------------------------------
    summary_start = len(out)
    summary_bytes, summary_offset_start = _build_summary(
        schema_records=schema_records,
        channel_records=channel_records,
        chunk_metas=chunk_metas,
        summary_start=summary_start,
    )
    out += summary_bytes

    # -----------------------------------------------------------------------
    # Footer
    # -----------------------------------------------------------------------
    footer = struct.pack("<QQI", summary_start, summary_offset_start, 0)
    out += write_record(OP_FOOTER, footer)

    # -----------------------------------------------------------------------
    # Trailing magic
    # -----------------------------------------------------------------------
    out += write_magic()

    # Zero the symmetric key.
    for i in range(len(sym_key)):
        sym_key[i] = 0

    return bytes(out)
