"""Re-wrap symmetric key for new recipients without re-encrypting chunk data.

Public API: rotate_mcap_keys(input_bytes, old_private_key_pem, new_public_key_pems) -> bytes
"""
from __future__ import annotations

import struct
import time
from typing import Union

from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey

from ._keys import (
    WrappedKeyData,
    _WRAPPED_KEY_VERSION,
    _load_private_key_from_pem,
    _load_public_key_from_pem,
    compute_manifest_hmac,
    spki_fingerprint,
    unwrap_sym_key,
    wrap_key_rsa,
    wrap_key_x25519,
)
from ._records import (
    OP_ATTACHMENT,
    OP_CHANNEL,
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

_ATTACHMENT_NAME = "mcap_encryption_key"
_ATTACHMENT_MEDIA_TYPE = "application/x-mcap-wrapped-key"
_MANIFEST_NAME = "mcap_encryption_manifest"
_MANIFEST_MEDIA_TYPE = "application/x-mcap-manifest"
_MANIFEST_PAYLOAD_SIZE = 40


def rotate_mcap_keys(
    input_bytes: bytes,
    old_private_key_pem: str,
    new_public_key_pems: Union[str, list[str]],
) -> bytes:
    """Re-wrap the symmetric key for new recipients without re-encrypting.

    Chunk and attachment ciphertext is copied verbatim. Only the wrapped-key
    and manifest attachments are regenerated.

    Args:
        input_bytes: Encrypted MCAP bytes.
        old_private_key_pem: PEM private key that can currently decrypt the file.
        new_public_key_pems: One or more PEM public keys for the new recipient set.

    Returns:
        Encrypted MCAP with the new wrapped-key attachments.

    Raises:
        ValueError: If the old key doesn't match, new_public_key_pems is empty,
            or the input is not a valid encrypted MCAP.
    """
    if isinstance(new_public_key_pems, str):
        new_public_key_pems = [new_public_key_pems]
    if not new_public_key_pems:
        raise ValueError("at least one new public key is required")

    try:
        old_priv = _load_private_key_from_pem(old_private_key_pem)
    except Exception as exc:
        raise ValueError(f"parse old private key: {exc}") from exc

    read_magic(input_bytes)

    # ------------------------------------------------------------------
    # Scan pass: collect key material and split content into sections.
    # ------------------------------------------------------------------
    sym_key: bytearray | None = None
    file_id: bytes | None = None
    wka_count = 0

    # Records that go into the header section (before key attachments):
    header_records: list[bytes] = []  # raw write_record() bytes
    schema_payloads: list[bytes] = []
    channel_payloads: list[bytes] = []

    # Records that go into the data section (after key attachments):
    data_records: list[bytes] = []  # raw write_record() bytes

    # Chunk metadata for the summary section.
    chunk_metas: list[dict] = []

    seen_first_chunk = False

    for opcode, payload in iter_records(input_bytes, start=8):
        if opcode == OP_HEADER:
            header_records.append(write_record(opcode, payload))

        elif opcode == OP_SCHEMA:
            header_records.append(write_record(opcode, payload))
            schema_payloads.append(payload)

        elif opcode == OP_CHANNEL:
            header_records.append(write_record(opcode, payload))
            channel_payloads.append(payload)

        elif opcode == OP_METADATA:
            data_records.append(write_record(opcode, payload))

        elif opcode == OP_ATTACHMENT:
            try:
                log_t, create_t, name, media_type, att_data = decode_attachment(payload)
            except ValueError as exc:
                raise ValueError(f"parse attachment: {exc}") from exc

            if name == _ATTACHMENT_NAME and media_type == _ATTACHMENT_MEDIA_TYPE:
                wka_count += 1
                if sym_key is None:
                    try:
                        wkd = WrappedKeyData.decode(att_data)
                        candidate = unwrap_sym_key(wkd, old_priv)
                        if len(candidate) == 32:
                            sym_key = bytearray(candidate)
                            file_id = wkd.file_id
                    except (ValueError, Exception):
                        pass
                # Skip: will be regenerated.
                continue

            if name == _MANIFEST_NAME and media_type == _MANIFEST_MEDIA_TYPE:
                # Skip: will be regenerated.
                continue

            # User attachment: keep verbatim.
            data_records.append(write_record(opcode, payload))

        elif opcode == OP_ENCRYPTED_CHUNK:
            seen_first_chunk = True
            try:
                ec = _decode_encrypted_chunk_header(payload)
            except ValueError as exc:
                raise ValueError(f"decode encrypted chunk header: {exc}") from exc

            # Record offset within data_records (fixed up after layout is known).
            chunk_metas.append({
                "data_buf_offset": sum(len(r) for r in data_records),
                "record_len": 9 + len(payload),
                "msg_start": ec["msg_start"],
                "msg_end": ec["msg_end"],
                "compression": ec["compression"],
                "compressed_size": ec["compressed_size"],
                "uncomp_size": ec["uncomp_size"],
            })
            data_records.append(write_record(opcode, payload))

        elif opcode == OP_ENCRYPTED_ATTACHMENT:
            seen_first_chunk = True
            data_records.append(write_record(opcode, payload))

        elif opcode in (OP_DATA_END, OP_FOOTER):
            break  # stop at DataEnd or Footer

    if sym_key is None:
        if wka_count == 0:
            raise ValueError(
                "no wrapped key attachment found: is this an encrypted MCAP file?"
            )
        raise ValueError(
            f"old private key does not match any of the {wka_count} "
            "recipient key(s) in this file"
        )

    # ------------------------------------------------------------------
    # Build new wrapped-key attachments.
    # ------------------------------------------------------------------
    now = int(time.time() * 1e9)
    key_att_records: list[bytes] = []

    for i, pub_pem in enumerate(new_public_key_pems):
        try:
            pub = _load_public_key_from_pem(pub_pem)
        except Exception as exc:
            raise ValueError(f"load new public key {i + 1}: {exc}") from exc

        key_id = spki_fingerprint(pub)
        if isinstance(pub, RSAPublicKey):
            wrapped = wrap_key_rsa(bytes(sym_key), pub)
            kek_alg = "rsa-oaep-sha256"
        elif isinstance(pub, X25519PublicKey):
            wrapped = wrap_key_x25519(bytes(sym_key), pub)
            kek_alg = "x25519-hkdf-xchacha20poly1305"
        else:
            raise ValueError(f"unsupported public key type {type(pub).__name__} for new recipient {i + 1}")

        wkd = WrappedKeyData(
            version=_WRAPPED_KEY_VERSION,
            file_id=file_id,  # type: ignore[arg-type]
            key_id=key_id,
            algorithm="xchacha20poly1305",
            kek_algorithm=kek_alg,
            wrapped_key=wrapped,
        )
        att_payload = encode_attachment(now, 0, _ATTACHMENT_NAME, _ATTACHMENT_MEDIA_TYPE, wkd.encode())
        key_att_records.append(write_record(OP_ATTACHMENT, att_payload))

    # Build manifest attachment.
    chunk_count = len(chunk_metas)
    mac = compute_manifest_hmac(bytes(sym_key), chunk_count, file_id)  # type: ignore
    manifest_data = struct.pack("<Q", chunk_count) + mac
    manifest_att = encode_attachment(now, 0, _MANIFEST_NAME, _MANIFEST_MEDIA_TYPE, manifest_data)
    manifest_record = write_record(OP_ATTACHMENT, manifest_att)

    # ------------------------------------------------------------------
    # Compute absolute file offsets for ChunkIndex records.
    # prefix_size = magic(8) + header_records + key_att_records + manifest_record
    # ------------------------------------------------------------------
    prefix_size = 8  # magic
    for r in header_records:
        prefix_size += len(r)
    for r in key_att_records:
        prefix_size += len(r)
    prefix_size += len(manifest_record)

    for m in chunk_metas:
        m["file_offset"] = prefix_size + m["data_buf_offset"]

    # ------------------------------------------------------------------
    # Assemble output.
    # ------------------------------------------------------------------
    out = bytearray()
    out += write_magic()
    for r in header_records:
        out += r
    for r in key_att_records:
        out += r
    out += manifest_record
    for r in data_records:
        out += r

    # DataEnd
    out += write_record(OP_DATA_END, struct.pack("<I", 0))

    # Summary section
    data_section_end = len(out)
    summary_start = data_section_end
    summary_bytes, summary_offset_start = _build_summary(
        schema_payloads, channel_payloads, chunk_metas, summary_start
    )
    out += summary_bytes

    # Footer
    out += write_record(OP_FOOTER, struct.pack("<QQI", summary_start, summary_offset_start, 0))

    # Trailing magic
    out += write_magic()

    # Zero sym_key
    for i in range(len(sym_key)):
        sym_key[i] = 0

    return bytes(out)


def _decode_encrypted_chunk_header(payload: bytes) -> dict:
    """Parse just the header fields of an EncryptedChunk for metadata."""
    if len(payload) < 28:
        raise ValueError(f"encrypted chunk payload too short ({len(payload)} bytes)")
    off = 0
    msg_start, msg_end, uncomp_size = struct.unpack_from("<QQQ", payload, off)
    off += 24
    (uncomp_crc,) = struct.unpack_from("<I", payload, off)
    off += 4

    def get_str(o: int):
        if o + 4 > len(payload):
            raise ValueError(f"truncated string length at offset {o}")
        (n,) = struct.unpack_from("<I", payload, o)
        o += 4
        if o + n > len(payload):
            raise ValueError(f"truncated string data at offset {o}")
        return payload[o : o + n].decode("utf-8"), o + n

    def get_bytes_size(o: int):
        if o + 4 > len(payload):
            raise ValueError(f"truncated bytes length at offset {o}")
        (n,) = struct.unpack_from("<I", payload, o)
        return n, o + 4 + n

    compression, off = get_str(off)
    slot_id, off = get_str(off)
    _, off = get_bytes_size(off)  # nonce: skip
    enc_size, off = get_bytes_size(off)  # encrypted_data size

    return {
        "msg_start": msg_start,
        "msg_end": msg_end,
        "uncomp_size": uncomp_size,
        "uncomp_crc": uncomp_crc,
        "compression": compression,
        "slot_id": slot_id,
        "compressed_size": enc_size,
    }


def _build_summary(
    schema_payloads: list[bytes],
    channel_payloads: list[bytes],
    chunk_metas: list[dict],
    summary_start: int,
) -> tuple[bytes, int]:
    """Build the summary section. Returns (bytes, summary_offset_start)."""
    out = bytearray()

    def emit(opcode: int, payload: bytes) -> None:
        out.extend(write_record(opcode, payload))

    groups: list[tuple] = []  # (opcode, abs_start, abs_len)

    def cur() -> int:
        return summary_start + len(out)

    # Schema group
    gs = cur()
    for sp in schema_payloads:
        emit(OP_SCHEMA, sp)
    if (gl := cur() - gs) > 0:
        groups.append((OP_SCHEMA, gs, gl))

    # Channel group
    gc = cur()
    for cp in channel_payloads:
        emit(OP_CHANNEL, cp)
    if (gl := cur() - gc) > 0:
        groups.append((OP_CHANNEL, gc, gl))

    # Statistics
    gst = cur()
    g_start = chunk_metas[0]["msg_start"] if chunk_metas else 0
    g_end = chunk_metas[0]["msg_end"] if chunk_metas else 0
    for m in chunk_metas[1:]:
        if m["msg_start"] < g_start:
            g_start = m["msg_start"]
        if m["msg_end"] > g_end:
            g_end = m["msg_end"]
    stats = bytearray()
    stats += struct.pack("<Q", 0)
    stats += struct.pack("<H", len(schema_payloads))
    stats += struct.pack("<I", len(channel_payloads))
    stats += struct.pack("<I", 0)
    stats += struct.pack("<I", 0)
    stats += struct.pack("<I", len(chunk_metas))
    stats += struct.pack("<Q", g_start)
    stats += struct.pack("<Q", g_end)
    stats += struct.pack("<I", 0)
    emit(OP_STATISTICS, bytes(stats))
    groups.append((OP_STATISTICS, gst, cur() - gst))

    # ChunkIndex
    gci = cur()
    for m in chunk_metas:
        comp_b = m["compression"].encode("utf-8")
        ci = bytearray()
        ci += struct.pack("<Q", m["msg_start"])
        ci += struct.pack("<Q", m["msg_end"])
        ci += struct.pack("<Q", m["file_offset"])
        ci += struct.pack("<Q", m["record_len"])
        ci += struct.pack("<I", 0)
        ci += struct.pack("<Q", 0)
        ci += struct.pack("<I", len(comp_b))
        ci += comp_b
        ci += struct.pack("<Q", m["compressed_size"])
        ci += struct.pack("<Q", m["uncomp_size"])
        emit(OP_CHUNK_INDEX, bytes(ci))
    if (gl := cur() - gci) > 0:
        groups.append((OP_CHUNK_INDEX, gci, gl))

    # SummaryOffset records
    summary_offset_start = cur()
    for opcode, abs_start, abs_len in groups:
        so = struct.pack("<BQQ", opcode, abs_start, abs_len)
        emit(OP_SUMMARY_OFFSET, so)

    return bytes(out), summary_offset_start
