"""Decrypt an mcap-encrypted MCAP file back to a standard MCAP.

Public API:
    decrypt_mcap(input_bytes, private_key_pem) -> bytes
    iterate_messages(input_bytes, private_key_pem) -> Iterator[dict]
"""
from __future__ import annotations

import hmac as _hmac
import struct
from typing import Iterator

from ._xchacha import XChaCha20Poly1305
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from ._aad import attachment_aad, chunk_aad, metadata_aad
from ._keys import (
    WrappedKeyData,
    _WRAPPED_KEY_VERSION,
    _load_private_key_from_pem,
    compute_manifest_hmac,
    unwrap_sym_key,
)
from ._records import (
    OP_ATTACHMENT,
    OP_CHANNEL,
    OP_CHUNK,
    OP_DATA_END,
    OP_ENCRYPTED_ATTACHMENT,
    OP_ENCRYPTED_CHUNK,
    OP_ENCRYPTED_METADATA,
    OP_FOOTER,
    OP_HEADER,
    OP_MESSAGE,
    OP_METADATA,
    OP_SCHEMA,
    decode_attachment,
    encode_attachment,
    iter_records,
    read_magic,
    write_magic,
    write_record,
)

_XCHACHA20_NONCE_SIZE = 24
_MANIFEST_NAME = "mcap_encryption_manifest"
_MANIFEST_MEDIA_TYPE = "application/x-mcap-manifest"
_ATTACHMENT_NAME = "mcap_encryption_key"
_ATTACHMENT_MEDIA_TYPE = "application/x-mcap-wrapped-key"
_MANIFEST_PAYLOAD_SIZE = 40  # chunk_count(8) + HMAC-SHA256(32)


# -------------------------------------------------------------------------
# Encrypted record decoders
# -------------------------------------------------------------------------


def _decode_encrypted_chunk(payload: bytes) -> dict:
    """Parse EncryptedChunk payload. Returns a dict of fields."""
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

    def get_bytes_field(o: int):
        if o + 4 > len(payload):
            raise ValueError(f"truncated bytes length at offset {o}")
        (n,) = struct.unpack_from("<I", payload, o)
        o += 4
        if o + n > len(payload):
            raise ValueError(f"truncated bytes data at offset {o}")
        return bytes(payload[o : o + n]), o + n

    compression, off = get_str(off)
    slot_id, off = get_str(off)
    nonce, off = get_bytes_field(off)
    encrypted_data, off = get_bytes_field(off)

    return {
        "msg_start": msg_start,
        "msg_end": msg_end,
        "uncomp_size": uncomp_size,
        "uncomp_crc": uncomp_crc,
        "compression": compression,
        "slot_id": slot_id,
        "nonce": nonce,
        "encrypted_data": encrypted_data,
    }


def _decode_encrypted_attachment(payload: bytes) -> dict:
    """Parse EncryptedAttachment payload. Returns a dict of fields."""
    if len(payload) < 4:
        raise ValueError(f"encrypted attachment payload too short ({len(payload)} bytes)")
    off = 0

    def get_str(o: int):
        if o + 4 > len(payload):
            raise ValueError(f"truncated string length at offset {o}")
        (n,) = struct.unpack_from("<I", payload, o)
        o += 4
        if o + n > len(payload):
            raise ValueError(f"truncated string data at offset {o}")
        return payload[o : o + n].decode("utf-8"), o + n

    def get_bytes_field(o: int):
        if o + 4 > len(payload):
            raise ValueError(f"truncated bytes length at offset {o}")
        (n,) = struct.unpack_from("<I", payload, o)
        o += 4
        if o + n > len(payload):
            raise ValueError(f"truncated bytes data at offset {o}")
        return bytes(payload[o : o + n]), o + n

    name, off = get_str(off)
    media_type, off = get_str(off)

    if off + 16 > len(payload):
        raise ValueError("truncated before log_time/create_time")
    log_time, create_time = struct.unpack_from("<QQ", payload, off)
    off += 16

    nonce, off = get_bytes_field(off)
    encrypted_data, off = get_bytes_field(off)

    return {
        "name": name,
        "media_type": media_type,
        "log_time": log_time,
        "create_time": create_time,
        "nonce": nonce,
        "encrypted_data": encrypted_data,
    }


def _decode_encrypted_metadata(payload: bytes) -> dict:
    """Parse EncryptedMetadata payload. Returns a dict of fields."""
    if len(payload) < 1:
        raise ValueError(f"encrypted metadata payload too short ({len(payload)} bytes)")
    off = 0

    flags = payload[off]
    off += 1
    if flags not in (0x00, 0x01):
        raise ValueError(f"unknown encrypted metadata flags 0x{flags:02x}")

    def get_str(o: int):
        if o + 4 > len(payload):
            raise ValueError(f"truncated string length at offset {o}")
        (n,) = struct.unpack_from("<I", payload, o)
        o += 4
        if o + n > len(payload):
            raise ValueError(f"truncated string data at offset {o}")
        return payload[o : o + n].decode("utf-8"), o + n

    def get_bytes_field(o: int):
        if o + 4 > len(payload):
            raise ValueError(f"truncated bytes length at offset {o}")
        (n,) = struct.unpack_from("<I", payload, o)
        o += 4
        if o + n > len(payload):
            raise ValueError(f"truncated bytes data at offset {o}")
        return bytes(payload[o : o + n]), o + n

    name, off = get_str(off)
    nonce, off = get_bytes_field(off)
    encrypted_data, off = get_bytes_field(off)

    return {
        "flags": flags,
        "name": name,
        "nonce": nonce,
        "encrypted_data": encrypted_data,
    }


def _decrypt_metadata_record(em: dict, sym_key: bytes, file_id: bytes) -> bytes:
    """Decrypt one EncryptedMetadata and return the plaintext MCAP Metadata payload."""
    nonce = em["nonce"]
    enc_data = em["encrypted_data"]
    flags = em["flags"]
    name = em["name"]

    if len(nonce) != _XCHACHA20_NONCE_SIZE:
        raise ValueError(
            f"encrypted metadata nonce length {len(nonce)} invalid "
            f"(want {_XCHACHA20_NONCE_SIZE})"
        )
    if len(enc_data) < 16:
        raise ValueError(
            f"encrypted metadata ciphertext too short ({len(enc_data)} bytes, minimum 16)"
        )

    aad = metadata_aad(file_id=file_id, flags=flags, name=name)
    aead = XChaCha20Poly1305(sym_key)
    try:
        plain = aead.decrypt(nonce, enc_data, aad)
    except Exception as exc:
        raise ValueError("decrypt metadata: AEAD authentication failed") from exc

    if flags == 0x01:
        # full metadata payload
        return bytes(plain)

    # flags == 0x00: plain = map bytes only; prepend the plaintext name
    name_b = name.encode("utf-8")
    out = bytearray()
    out += struct.pack("<I", len(name_b))
    out += name_b
    out += plain
    return bytes(out)


# -------------------------------------------------------------------------
# Decompression helpers
# -------------------------------------------------------------------------


def _decompress(data: bytes, compression: str) -> bytes:
    if compression in ("", "none"):
        return data
    if compression == "zstd":
        import zstandard
        dctx = zstandard.ZstdDecompressor()
        return dctx.decompress(data, max_output_size=256 * 1024 * 1024)
    if compression == "lz4":
        import lz4.frame
        return lz4.frame.decompress(data)
    raise ValueError(f"unsupported compression {compression!r}")


# -------------------------------------------------------------------------
# Core decrypt logic
# -------------------------------------------------------------------------


def _stream_decrypt(input_bytes: bytes, private_key: RSAPrivateKey | X25519PrivateKey) -> bytes:
    """Single-pass decrypt. Returns decrypted MCAP bytes."""

    read_magic(input_bytes)

    sym_key: bytearray | None = None
    file_id: bytes | None = None
    chunk_idx = 0
    wka_count = 0
    manifest_required = False
    manifest_payload: bytes | None = None

    header_payload: bytes | None = None
    schema_records: list[bytes] = []
    channel_records: list[bytes] = []
    # Buffered decrypted messages: (channel_id, sequence, log_time, publish_time, data)
    messages: list[tuple] = []
    # Buffered attachments: (log_time, create_time, name, media_type, data)
    attachments: list[tuple] = []
    metadata_records: list[bytes] = []
    encrypted_metadata_recs: list[dict] = []  # buffered EncryptedMetadata records

    for opcode, payload in iter_records(input_bytes, start=8):
        if opcode == OP_HEADER:
            header_payload = payload

        elif opcode == OP_SCHEMA:
            schema_records.append(payload)

        elif opcode == OP_CHANNEL:
            channel_records.append(payload)

        elif opcode == OP_METADATA:
            metadata_records.append(payload)

        elif opcode == OP_ATTACHMENT:
            try:
                log_time, create_time, name, media_type, att_data = decode_attachment(payload)
            except ValueError:
                continue

            if name == _MANIFEST_NAME and media_type == _MANIFEST_MEDIA_TYPE:
                manifest_payload = att_data
                continue

            if name == _ATTACHMENT_NAME and media_type == _ATTACHMENT_MEDIA_TYPE:
                wka_count += 1
                try:
                    wkd = WrappedKeyData.decode(att_data)
                except ValueError:
                    continue  # malformed; try next

                if wkd.version >= _WRAPPED_KEY_VERSION:
                    manifest_required = True

                if sym_key is not None:
                    continue  # already have key

                try:
                    candidate = unwrap_sym_key(wkd, private_key)
                except (ValueError, Exception):
                    continue  # wrong key; try next

                if len(candidate) != 32:
                    continue
                sym_key = bytearray(candidate)
                file_id = wkd.file_id
                continue

            # Regular (non-encryption-framework) attachment: pass through.
            attachments.append((log_time, create_time, name, media_type, att_data))

        elif opcode == OP_ENCRYPTED_ATTACHMENT:
            if sym_key is None:
                continue  # can't decrypt yet
            try:
                ea = _decode_encrypted_attachment(payload)
            except ValueError as exc:
                raise ValueError(f"decode encrypted attachment: {exc}") from exc

            nonce = ea["nonce"]
            enc_data = ea["encrypted_data"]

            if len(nonce) != _XCHACHA20_NONCE_SIZE:
                raise ValueError(
                    f"encrypted attachment nonce length {len(nonce)} invalid "
                    f"(want {_XCHACHA20_NONCE_SIZE})"
                )
            if len(enc_data) < 16:
                raise ValueError(
                    f"encrypted attachment ciphertext too short ({len(enc_data)} bytes, minimum 16)"
                )

            aad = attachment_aad(
                file_id=file_id,  # type: ignore[arg-type]
                name=ea["name"],
                media_type=ea["media_type"],
                log_time=ea["log_time"],
                create_time=ea["create_time"],
            )
            aead = XChaCha20Poly1305(bytes(sym_key))
            try:
                plain = aead.decrypt(nonce, enc_data, aad)
            except Exception as exc:
                raise ValueError(
                    f"decrypt attachment {ea['name']!r}: AEAD authentication failed"
                ) from exc
            attachments.append((
                ea["log_time"], ea["create_time"],
                ea["name"], ea["media_type"], plain,
            ))

        elif opcode == OP_ENCRYPTED_METADATA:
            try:
                em = _decode_encrypted_metadata(payload)
            except ValueError as exc:
                raise ValueError(f"decode encrypted metadata: {exc}") from exc
            encrypted_metadata_recs.append(em)

        elif opcode == OP_ENCRYPTED_CHUNK:
            if sym_key is None:
                if wka_count == 0:
                    raise ValueError(
                        "encountered encrypted chunk before wrapped key attachment"
                    )
                raise ValueError(
                    f"private key does not match any of the {wka_count} "
                    "recipient key(s) in this file"
                )

            try:
                ec = _decode_encrypted_chunk(payload)
            except ValueError as exc:
                raise ValueError(f"decode encrypted chunk: {exc}") from exc

            nonce = ec["nonce"]
            enc_data = ec["encrypted_data"]

            if len(nonce) != _XCHACHA20_NONCE_SIZE:
                raise ValueError(
                    f"chunk [{ec['msg_start']}-{ec['msg_end']}]: nonce length "
                    f"{len(nonce)} invalid (want {_XCHACHA20_NONCE_SIZE})"
                )
            if len(enc_data) < 16:
                raise ValueError(
                    f"chunk [{ec['msg_start']}-{ec['msg_end']}]: ciphertext too "
                    f"short ({len(enc_data)} bytes, minimum 16)"
                )

            aad = chunk_aad(
                file_id=file_id,  # type: ignore[arg-type]
                chunk_idx=chunk_idx,
                slot_id=ec["slot_id"],
                compression=ec["compression"],
                uncompressed_size=ec["uncomp_size"],
                uncompressed_crc=ec["uncomp_crc"],
                message_start_time=ec["msg_start"],
                message_end_time=ec["msg_end"],
            )
            aead = XChaCha20Poly1305(bytes(sym_key))
            try:
                plaintext = aead.decrypt(nonce, enc_data, aad)
            except Exception as exc:
                raise ValueError(
                    f"decrypt chunk [{ec['msg_start']}-{ec['msg_end']}]: "
                    "AEAD authentication failed"
                ) from exc
            chunk_idx += 1

            # Decompress and parse messages from the decrypted chunk.
            try:
                decompressed = _decompress(plaintext, ec["compression"])
            except Exception as exc:
                raise ValueError(f"decompress chunk: {exc}") from exc

            if ec["uncomp_size"] != 0 and len(decompressed) != ec["uncomp_size"]:
                raise ValueError(
                    f"uncompressed size mismatch: got {len(decompressed)}, "
                    f"want {ec['uncomp_size']}"
                )

            # Parse inner records (messages) from the decompressed chunk.
            inner_off = 0
            while inner_off < len(decompressed):
                if inner_off + 9 > len(decompressed):
                    break
                inner_op = decompressed[inner_off]
                (inner_len,) = struct.unpack_from("<Q", decompressed, inner_off + 1)
                inner_off += 9
                if inner_off + inner_len > len(decompressed):
                    break
                inner_payload = decompressed[inner_off : inner_off + inner_len]
                inner_off += inner_len

                if inner_op == OP_MESSAGE:
                    if len(inner_payload) < 22:
                        continue
                    channel_id, sequence = struct.unpack_from("<HI", inner_payload)
                    log_t, pub_t = struct.unpack_from("<QQ", inner_payload, 6)
                    msg_data = inner_payload[22:]
                    messages.append((channel_id, sequence, log_t, pub_t, msg_data))

        elif opcode == OP_FOOTER:
            break

    # ------------------------------------------------------------------
    # Post-scan checks
    # ------------------------------------------------------------------
    if sym_key is None:
        if wka_count == 0:
            raise ValueError(
                "no wrapped key attachment found: is this an encrypted MCAP file?"
            )
        raise ValueError(
            f"private key does not match any of the {wka_count} "
            "recipient key(s) in this file"
        )

    if manifest_required and manifest_payload is None:
        for i in range(len(sym_key)):
            sym_key[i] = 0
        raise ValueError(
            "manifest attachment missing: file may have been tampered with (strip attack)"
        )

    if manifest_payload is not None:
        if len(manifest_payload) < _MANIFEST_PAYLOAD_SIZE:
            for i in range(len(sym_key)):
                sym_key[i] = 0
            raise ValueError(
                f"manifest payload too short ({len(manifest_payload)} bytes, "
                f"need {_MANIFEST_PAYLOAD_SIZE})"
            )
        (stored_count,) = struct.unpack_from("<Q", manifest_payload)
        stored_hmac = manifest_payload[8:40]
        expected_hmac = compute_manifest_hmac(bytes(sym_key), stored_count, file_id)  # type: ignore
        if not _hmac.compare_digest(stored_hmac, expected_hmac):
            for i in range(len(sym_key)):
                sym_key[i] = 0
            raise ValueError(
                "manifest HMAC verification failed: file may be corrupted or tampered"
            )
        if stored_count != chunk_idx:
            for i in range(len(sym_key)):
                sym_key[i] = 0
            if stored_count < chunk_idx:
                raise ValueError(
                    f"manifest chunk count mismatch: declared {stored_count}, "
                    f"found {chunk_idx} (file may have been padded with extra chunks)"
                )
            raise ValueError(
                f"manifest chunk count mismatch: declared {stored_count}, "
                f"found {chunk_idx} (file appears truncated)"
            )

    # ------------------------------------------------------------------
    # Build output MCAP (flat: magic + header + schemas + channels +
    # messages-in-chunks + attachments + metadata + DataEnd + Footer + magic)
    # ------------------------------------------------------------------
    out = bytearray()
    out += write_magic()

    # Header
    if header_payload is not None:
        out += write_record(OP_HEADER, header_payload)
    else:
        out += write_record(OP_HEADER, b"\x00\x00\x00\x00\x00\x00\x00\x00")

    # Schema records
    for sr in schema_records:
        out += write_record(OP_SCHEMA, sr)

    # Channel records
    for cr in channel_records:
        out += write_record(OP_CHANNEL, cr)

    # Messages (re-wrapped as Chunk records for valid MCAP output).
    # Group all messages into a single chunk for simplicity.
    if messages:
        chunk_inner = bytearray()
        msg_start_t = messages[0][2]
        msg_end_t = messages[0][2]
        for channel_id, sequence, log_t, pub_t, msg_data in messages:
            if log_t < msg_start_t:
                msg_start_t = log_t
            if log_t > msg_end_t:
                msg_end_t = log_t
            msg_payload = struct.pack("<HI", channel_id, sequence)
            msg_payload += struct.pack("<QQ", log_t, pub_t)
            msg_payload += msg_data
            chunk_inner += write_record(OP_MESSAGE, bytes(msg_payload))

        inner_bytes = bytes(chunk_inner)
        chunk_payload = bytearray()
        chunk_payload += struct.pack("<QQQ", msg_start_t, msg_end_t, len(inner_bytes))
        chunk_payload += struct.pack("<I", 0)  # uncompressed_crc = 0
        comp_b = b""  # no compression
        chunk_payload += struct.pack("<I", len(comp_b))
        chunk_payload += comp_b
        chunk_payload += struct.pack("<Q", len(inner_bytes))
        chunk_payload += inner_bytes
        out += write_record(OP_CHUNK, bytes(chunk_payload))

    # Metadata records (plaintext)
    for mr in metadata_records:
        out += write_record(OP_METADATA, mr)

    # Encrypted metadata records (decrypt with sym_key)
    for em in encrypted_metadata_recs:
        try:
            plain = _decrypt_metadata_record(em, bytes(sym_key), file_id)  # type: ignore[arg-type]
        except ValueError as exc:
            raise ValueError(f"decrypt metadata record: {exc}") from exc
        out += write_record(OP_METADATA, plain)

    # Attachments
    for log_time, create_time, name, media_type, att_data in attachments:
        att_payload = encode_attachment(log_time, create_time, name, media_type, att_data)
        out += write_record(OP_ATTACHMENT, att_payload)

    # DataEnd
    out += write_record(OP_DATA_END, struct.pack("<I", 0))

    # Footer (no summary)
    out += write_record(OP_FOOTER, struct.pack("<QQI", 0, 0, 0))

    # Trailing magic
    out += write_magic()

    # Zero sym_key
    for i in range(len(sym_key)):
        sym_key[i] = 0

    return bytes(out)


# -------------------------------------------------------------------------
# Public API
# -------------------------------------------------------------------------


def decrypt_mcap(input_bytes: bytes, private_key_pem: str) -> bytes:
    """Decrypt an mcap-encrypted MCAP file.

    Args:
        input_bytes: Raw bytes of an encrypted MCAP file.
        private_key_pem: PEM-encoded private key (RSA or X25519, PKCS8 format).

    Returns:
        Decrypted standard MCAP as bytes.

    Raises:
        ValueError: If the file is not encrypted, the key is wrong, or
            authentication fails.
    """
    try:
        private_key = _load_private_key_from_pem(private_key_pem)
    except Exception as exc:
        raise ValueError(f"parse private key: {exc}") from exc

    return _stream_decrypt(input_bytes, private_key)


def iterate_messages(
    input_bytes: bytes,
    private_key_pem: str,
) -> Iterator[dict]:
    """Decrypt and iterate over messages without building a full MCAP output.

    Yields dicts with keys: channel_id, sequence, log_time, publish_time, data.

    Args:
        input_bytes: Raw bytes of an encrypted MCAP file.
        private_key_pem: PEM-encoded private key (RSA or X25519, PKCS8 format).

    Raises:
        ValueError: If decryption or authentication fails.
    """
    try:
        private_key = _load_private_key_from_pem(private_key_pem)
    except Exception as exc:
        raise ValueError(f"parse private key: {exc}") from exc

    read_magic(input_bytes)

    sym_key: bytearray | None = None
    file_id: bytes | None = None
    chunk_idx = 0
    wka_count = 0
    manifest_required = False
    manifest_payload: bytes | None = None
    chunks: list[dict] = []

    for opcode, payload in iter_records(input_bytes, start=8):
        if opcode == OP_ATTACHMENT:
            try:
                _, _, name, media_type, att_data = decode_attachment(payload)
            except ValueError:
                continue
            if name == _MANIFEST_NAME and media_type == _MANIFEST_MEDIA_TYPE:
                manifest_payload = att_data
                continue
            if name == _ATTACHMENT_NAME and media_type == _ATTACHMENT_MEDIA_TYPE:
                wka_count += 1
                try:
                    wkd = WrappedKeyData.decode(att_data)
                except ValueError:
                    continue
                if wkd.version >= _WRAPPED_KEY_VERSION:
                    manifest_required = True
                if sym_key is not None:
                    continue
                try:
                    candidate = unwrap_sym_key(wkd, private_key)
                except (ValueError, Exception):
                    continue
                if len(candidate) == 32:
                    sym_key = bytearray(candidate)
                    file_id = wkd.file_id

        elif opcode == OP_ENCRYPTED_CHUNK:
            chunks.append({"payload": payload, "chunk_idx": chunk_idx})
            chunk_idx += 1

        elif opcode == OP_FOOTER:
            break

    if sym_key is None:
        if wka_count == 0:
            raise ValueError("no wrapped key attachment found: is this an encrypted MCAP file?")
        raise ValueError(
            f"private key does not match any of the {wka_count} recipient key(s) in this file"
        )

    if manifest_required and manifest_payload is None:
        raise ValueError("manifest attachment missing: file may have been tampered with (strip attack)")

    if manifest_payload is not None and len(manifest_payload) >= _MANIFEST_PAYLOAD_SIZE:
        (stored_count,) = struct.unpack_from("<Q", manifest_payload)
        stored_hmac = manifest_payload[8:40]
        expected_hmac = compute_manifest_hmac(bytes(sym_key), stored_count, file_id)  # type: ignore
        if not _hmac.compare_digest(stored_hmac, expected_hmac):
            raise ValueError("manifest HMAC verification failed")
        if stored_count != len(chunks):
            raise ValueError(f"manifest chunk count mismatch: declared {stored_count}, found {len(chunks)}")

    for chunk_info in chunks:
        try:
            ec = _decode_encrypted_chunk(chunk_info["payload"])
        except ValueError as exc:
            raise ValueError(f"decode encrypted chunk: {exc}") from exc

        aad = chunk_aad(
            file_id=file_id,  # type: ignore
            chunk_idx=chunk_info["chunk_idx"],
            slot_id=ec["slot_id"],
            compression=ec["compression"],
            uncompressed_size=ec["uncomp_size"],
            uncompressed_crc=ec["uncomp_crc"],
            message_start_time=ec["msg_start"],
            message_end_time=ec["msg_end"],
        )
        aead = XChaCha20Poly1305(bytes(sym_key))
        try:
            plaintext = aead.decrypt(ec["nonce"], ec["encrypted_data"], aad)
        except Exception as exc:
            raise ValueError(f"decrypt chunk: AEAD authentication failed") from exc

        decompressed = _decompress(plaintext, ec["compression"])
        inner_off = 0
        while inner_off < len(decompressed):
            if inner_off + 9 > len(decompressed):
                break
            inner_op = decompressed[inner_off]
            (inner_len,) = struct.unpack_from("<Q", decompressed, inner_off + 1)
            inner_off += 9
            if inner_off + inner_len > len(decompressed):
                break
            inner_payload = decompressed[inner_off : inner_off + inner_len]
            inner_off += inner_len
            if inner_op == OP_MESSAGE and len(inner_payload) >= 22:
                channel_id, sequence = struct.unpack_from("<HI", inner_payload)
                log_t, pub_t = struct.unpack_from("<QQ", inner_payload, 6)
                yield {
                    "channel_id": channel_id,
                    "sequence": sequence,
                    "log_time": log_t,
                    "publish_time": pub_t,
                    "data": inner_payload[22:],
                }

    for i in range(len(sym_key)):
        sym_key[i] = 0
