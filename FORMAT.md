# mcap-encrypt File Format Specification

Version: **4** (current)

---

## Overview

An encrypted MCAP file is a valid MCAP file. It uses the standard MCAP container
(magic bytes, record framing, footer) with three additions:

1. A custom `EncryptedChunk` record (opcode `0x81`) replaces every standard `Chunk`.
2. One or more `Attachment` records carry the wrapped symmetric key, one per recipient.
3. One `Attachment` record carries the file manifest (chunk count + HMAC), enabling truncation detection.

Standard MCAP readers that do not know opcode `0x81` will skip encrypted chunks and
see only schemas, channels, and the key attachments in plaintext.

---

## File structure

```
<magic>                              8 bytes  89 4D 43 41 50 30 0D 0A
<Header record>                      opcode 0x01
<Schema records>                     opcode 0x03  — one per channel schema
<Channel records>                    opcode 0x04  — one per topic
<WrappedKey Attachment records>      opcode 0x09  — one per recipient
<Manifest Attachment record>         opcode 0x09  — exactly one
<EncryptedChunk records>             opcode 0x81  — one per original chunk
<DataEnd record>                     opcode 0x0F
<Summary section>                    — schemas, channels, Statistics, ChunkIndex records
<Footer record>                      opcode 0x02  — summary_start points to summary section
<magic>                              8 bytes
```

All wrapped-key and manifest attachments appear **before** the first `EncryptedChunk`
so a decoder can stream-decrypt in a single pass.

The summary section allows seekable access by time range without decryption. Each
`ChunkIndex` record (opcode `0x08`) points to an `EncryptedChunk` record at
`chunk_start_offset`. A reader that does not understand opcode `0x81` will seek to
that offset and skip the unknown record; a reader that does understand it can
decrypt the specific chunk without scanning from the beginning.

---

## Record framing

Every MCAP record (standard or custom) uses the same framing:

```
opcode    uint8
length    uint64 LE   byte length of the following data field
data      bytes[length]
```

---

## EncryptedChunk record (opcode 0x81)

Replaces a standard `Chunk`. Fields are little-endian.

| Field | Type | Description |
|---|---|---|
| `message_start_time` | `uint64 LE` | Earliest log time of messages in this chunk (nanoseconds) |
| `message_end_time` | `uint64 LE` | Latest log time of messages in this chunk (nanoseconds) |
| `uncompressed_size` | `uint64 LE` | Byte length of the plaintext records after decompression (0 = unknown) |
| `uncompressed_crc` | `uint32 LE` | CRC32-IEEE of the decompressed records (0 = not checked) |
| `compression` | `string` | Compression applied to the records before encryption: `"zstd"` or `""` |
| `slot_id` | `string` | Content-key slot identifier included in the AAD. Currently always `"key-1"`. **Not** the same as the recipient fingerprint in `WrappedKeyData.key_id`. |
| `nonce` | `bytes` | 24-byte XChaCha20 nonce (4-byte LE length prefix + 24 bytes) |
| `encrypted_data` | `bytes` | Ciphertext of the (optionally compressed) chunk records, including the 16-byte Poly1305 authentication tag (4-byte LE length prefix + N bytes) |

`string` encoding: 4-byte LE length prefix followed by UTF-8 bytes.
`bytes` encoding: 4-byte LE length prefix followed by the raw bytes.

---

## WrappedKey Attachment

Stored as a standard MCAP `Attachment` record (opcode `0x09`) with:

- `name` = `"mcap_encryption_key"`
- `media_type` = `"application/x-mcap-wrapped-key"`

The `data` field contains a `WrappedKeyData` binary payload:

| Field | Type | Description |
|---|---|---|
| `version` | `uint8` | Format version; must be `2` |
| `file_id` | `bytes[16]` | Random 16-byte file identity, same across all recipients of the same file |
| `key_id` | `string` | Hex-encoded SHA-256 of the recipient's SPKI public key DER encoding |
| `algorithm` | `string` | Symmetric cipher; must be `"xchacha20poly1305"` |
| `kek_algorithm` | `string` | Key-wrapping algorithm: `"rsa-oaep-sha256"` or `"x25519-hkdf-xchacha20poly1305"` |
| `wrapped_key` | `bytes` | Wrapped symmetric key; format depends on `kek_algorithm` (see below) |

`string` and `bytes` fields use 4-byte LE length prefixes.

### kek_algorithm: `rsa-oaep-sha256`

The 32-byte symmetric key is encrypted with RSA-OAEP-SHA-256.
`wrapped_key` length: 512 bytes (RSA-4096) or 256 bytes (RSA-2048, legacy).

### kek_algorithm: `x25519-hkdf-xchacha20poly1305`

The symmetric key is wrapped using ephemeral X25519 ECDH + HKDF-SHA-256 + XChaCha20-Poly1305:

1. Generate ephemeral X25519 key pair `(ephem_priv, ephem_pub)`.
2. `shared = X25519(ephem_priv, recipient_pub)` — 32 bytes.
3. `kek = HKDF-SHA-256(IKM=shared, salt=nil, info="mcap-encrypt x25519 v1", L=32)`.
4. `ciphertext = XChaCha20-Poly1305(key=kek, nonce=random_24_bytes).Seal(sym_key)` — 48 bytes.
5. `wrapped_key = ephem_pub(32) || nonce(24) || ciphertext(48)` — 104 bytes total.

---

## Manifest Attachment

Stored as a standard MCAP `Attachment` record (opcode `0x09`) with:

- `name` = `"mcap_encryption_manifest"`
- `media_type` = `"application/x-mcap-manifest"`

The `data` field (40 bytes total) enables truncation detection:

| Field | Type | Description |
|---|---|---|
| `chunk_count` | `uint64 LE` | Number of `EncryptedChunk` records in this file |
| `hmac` | `bytes[32]` | `HMAC-SHA-256(key=sym_key, data=chunk_count_le8 \|\| file_id)` |

During decryption:
1. Compute `expected_hmac = HMAC-SHA-256(sym_key, stored_chunk_count_le8 || file_id)`.
2. Verify `expected_hmac == stored_hmac` in constant time. Failure means the manifest was tampered.
3. Verify `stored_chunk_count == actual_chunks_decrypted`. Mismatch means the file was truncated or padded.

Files written before manifest support was added (format version 2) will not have this attachment; decoders skip verification for backwards compatibility.

---

## Authenticated Encryption

Each chunk is encrypted with **XChaCha20-Poly1305** (24-byte nonce, 16-byte tag).

The **AEAD additional data (AAD)** authenticates all plaintext metadata that must not
be altered without detection. It is serialised as:

```
file_id             bytes[16]     (no length prefix)
chunk_index         uint64 LE     position of this chunk in the file, zero-based
slot_id             string        4-byte LE length prefix + UTF-8 bytes
compression         string        4-byte LE length prefix + UTF-8 bytes
uncompressed_size   uint64 LE
uncompressed_crc    uint32 LE
message_start_time  uint64 LE
message_end_time    uint64 LE
```

Any modification to the ciphertext or to any AAD field causes AEAD authentication
to fail with a clear error. Swapping chunks between files or reordering them within
a file is detected via `file_id` and `chunk_index`. Tail truncation is detected by
the manifest attachment.

---

## Key derivation

For RSA: no KDF. The 32-byte symmetric key is generated by a CSPRNG and wrapped
directly with RSA-OAEP-SHA-256. The nonce is also CSPRNG-generated per chunk.

For X25519: the symmetric key is wrapped using ephemeral ECDH + HKDF-SHA-256 +
XChaCha20-Poly1305 as described in the WrappedKey section above.

---

## Version history

| Version | Change |
|---|---|
| 1 | Initial format. AAD bound only `message_start_time` and `message_end_time`. No `file_id`. |
| 2 | AAD expanded to include `file_id`, `chunk_index`, `key_id`, `compression`, `uncompressed_size`, and `uncompressed_crc`. `file_id` added to `WrappedKeyData`. Multi-recipient support. |
| 3 | `key_id` field in `EncryptedChunk` renamed to `slot_id` (wire value unchanged: `"key-1"`). Added `Manifest Attachment` for truncation detection. Added X25519 key-wrapping algorithm. RSA key size upgraded to 4096 bits. |
| 4 | Added summary section after `DataEnd`. Footer `summary_start` now points to a real summary containing `Schema`, `Channel`, `Statistics`, `ChunkIndex`, and `SummaryOffset` records. `ChunkIndex` entries point to `EncryptedChunk` records, enabling O(log n) time-range seeking without decryption. |

Version 1 files are rejected by this implementation. Version 2 files decrypt correctly
(manifest verification is skipped when the manifest attachment is absent). Version 3
files decrypt correctly (summary section is absent; decoders fall back to linear scan).
Re-encrypt to upgrade.
