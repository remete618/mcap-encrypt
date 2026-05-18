# Changelog

All notable changes to this project are documented here.

## [Unreleased]

### Added
- **Optional metadata encryption (format v6)**: `Metadata` records can now be encrypted with three modes: `plaintext` (default, pass-through), `encrypt` (map encrypted, name visible in the file), and `encrypt-all` (both name and map encrypted). Encrypted records use opcode `0x83` (`EncryptedMetadata`). AAD for `encrypt` mode binds `file_id + name`, preventing cross-record substitution; AAD for `encrypt-all` binds `file_id` only. Standard MCAP readers skip opcode `0x83` gracefully. Go: `EncryptOptions.MetadataMode`; TypeScript: `EncryptMcapOptions.metadataMode`; Python: `encrypt_mcap(..., metadata=...)`. CLI: `mcap-encrypt encrypt --metadata encrypt|encrypt-all`. Wire format backward-compatible: existing files produced without the flag are unchanged.
- **`inspect` command (Go and TypeScript)**: `InspectFile`/`Inspect` (Go) and `inspectMcap` (TypeScript) return file metadata — `IsEncrypted`, format version, `FileID`, chunk count, compression, and per-recipient `KeyID`+`KEKAlg` — without decrypting any chunk data. No private key required. CLI: `mcap-encrypt inspect <input.mcap>`. 4 Go tests, 4 TypeScript tests.
- **Performance benchmarks in README**: `## Performance` section with throughput table (Small/Medium/Large) measured on Apple M3, covering encrypt and decrypt. Reproduce with `go test ./pkg/mcapencrypt/ -bench='BenchmarkEncrypt|BenchmarkDecrypt' -benchtime=5s`.
- **Streaming encrypt API (Go)**: `EncryptStream(r io.Reader, w io.Writer, pubKeyPems []string, ...)` accepts arbitrary `io.Reader`/`io.Writer` pairs. Input is buffered to a temp file (two-pass encrypt requires seekable input); public-key PEM strings are passed directly without file I/O. `ParsePublicKeyPEM(string) (any, error)` added for in-memory key parsing. 5 new unit tests (round-trip, multi-recipient, wrong-key rejection, re-encrypt guard, empty-key guard).
- **Python library** (`py/`): `encrypt_mcap`, `decrypt_mcap`, `iterate_messages`, `inspect_mcap`, `rotate_mcap_keys`, `generate_key_pair`, `generate_x25519_key_pair`. XChaCha20-Poly1305 backed by pynacl (libsodium) for `cryptography>=42` compatibility. 4 test modules: roundtrip, inspect, rotate, interop. All 37 Python tests pass (4 interop tests skipped when Go binary absent); 4 interop tests verify Go-encrypts/Python-decrypts and Python-encrypts/Go-decrypts for both RSA and X25519.

### Fixed
- **Zero-size chunk skip in decrypt loop (Go)**: `DecryptWithOptions`/`Decrypt` now silently skip `EncryptedChunk` records where `UncompressedSize == 0` instead of forwarding an empty payload to `writeChunkMessages`. AEAD authentication already verified the chunk before the guard triggers. Test added in `guards_test.go` using an in-memory MCAP with a genuinely zero-size encrypted chunk.

---

## [0.9.0]

### Security
- **INT-2025-001 resolved**: `ReadRecord` now returns an error instead of panicking when the 8-byte length field exceeds 4 GiB. Found by `FuzzStreamDecrypt`.
- `writeChunkMessages`: replaced `int(length)` cast with a uint64-safe bounds check before conversion, eliminating a theoretical integer overflow on 32-bit hosts or with adversarially large length fields.
- **INT-2025-002 resolved**: `ReadRecord` no longer pre-allocates the declared record length; reads are bounded to the bytes actually present (`io.LimitReader`), closing a memory-exhaustion DoS the 4 GiB cap did not prevent. Found by `FuzzStreamDecrypt`.
- **INT-2025-003 resolved**: `parseAttachmentRecord` keeps the attachment `data_size` as `uint64` with a pre-slice bounds check, eliminating a negative-`int` cast that defeated the length check and panicked. Reproducer committed as a fuzz regression seed. Found by `FuzzStreamDecrypt`.
- Four Go fuzz targets now run on every CI push (30s each): `FuzzDecodeEncryptedChunk`, `FuzzDecodeEncryptedAttachment`, `FuzzDecodeWrappedKeyData`, `FuzzStreamDecrypt`.
- `GenerateKeyPair` and `GenerateX25519KeyPair` now refuse to run if either output file already exists, preventing silent key clobber.
- Threat model, attacker assumptions, unauthenticated summary explanation, FileID binding, and format version behavior documented in `.github/SECURITY.md`.
- TypeScript key material not-zeroed limitation documented in `.github/SECURITY.md` (JS runtime provides no guaranteed memory-wipe primitive).

### Added
- **Key rotation without re-encryption**: `RotateKeys`/`RotateKeyFile` (Go) and `rotateMcapKeys` (TypeScript) re-wrap the symmetric key for a new set of recipients without decrypting any chunk data. O(file size) I/O with zero message decryption. CLI: `mcap-encrypt rotate --old-key old.priv.pem --new-key new.pub.pem input.mcap output.mcap`.
- **Warning callback on malformed attachments**: `DecryptWithOptions` (Go) and `decryptMcap` optional `onWarn` (TypeScript) emit a warning when a wrapped-key attachment cannot be parsed, instead of silently dropping it. Silent by default; fully backward compatible.
- **Encrypted attachments (format v5)**: User attachments are now encrypted with XChaCha20-Poly1305 and stored as `EncryptedAttachment` records (opcode `0x82`). Attachment data is fully opaque to readers without the private key. Attachment name, media type, and timestamps remain plaintext for enumeration without a key. AAD binds `file_id`, `name`, `media_type`, `log_time`, and `create_time`, preventing cross-file transplant and rename attacks.
- **Seekable summary section (format v4)**: Encrypted output now includes a full MCAP summary section after `DataEnd`: `Schema`, `Channel`, `Statistics`, `ChunkIndex`, and `SummaryOffset` records. `ChunkIndex` entries point at `EncryptedChunk` file offsets, enabling O(log n) time-range seeking and timeline display in any MCAP reader (including Foxglove Studio) without decrypting.
- **X25519-HKDF-XChaCha20Poly1305 key wrapping (Go and TypeScript)**: `GenerateX25519KeyPair`, `WrapSymmetricKeyX25519`, `UnwrapSymmetricKeyX25519` in Go; `generateX25519KeyPair`, `wrapSymmetricKeyX25519`, `unwrapSymmetricKeyX25519` in TypeScript. Any file can have a mix of RSA and X25519 recipients in both implementations. TypeScript auto-detects key type from the SPKI OID at encrypt time. `encryptMcap` and `decryptMcap` accept X25519 keys without API changes. Verified by 13 unit tests and 2 new interop tests (Go encrypts X25519 → TS decrypts; TS encrypts X25519 → Go decrypts).
- **Re-encrypt guard (Go and TypeScript)**: `Encrypt`/`EncryptMulti` (Go) and `encryptMcap` (TypeScript) now return an explicit error when the input file is already encrypted (contains opcode `0x81` or `0x82`) instead of silently producing an output with no user attachments.
- **Format v3**: manifest attachment required on decrypt; decrypting a v3 file without the manifest returns an error. Prevents strip attacks. All files written by this library use v3.
- **Manifest HMAC**: HMAC-SHA-256 over `chunkCount || fileID` detects tail truncation and chunk removal.
- **HKDF test vector** (`TestX25519KDFTestVector`): anchors info string, hash, and salt so a wire-incompatible KDF change causes a test failure.
- `SECURITY.md` moved to `.github/SECURITY.md`: enables GitHub's "Report a vulnerability" button and private advisory workflow.

### Fixed
- Symmetric key memory zeroed after use (`defer clear(symKey)`) in both encrypt and decrypt.
- Nonce length and minimum ciphertext size validated before AEAD open.
- Wrapped key metadata fields (version, algorithm, kek_algorithm) validated on decrypt.
- Uncompressed size verified after chunk decompression.
- Header `profile` and `library` fields preserved through decrypt in both Go and TypeScript.
- Non-chunked MCAP input rejected with a clear error in both implementations.
- `BinaryReader` bounds checks prevent out-of-bounds reads on malformed input.
- `Number(bigint)` conversions guarded against unsafe integer overflow.

### Changed
- SPKI fingerprint (SHA-256 of DER-encoded SubjectPublicKeyInfo) used as `key_id` in wrapped-key attachments.
- LZ4-compressed chunks transparently re-compressed as zstd on encrypt (JS-compatible). TypeScript rejects LZ4 source files.
- Encrypted output no longer carries the source MCAP index; decrypted output is fully re-indexed.

### Tests (Go: 85+ unit tests, 4 fuzz targets; TypeScript: 80; Python: 33; interop: 8)
- Nonce uniqueness across all chunks in a file.
- All AAD fields independently tampered (message_start_time, message_end_time, uncompressed_size, uncompressed_crc, slot_id, compression).
- FileID tampered in the wrapped-key attachment (caught by chunk AAD mismatch).
- Multi-recipient byte-identical plaintext consistency.
- LZ4 input normalized to zstd (Go) / rejected (TypeScript).
- Manifest HMAC forge detection; strip-attack prevention; tampered record count.
- Tail truncation detected via manifest.
- `writeChunkMessages` oversized inner record (uint64 overflow guard), off-by-one, truncated header.
- `GenerateKeyPair` / `GenerateX25519KeyPair` refuse to overwrite existing key files.
- `ReadRecord` oversized length field rejected; at-limit value accepted.
- Encrypted attachment round-trip (single and multiple attachments, Go and TypeScript).
- Encrypted attachment ciphertext tamper rejected; plaintext name tamper detected via AAD.
- Attachment data not visible in plaintext inside the encrypted file.
- Interop: Go encrypts with attachment, TypeScript decrypts (and vice versa).
- Re-encrypting an already-encrypted MCAP returns a clear error (Go and TypeScript); no partial output left on disk.
- TypeScript AAD parity: 8 `chunkAAD()` unit tests prove each field (fileId, chunkIdx, slotId, compression, uncompressedSize, uncompressedCrc, startTime, endTime) produces distinct AAD bytes. 6 end-to-end tamper tests prove each mutable field causes AEAD rejection. fileId tamper and chunk reordering tests complete parity with the Go adversarial suite.
- TypeScript X25519: 13 unit tests (KDF vector, wrap/unwrap round-trip, wrong key rejection, RSA key type mismatch, key generation, full encrypt/decrypt round-trip, multi-recipient RSA+X25519). HKDF test vector matches the Go reference vector exactly.
- Interop X25519: 2 new tests (Go encrypts X25519 → TS decrypts; TS encrypts X25519 → Go decrypts). Go CLI reads TS-generated PKCS8/SPKI PEM files directly.
- Interop rotation: 2 new tests (Go rotates → TS decrypts; TS rotates → Go decrypts). Completes rotation parity with the encrypt/decrypt interop suite.
- Key rotation: round-trip (encrypt A → rotate to B → decrypt B), old key rejected after rotation, multi-recipient rotation (B and C both decrypt, identical messages), non-encrypted input rejected, `RotateKeyFile` leaves no temp file on failure. TypeScript mirrors all Go cases plus X25519 rotation round-trip.
- Warn callback: fires on malformed wrapped-key attachment slot (two-recipient file, first slot corrupted, second slot still decrypts cleanly); stays silent on a well-formed decrypt. Go and TypeScript both covered.

---

## [0.4.0]

### Added
- **Multi-recipient encryption**: `EncryptMulti` wraps the same symmetric key for each public key; any matching private key can decrypt.
- **Attachment passthrough**: non-key attachments survive the encrypt/decrypt round-trip in both Go and TypeScript.
- **Format v2**: AAD expanded; `file_id` added to `WrappedKeyData`; multi-recipient support.
- `FORMAT.md`: complete binary format specification.
- **TypeScript library** (`ts/`): `encryptMcap`, `decryptMcap`, `iterateMessages`, `generateKeyPair`; runs in both Node.js and browsers.
- Atomic output writes: encrypt and decrypt write to a temp file and rename on success.
- CI: `gofmt`, `staticcheck`, `govulncheck`, `npm audit`, Dependabot, cross-language interop tests.
- npm publish configuration: `package.json` exports, `tsconfig.build.json`, `.npmignore`.

---

## Format version history

| Version | Change |
|---------|--------|
| 1 | Initial format. AAD bound only `message_start_time` and `message_end_time`. No `file_id`. |
| 2 | AAD expanded to include `file_id`, `chunk_index`, `slot_id`, `compression`, `uncompressed_size`, `uncompressed_crc`. `file_id` added to `WrappedKeyData`. Multi-recipient support. |
| 3 | Manifest attachment required on decrypt; strip-attack prevention via HMAC-SHA-256. X25519 key-wrapping algorithm added. |
| 4 | Summary section added after `DataEnd`: `Schema`, `Channel`, `Statistics`, `ChunkIndex`, `SummaryOffset`. Enables O(log n) time-range seeking without decryption. |
| 5 | `EncryptedAttachment` record (opcode `0x82`) added. Attachment data encrypted; name and media type remain plaintext. |
| 6 | `EncryptedMetadata` record (opcode `0x83`) added. Metadata map (and optionally name) can be encrypted with `encrypt` or `encrypt-all` mode. Default (`plaintext`) produces no wire-format change. |
