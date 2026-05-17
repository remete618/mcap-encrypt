# Changelog

All notable changes to this project are documented here.

## [Unreleased]

### Security
- **INT-2025-001 resolved**: `ReadRecord` now returns an error instead of panicking when the 8-byte length field exceeds 4 GiB. Found by `FuzzStreamDecrypt`.
- `writeChunkMessages`: replaced `int(length)` cast with a uint64-safe bounds check before conversion, eliminating a theoretical integer overflow on 32-bit hosts or with adversarially large length fields.
- `GenerateKeyPair` and `GenerateX25519KeyPair` now refuse to run if either output file already exists, preventing silent key clobber.
- Threat model, attacker assumptions, unauthenticated summary explanation, FileID binding, and format version behavior documented in `.github/SECURITY.md`.
- TypeScript key material not-zeroed limitation documented in `.github/SECURITY.md` (JS runtime provides no guaranteed memory-wipe primitive).

### Added
- **X25519-HKDF-XChaCha20Poly1305 key wrapping**: `GenerateX25519KeyPair`, `WrapSymmetricKeyX25519`, `UnwrapSymmetricKeyX25519`. Any file can have a mix of RSA and X25519 recipients.
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

### Tests (Go: 57 unit tests, 3 fuzz targets; TypeScript: 21; interop: 2)
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
| 1 | Initial format. AAD bound only `message_start_time` and `message_end_time`. |
| 2 | AAD expanded; `file_id` added to `WrappedKeyData`; multi-recipient support. |
| 3 | Manifest attachment required on decrypt; strip-attack prevention via HMAC. |
