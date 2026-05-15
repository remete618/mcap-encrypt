# Changelog

All notable changes to this project are documented here.

## [Unreleased]

### Security
- Symmetric key memory is zeroed after use with `defer clear(symKey)` in both encrypt and decrypt paths.
- Nonce length and minimum ciphertext length are validated before AEAD open.
- Wrapped key metadata fields (version, algorithm, kek_algorithm) are validated on decrypt.
- Uncompressed size is verified after chunk decompression.

### Added
- **Multi-recipient encryption**: `EncryptMulti` wraps the same symmetric key for each public key; any matching private key can decrypt.
- **Attachment passthrough**: non-key attachments survive the encrypt/decrypt round-trip in both Go and TypeScript.
- **Format v2**: AAD now binds `file_id`, `chunk_index`, `key_id`, `compression`, `uncompressed_size`, and `uncompressed_crc` in addition to timestamps. Swapped or replayed chunks are detected. Version 1 files are rejected.
- `FORMAT.md`: complete binary format specification.
- `SECURITY.md`: responsible disclosure policy and scope.
- **TypeScript library** (`ts/`): `encryptMcap`, `decryptMcap`, `iterateMessages`, `generateKeyPair`; runs in both Node.js and browsers.
- Atomic output writes: encrypt and decrypt write to a temp file and rename on success; no partial output on failure.
- CI: `gofmt`, `staticcheck`, `govulncheck`, `npm audit`, Dependabot for Go/npm/GitHub Actions.
- Cross-language interop tests between Go and TypeScript implementations.
- npm publish configuration: `package.json` exports, `tsconfig.build.json`, `.npmignore`.

### Fixed
- Header `profile` and `library` fields are preserved through decrypt in both Go and TypeScript.
- Non-chunked MCAP input is rejected with a clear error in both implementations.
- `BinaryReader` bounds checks prevent out-of-bounds reads on malformed input.
- `Number(bigint)` conversions are guarded against unsafe integer overflow.

### Changed
- SPKI fingerprint (SHA-256 of the DER-encoded SubjectPublicKeyInfo) is used as the `key_id` in wrapped-key attachments instead of a static string.
- LZ4-compressed chunks are transparently re-compressed as zstd on encrypt so the format is JS-compatible.
- Output is no longer MCAP-indexed on encrypt (index records from the source are dropped); the decrypted output is fully indexed.

---

## Format version history

| Version | Change |
|---------|--------|
| 1 | Initial format. AAD bound only `message_start_time` and `message_end_time`. |
| 2 | AAD expanded; `file_id` added to `WrappedKeyData`; multi-recipient support. |
