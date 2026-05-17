# Security Policy

## Supported versions

Only the latest release on `main` receives security fixes.

## Reporting a vulnerability

Please **do not** open a public GitHub issue for security vulnerabilities.

Email: radu@cioplea.com

Include:
- A description of the vulnerability and its potential impact
- Steps to reproduce or a minimal proof of concept
- The affected component (Go library, TypeScript library, CLI, or file format)

Expected response time: within 7 days. If a fix is warranted, a patched release will be issued and the reporter credited (unless anonymity is requested).

## Scope

In scope:
- Incorrect AEAD usage (nonce reuse, missing authentication, AAD bypass)
- Key unwrapping vulnerabilities (RSA-OAEP misuse, oracle attacks)
- Format parsing vulnerabilities (buffer overflows, integer overflows in record parsing)
- Logic errors that allow decryption without the private key

Out of scope:
- Plaintext schema and channel metadata (intentional by design)
- Attachment content not being encrypted (documented known limitation)
- Vulnerabilities in dependencies (please report those upstream)

## Threat model

**Goals:**
- Confidentiality: message data inside EncryptedChunk records is unreadable without the recipient's private key.
- Integrity: any modification to ciphertext, nonces, AAD fields, or chunk count is detected before plaintext is returned. Per-chunk integrity is covered by AEAD authentication. Cross-chunk integrity (truncation, chunk removal) is covered by the manifest HMAC.

**Attacker model:**
The attacker has full read access to the encrypted file and knows all algorithms (Kerckhoffs principle). The symmetric key is generated randomly per file and is the only secret. Each recipient's private key is an independent secret.

**What is NOT authenticated:**
The MCAP summary section (ChunkIndex, Statistics, SummaryOffset) is plaintext and unauthenticated. This is intentional: it allows seekable access and time-range queries without the private key. The authenticated ground truth is the EncryptedChunk stream, not the summary.

**FileID:**
Every encrypted file carries a random 16-byte FileID embedded in each wrapped-key attachment and bound into the AAD of every EncryptedChunk. Transplanting a wrapped-key attachment from one file to another causes authentication to fail on the first chunk, because the fileID will not match.

**Format versions:**
- Version 2 (legacy): manifest attachment is optional on decryption.
- Version 3 (current default): manifest is required. Decrypting a v3 file without the manifest attachment returns an error. All files written by this library use version 3.

**Out of scope:**
- Side-channel and timing attacks. No constant-time guarantees beyond what Go's `crypto/rsa` and `crypto/ecdh` packages provide.
- In-memory key extraction. The PEM/DER buffer is zeroed immediately after parsing; the parsed key struct is managed by the Go runtime and is not zeroed on use.
- Compromise of private key files on disk or in transit.

## Security status

This library uses standard primitives (XChaCha20-Poly1305, RSA-4096-OAEP-SHA-256, X25519-HKDF-XChaCha20Poly1305) and has adversarial unit tests. It has **not** been externally audited. Use accordingly.

## Resolved findings

### INT-2025-001: `ReadRecord` panic on oversized length field

**Component:** `pkg/mcapencrypt/record.go`, function `ReadRecord`

**Found by:** `FuzzStreamDecrypt` during internal testing. Not reported externally.

**Trigger:** A crafted MCAP byte stream where the 8-byte little-endian length field in a record header decodes to a value exceeding addressable memory. The fuzz seed entry `\x89MCAP0\r\n` + 9 bytes of `0x30` produces a length field of `0x3030303030303030` (approx. 3.47 EiB). Go's runtime panics with `makeslice: len out of range` at the `make([]byte, length)` call inside `ReadRecord`.

**Impact:** Any caller passing attacker-controlled bytes to the decrypt pipeline can trigger a panic. No data leakage, no decryption bypass, no authentication bypass.

**Fix:** Added `maxRecordDataSize = 1 << 32` (4 GiB) constant. `ReadRecord` returns an error before any allocation if the length field exceeds this limit. No real MCAP record approaches 4 GiB; values above this indicate corrupt or adversarial input.

**Fixed in:** commit `fix: guard ReadRecord against oversized length fields`

## Test coverage

All tests run on every CI push (`go test -race -count=1 ./...`).

### Go: 45 unit tests, 3 fuzz targets

**Round-trip:**
- RSA-4096-OAEP-SHA-256 key wrapping and unwrapping
- X25519-HKDF-XChaCha20Poly1305 key wrapping and unwrapping
- Multiple recipients, mixed algorithms (one RSA, one X25519 in the same file)
- RSA key rejected when attempting to decrypt an X25519-encrypted file
- All recipients recover byte-identical plaintext (symmetric key consistency)

**Adversarial:**
- Ciphertext tamper (AEAD tag failure)
- Nonce tamper (AEAD tag failure)
- AAD tamper: each field independently (message_start_time, message_end_time, uncompressed_size, uncompressed_crc, slot_id, compression)
- Nonce uniqueness across all chunks in a file (nonce reuse detection)
- FileID tamper in the wrapped-key attachment (caught by chunk AAD mismatch)
- Wrong private key
- Manifest HMAC forge detection
- Manifest strip attack rejected under v3 (strip-attack prevention)
- Manifest tampered record count rejected
- Tail truncation detected via manifest

**Format integrity:**
- EncryptedChunk opcode (`0x81`) present in output
- ChunkIndex (`0x08`) and Statistics (`0x0A`) present in summary section
- WrappedKeyAttachment and ManifestAttachment present
- Schema (`0x03`) and Channel (`0x04`) records readable without a key
- Plaintext Message (`0x05`) absent from encrypted output

**Edge cases:**
- Empty MCAP input
- Non-chunked MCAP input rejected
- LZ4-compressed input normalized to zstd (Go transparently re-compresses; TypeScript rejects LZ4 source)
- Truncated file returns error, not panic
- Output file not created on failure
- Overwrite protection for both encrypt and decrypt
- Same input and output path rejected
- Private key material zeroed after use (RSA and X25519)
- Metadata passthrough, attachment passthrough, header profile preserved

**Fuzz targets:**
- `FuzzDecodeEncryptedChunk`
- `FuzzDecodeWrappedKeyData`
- `FuzzStreamDecrypt` (found INT-2025-001)

### TypeScript: 21 unit tests

Covers RSA-4096 and X25519 key wrapping, tamper detection, and format compatibility with the Go implementation.

### Cross-language interop: 2 tests

Go encrypts, TypeScript decrypts. TypeScript encrypts, Go decrypts. Run as a dedicated CI job on every push.
