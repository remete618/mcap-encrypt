# Security Policy

For a plain-English summary for security buyers, see [Security limitations](../docs/security-limitations.md).

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
- Plaintext attachment name and media type fields (intentional; only attachment data is encrypted)
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
Every encrypted file carries a random 16-byte FileID embedded in each wrapped-key attachment and bound into the AAD of every EncryptedChunk, every EncryptedAttachment, and every EncryptedMetadata record. Transplanting records from one file to another causes authentication to fail, because the fileID will not match.

**Format versions:**
- Version 2 (legacy): manifest attachment is optional on decryption.
- Version 3: manifest is required. Decrypting a v3 file without the manifest attachment returns an error.
- Version 4: seekable summary section added after DataEnd (Schema, Channel, Statistics, ChunkIndex, SummaryOffset). Enables O(log n) time-range seeking without decryption.
- Version 5: EncryptedAttachment record (opcode 0x82) added. User attachment data is encrypted.
- Version 6 (current): EncryptedMetadata record (opcode 0x83) added. Metadata records are optionally encrypted. Default mode is wire-compatible with version 5.

**Out of scope:**
- Side-channel and timing attacks below the level addressed by Go's `crypto/rsa` and `crypto/ecdh` packages and by the wrapped-key slot trial (see resolved finding INT-2025-004). No nanosecond-resolution constant-time guarantee is claimed; a formal timing audit (e.g. dudect) has not been performed.
- In-memory key extraction. The PEM/DER buffer is zeroed immediately after parsing; the parsed key struct is managed by the Go runtime and is not zeroed on use.
- TypeScript key material zeroing. The JavaScript runtime provides no guaranteed memory-wipe primitive; the symmetric key and private key buffers in the TypeScript implementation are not zeroed after use.
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

### INT-2025-002: `ReadRecord` memory exhaustion via eager allocation within the size cap

**Component:** `pkg/mcapencrypt/record.go`, function `ReadRecord`

**Found by:** `FuzzStreamDecrypt` during internal testing (OOM-killed in CI after the INT-2025-001 cap was already in place). Not reported externally.

**Trigger:** A record header declaring a length at or below the 4 GiB `maxRecordDataSize` cap while the stream supplies far fewer bytes. `data = make([]byte, length)` eagerly allocated the full declared size before reading, so a small hostile input could force a multi-GiB allocation. The INT-2025-001 cap rejects only values above 4 GiB; it does not prevent a ~4 GiB allocation from a value at or under the cap.

**Impact:** Memory-exhaustion denial of service. A caller passing attacker-controlled bytes to the decrypt pipeline can drive a single allocation up to ~4 GiB (measured ~3.8 to 5.3 GiB peak RSS), OOM-killing the process. No data leakage, no decryption bypass, no authentication bypass.

**Fix:** `ReadRecord` no longer pre-allocates the declared length. It reads via `io.ReadAll(io.LimitReader(r, int64(length)))`, so allocation tracks the bytes actually present, then confirms the full record was delivered or returns a truncation error. Peak RSS for the same fuzz workload dropped to ~190 MiB. The `maxRecordDataSize` cap is retained as a cheap upfront sanity bound.

**Fixed in:** commit `fix: harden input parsing`

### INT-2025-004: wrapped-key slot trial leaked recipient position via decrypt latency

**Component:** `pkg/mcapencrypt/decrypt.go`, function `streamDecrypt` (wrapped-key attachment branch)

**Found by:** Internal review; tracked as issue #21.

**Trigger:** `streamDecrypt` iterated over wrapped-key attachments and called `unwrap()` on each slot, but exited the trial loop on the first success (`if symKey != nil { continue }`) and skipped to the next slot on each failure. An attacker able to observe wall-clock decrypt latency could therefore infer which slot position belonged to a given recipient: matching the first slot returned roughly N times faster than matching the Nth slot in an N-recipient file.

**Impact:** Partial metadata leak. The wrapped-key attachments themselves are public (algorithm and ciphertext are visible to anyone with read access to the file), so the slot count is not secret, but the mapping of slot to recipient was inferable without the private key from latency alone. No confidentiality loss for message data; no authentication bypass.

**Fix:** The slot trial loop now calls `unwrap()` on every well-formed wrapped-key attachment regardless of prior results. The matching symmetric key and FileID are selected via a `crypto/subtle`-based constant-time mask copy (`ctSelectInto`) into pre-allocated fixed-length buffers, so the per-byte work in the slot loop does not depend on which slot matched. A wall-clock smoke test (`TestDecryptSlotTrialConstantTime`) decrypts an 8-recipient file with the matching key in slot 0 versus slot 7 over 200 iterations and asserts the median latency ratio stays below 1.5. Observed ratio with the fix is ~1.00. The test is a smoke test, not a cryptographic constant-time proof; a formal audit would use nanosecond-resolution measurement with statistical tooling such as dudect.

**Fixed in:** commit `fix(decrypt): constant-time wrapped-key slot trial`

### INT-2025-003: `parseAttachmentRecord` slice-bounds panic via signed cast of attachment `data_size`

**Component:** `pkg/mcapencrypt/decrypt.go`, function `parseAttachmentRecord`

**Found by:** `FuzzStreamDecrypt` during internal testing (surfaced once the INT-2025-002 fix removed the OOM that previously masked it). Not reported externally.

**Trigger:** A crafted Attachment record whose 8-byte `data_size` field has the high bit set. `dataSize := int(binary.LittleEndian.Uint64(data[o:]))` converts it to a negative `int`, so the bounds check `o+dataSize > len(data)` passes (the negative value keeps the sum small) and `data[o : o+dataSize]` then panics with `slice bounds out of range [:-N]`. Reproducer committed at `pkg/mcapencrypt/testdata/fuzz/FuzzStreamDecrypt/fb736aa59e9c6bdc`.

**Impact:** Panic (denial of service) from attacker-controlled bytes in the decrypt pipeline. No data leakage, no decryption bypass, no authentication bypass.

**Fix:** `data_size` is kept as `uint64` and validated as `dataSize > uint64(len(data)-o)` before any conversion or slicing; the slice index is computed only after the value is proven to fit the remaining buffer. The committed fuzz seed is replayed as a regression test on every `go test`.

**Fixed in:** commit `fix: harden input parsing`

## Test coverage

All tests run on every CI push (`go test -race -count=1 ./...`).

### Go: 85+ unit tests, 4 fuzz targets

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
- EncryptedAttachment opcode (`0x82`) present in output when source has attachments
- EncryptedMetadata opcode (`0x83`) present in output when source has Metadata records and metadata mode is not `plaintext`
- EncryptedMetadata records absent when metadata mode is `plaintext` (default)
- ChunkIndex (`0x08`) and Statistics (`0x0A`) present in summary section
- WrappedKeyAttachment and ManifestAttachment present
- Schema (`0x03`) and Channel (`0x04`) records readable without a key
- Plaintext Message (`0x05`) absent from encrypted output

**Encrypted attachment integrity:**
- Attachment data survives encrypt/decrypt round-trip (single and multiple attachments)
- Attachment data not visible in plaintext inside the encrypted file
- EncryptedAttachment ciphertext tamper rejected (Poly1305 tag failure)
- EncryptedAttachment name tamper rejected (AAD mismatch causes tag failure)

**Edge cases:**
- Empty MCAP input
- Non-chunked MCAP input rejected
- LZ4-compressed input normalized to zstd (Go transparently re-compresses; TypeScript rejects LZ4 source)
- Truncated file returns error, not panic
- Output file not created on failure
- Overwrite protection for both encrypt and decrypt
- Same input and output path rejected
- Private key material zeroed after use (RSA and X25519)
- Metadata passthrough verified (plaintext mode), header profile preserved

**Encrypted metadata:**
- Plaintext (default) mode: Metadata records pass through unchanged, readable without a key
- encrypt mode: map encrypted, record name visible; name tamper detected via AAD
- encrypt-all mode: full payload (name + map) encrypted; neither visible without a key
- Ciphertext tamper rejected (AEAD tag failure) for both encrypt and encrypt-all modes
- Round-trip verified for both modes across Go, TypeScript, and Python

**Key rotation:**
- Round-trip: encrypt with key A, rotate to key B, decrypt with key B — messages match original
- Old key cannot decrypt after rotation (unless it was also listed as a new recipient)
- Multi-recipient rotation: both new keys decrypt and yield identical messages
- Non-encrypted MCAP input rejected with a clear error
- `RotateKeyFile` leaves no temp file on failure (atomic write)
- TypeScript: same coverage plus X25519-to-X25519 rotation round-trip

**Warn callback:**
- `DecryptWithOptions` WarnFunc fires on a malformed wrapped-key attachment slot; decrypt still succeeds when an uncorrupted slot is present
- WarnFunc is not called on a clean, well-formed decrypt (Go and TypeScript)

**Fuzz targets:**
- `FuzzDecodeEncryptedChunk`
- `FuzzDecodeEncryptedAttachment`
- `FuzzDecodeWrappedKeyData`
- `FuzzStreamDecrypt` (found INT-2025-001, INT-2025-002, INT-2025-003)

### TypeScript: 83 unit tests

Covers RSA-4096 and X25519 key wrapping, KDF test vector (HKDF-SHA-256 output anchored against the Go reference), full AAD field tamper parity with Go (chunkAAD unit tests + end-to-end splice tests for all mutable fields + fileId tamper + chunk reordering), encrypted attachment round-trip and tamper rejection, key rotation (round-trip, old key rejected, multi-recipient, non-encrypted rejection, X25519 rotation), warn callback (fires on malformed key attachment slots and to stay silent on clean decrypts), and metadata encryption round-trip and tamper rejection (encrypt and encrypt-all modes), and format compatibility with the Go implementation.

### Python: 48 tests (44 unit + 4 interop; interop skipped when Go binary is absent)

Includes a Hypothesis-based fuzz suite covering five parser entry points
(`_decode_encrypted_chunk`, `_decode_encrypted_attachment`, `_decode_encrypted_metadata`, `WrappedKeyData.decode`, full `decrypt_mcap` pipeline) with 200 examples per target. `IndexError` and `KeyError` are explicitly excluded from the expected-exception set so any bounds-check regression surfaces as a finding.

Covers RSA-4096 and X25519 key wrapping, full encrypt/decrypt round-trip, inspect (no key required), key rotation (round-trip and multi-recipient), streaming message iteration, and metadata encryption (plaintext default, encrypt, encrypt-all modes, tamper rejection, invalid mode error). The 4 interop tests verify Go-encrypts/Python-decrypts and Python-encrypts/Go-decrypts for both RSA and X25519 recipients.

### Cross-language interop: 8 tests

- Go encrypts (RSA), TypeScript decrypts (messages).
- TypeScript encrypts (RSA), Go decrypts (messages).
- Go encrypts with attachment (RSA), TypeScript decrypts (attachment data verified).
- TypeScript encrypts with attachment (RSA), Go decrypts (attachment data verified).
- Go encrypts (X25519), TypeScript decrypts (messages).
- TypeScript encrypts (X25519), Go decrypts (messages).
- Go rotates keys, TypeScript decrypts with new key.
- TypeScript rotates keys, Go decrypts with new key.

Run as a dedicated CI job on every push.

### Re-encrypt guard

Both Go and TypeScript return an explicit error when the input file is already encrypted (contains opcode `0x81`, `0x82`, or `0x83`). Go verifies no partial output file is left on disk. This prevents the prior silent behavior where re-encrypting an encrypted MCAP would produce an output with no chunks and no user attachments.
