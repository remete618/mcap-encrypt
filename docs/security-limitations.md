# Security limitations and assumptions

## What this document is

A plain-English summary of what `mcap-encrypt` protects, what it does not, and what a security architect should weigh before deploying it. For the full threat model, algorithm rationale, and per-test coverage, read [`.github/SECURITY.md`](../.github/SECURITY.md).

## What is protected

Confidentiality and integrity, with cryptographic guarantees:

- Message payloads inside each chunk (XChaCha20-Poly1305, fresh 24-byte nonce per chunk).
- Attachment file data (XChaCha20-Poly1305, separate per-attachment nonce).
- Metadata records when the user selects `--metadata encrypt` or `--metadata encrypt-all`.
- The per-file symmetric key, wrapped separately per recipient (RSA-4096-OAEP-SHA-256 or X25519-HKDF-SHA256-XChaCha20Poly1305).
- Per-chunk integrity (AEAD authentication tag covers ciphertext, nonce, and binding metadata).
- Cross-chunk integrity: a manifest HMAC-SHA-256 detects chunk removal, tail truncation, and reordering.
- Cross-file transplant resistance: every chunk binds to a random 16-byte FileID; pasting a chunk into a different file fails authentication.

## What is NOT protected, and why

The format keeps some data readable so MCAP tools, Foxglove Studio, and the bridge can index, seek, and route without a private key. These choices are intentional and documented.

| Not protected | Why |
|---|---|
| Schemas and channel definitions | Required for standard MCAP tooling compatibility |
| Topic names and message timestamps | Required for timeline indexing and seekable summaries |
| Attachment name and media type | Plaintext so attachments can be enumerated without a key; only the attachment data is encrypted |
| Metadata records (default) | Plaintext by default; the `--metadata` flag covers them when needed |
| Ciphertext length | Chunks are not padded; an observer can see chunk sizes |
| Wrapped-key attachment count and algorithm | The number of recipients and which algorithm (RSA or X25519) each slot uses is visible |

Out of scope for this library, with explicit reasoning:

- **Side-channel attacks below the level provided by Go's `crypto/rsa` and `crypto/ecdh` packages**, plus the constant-time slot trial added in INT-2025-004. No nanosecond-resolution timing audit (for example, `dudect`) has been performed.
- **In-memory key extraction by an attacker who already has code execution on the host.** If the attacker can run code in the process, all bets are off. The library zeroes the PEM/DER buffer immediately after parsing; the parsed key struct itself lives under the Go runtime and is not zeroed.
- **Private key file storage.** Disk encryption, file permissions, HSM integration, and key escrow are the operator's responsibility. The keygen command writes private keys at `0600` and the CLI warns when a key file is world-readable, but the library does not enforce a custodian model.
- **Compromise of private keys in transit.** Out of scope; use TLS, signed delivery, or an HSM.
- **Topic name and timestamp confidentiality.** Visible by design. If hiding topic structure matters, layer the encrypted MCAP inside an additional envelope (full-disk encryption, encrypted object storage, or a tunneled bridge).

## Implementation caveats by language

The three implementations are interoperable on the wire and share the same cryptographic primitives. Runtime guarantees differ.

| Property | Go | TypeScript / Node.js | Python |
|---|---|---|---|
| AEAD primitive | `golang.org/x/crypto/chacha20poly1305` | Web Crypto + libsodium (`@noble/ciphers`) | `pynacl` (libsodium) |
| RSA wrap | `crypto/rsa` (OAEP, SHA-256) | Web Crypto SubtleCrypto | `cryptography` (OAEP, SHA-256) |
| X25519 wrap | `crypto/ecdh` + HKDF | `@noble/curves` + HKDF | `pynacl` + HKDF |
| Private key PEM buffer zeroed after parse | Yes | No (JavaScript runtime offers no guaranteed wipe) | No (CPython runtime offers no guaranteed wipe) |
| Symmetric key buffer zeroed after use | Yes | No | No |
| Constant-time slot trial | Yes (`crypto/subtle` mask copy) | Yes (constant-time selection) | Yes (constant-time selection) |
| Large file support | Streams; no in-memory cap on encrypt or decrypt | In-memory only; LZ4 source rejected | Streams |
| Recommended use | Production for any sensitive workload | Browser delivery, lightweight Node services | Server-side analytics, pipelines |

The TypeScript and Python notes are not a defect; they are a property of the runtime. If memory zeroing is a hard requirement (regulated environments, contested hosts, threat models that include process inspection by a co-tenant), use the Go CLI or Go library on the encrypt and decrypt path, and reserve the TypeScript build for browser-side decryption where the only realistic alternative is shipping no decryption at all.

## Format version handling

The format has a single explicit version byte in every wrapped-key attachment. Downgrade attempts are rejected at parse time.

- **Version 3 and later: manifest attachment is required.** A v3+ file with the manifest stripped fails to decrypt. This closes the strip-attack path where an attacker would otherwise delete the HMAC manifest to suppress truncation detection.
- **Version 2 is parsed in legacy mode only.** New files are written at the current version (v6); v2 files are still readable for backward compatibility but do not benefit from the v3+ guarantees.
- **The version byte is inside the wrapped-key attachment**, so it is implicitly bound to the recipient's key and cannot be silently rewritten without invalidating the wrap.
- **Chunk records carry a distinct opcode (`0x81`).** Re-encrypting an already-encrypted file is rejected, so a downgrade-by-re-encryption attack cannot strip records back to plaintext through normal CLI use.

## Resolved security findings

Four findings, all surfaced by internal fuzzing and review before any external release, all fixed in `main`. Listed here as evidence that fuzz-driven hardening is part of the development loop, not a weakness.

| ID | Component | Class | Resolved |
|---|---|---|---|
| INT-2025-001 | `ReadRecord` oversized length field | Panic on adversarial input | Length cap added before allocation |
| INT-2025-002 | `ReadRecord` eager allocation | Memory-exhaustion DoS | Read via `io.LimitReader`; allocation tracks bytes present |
| INT-2025-003 | `parseAttachmentRecord` signed-cast slice bounds | Panic on adversarial input | `data_size` stays `uint64`; bounds validated before conversion |
| INT-2025-004 | Wrapped-key slot trial latency | Slot-to-recipient mapping leak via wall-clock timing | Constant-time mask copy via `crypto/subtle`; wall-clock smoke test added |

None of the four findings allowed decryption without a private key, authentication bypass, or message confidentiality loss. The first three were denial-of-service vectors against the parser; the fourth was a partial-metadata leak (recipient slot position). Full per-finding writeups, including triggers, impact, and fix commits, live in [`.github/SECURITY.md`](../.github/SECURITY.md#resolved-findings).

## What this means for production use

Recommendations for a security-architect review:

- **Default to the Go CLI or Go library** on the encrypt and decrypt path for any workload where in-process memory hygiene matters. The Go path zeroes the PEM/DER buffer and uses `crypto/subtle` for the slot trial.
- **Use the TypeScript build only when browser delivery is the requirement.** Browser decryption is the strongest reason to ship in-memory key material; ship it behind a session that the user controls.
- **Use the Python build for server-side analytics and pipelines** where the file is decrypted inside a controlled environment, not on a contested host.
- **Store private keys at `0600` on POSIX hosts.** The CLI warns when a key file is world-readable; the warning is non-fatal but should be treated as a configuration error.
- **Rotate recipient keys periodically** with `mcap-encrypt rotate`. Rotation re-wraps the per-file symmetric key for new recipients without decrypting any chunk data; the operation is O(file size) on I/O and does zero AEAD work.
- **Treat the per-file symmetric key as terminal.** To replace the data-encryption key itself (not just the recipient list), decrypt and re-encrypt. The format does not support DEK rotation in place by design; rewrapping is cheap, re-keying is a deliberate operator action.
- **Pair the library with the operator's existing protections** (disk encryption, object-store SSE, transit TLS) when topic structure or timestamps are sensitive. Those fields are plaintext by design.
- **Treat v0.x as experimental** until an external audit lands. The library uses standard primitives in standard configurations and has the test coverage documented in `.github/SECURITY.md`, but it has not been externally audited. For highly sensitive production data, layer it inside an independently reviewed control.

If a deployment hits a constraint not covered here, open an issue at [`github.com/remete618/mcap-encrypt`](https://github.com/remete618/mcap-encrypt) or email `radu@cioplea.com` for a private discussion.
