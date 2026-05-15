# mcap-encrypt

**Chunk-level encryption for [MCAP](https://mcap.dev) robotics data files.**

![Go](https://img.shields.io/badge/go-1.21%2B-00ADD8?logo=go&logoColor=white)
![npm](https://img.shields.io/badge/npm-mcap--encrypt-CB3837?logo=npm&logoColor=white)
![License](https://img.shields.io/badge/license-MIT-green)
![Tests](https://img.shields.io/badge/tests-passing-brightgreen)

> 🔒 Encrypts every chunk in an MCAP file with XChaCha20-Poly1305. One symmetric key per file is wrapped with each recipient's RSA-2048 public key and stored as attachments; any matching private key decrypts. Schemas and channels stay plaintext so tooling can inspect file structure without a key. Available as a Go CLI, Go library, and TypeScript/Node.js library. Files encrypted by one implementation can be decrypted by the other.

---

## Table of contents

- [What it does](#what-it-does)
- [Security model](#security-model)
- [Install](#install)
- [Quick start](#quick-start)
- [CLI reference](#cli-reference)
- [Go library](#go-library)
- [TypeScript library](#typescript-library)
- [Cross-language compatibility](#cross-language-compatibility)
- [Encrypted file format](#encrypted-file-format)
- [Known limitations](#known-limitations)
- [License](#license)

---

## What it does

> **TLDR:** Takes a standard MCAP file, encrypts every chunk, and produces a new MCAP file that standard tools cannot read without the private key.

MCAP is the standard container format for robotics sensor data (ROS 2, Foxglove, etc.). Files can contain gigabytes of camera frames, lidar scans, and telemetry. `mcap-encrypt` adds at-rest encryption to those files without changing the outer structure.

**How it works:**

1. A random 32-byte symmetric key is generated per file.
2. Every chunk in the MCAP is encrypted with XChaCha20-Poly1305 (authenticated encryption).
3. The symmetric key is RSA-OAEP-SHA-256 wrapped with each recipient's public key. Each wrapped copy is stored as a separate attachment before the first encrypted chunk.
4. Schemas and channel metadata remain in plaintext so tools can inspect topics and message types without decrypting.

Decryption is single-pass: all wrapped-key attachments appear before the first encrypted chunk so a decoder can start streaming immediately after finding one that matches.

---

## Security model

> **TLDR:** Correct AEAD encryption, random nonces, authenticated with time-bound AAD to prevent chunk swapping. Key wrapping is RSA-2048-OAEP-SHA-256.

| Layer | Algorithm | Purpose |
|---|---|---|
| Message encryption | XChaCha20-Poly1305 | Per-chunk authenticated encryption |
| Key wrapping | RSA-2048-OAEP-SHA-256 | Protects the symmetric key at rest |
| Integrity binding | AEAD additional data (AAD) | Chunk time bounds bound to ciphertext; detects modification of AAD fields |

**Properties:**

- Each file gets a fresh random 32-byte key and a fresh 24-byte nonce per chunk. Nonce reuse is not possible.
- The AEAD tag (16 bytes, appended to each encrypted chunk) detects any tampering with ciphertext or the AAD fields.
- Chunk time bounds (`message_start_time`, `message_end_time`) are used as AAD. Modifying these fields or the ciphertext breaks authentication. Note: two chunks with identical timestamps from the same file are not distinguishable by AAD alone; chunk-index binding is planned for a future format version.
- The private key is never written to disk by this tool.

**What it does not protect:**

- Attachment content (passes through plaintext, see [Known limitations](#known-limitations)).
- Schema and channel metadata (intentionally plaintext for tool compatibility).
- Against an attacker who has the private key.

---

## Install

> **TLDR:** `go install` for the CLI, `go get` for the Go library, `npm install` for TypeScript.

### Go CLI

```bash
go install github.com/remete618/mcap-encrypt/cmd/mcap-encrypt@latest
```

Or build from source:

```bash
git clone https://github.com/remete618/mcap-encrypt
cd mcap-encrypt
go build -o mcap-encrypt ./cmd/mcap-encrypt
```

### Go library

```bash
go get github.com/remete618/mcap-encrypt/pkg/mcapencrypt
```

Requires Go 1.26+.

### TypeScript / Node.js

```bash
npm install mcap-encrypt
```

Requires Node.js 18+ (uses the built-in Web Crypto API). Works in modern browsers without polyfills.

---

## Quick start

> **TLDR:** Three commands: `keygen`, `encrypt`, `decrypt`.

```bash
# 1. Generate a key pair
mcap-encrypt keygen --out mykey
# Writes mykey.priv.pem (keep secret) and mykey.pub.pem

# 2. Encrypt
mcap-encrypt encrypt --key mykey.pub.pem input.mcap encrypted.mcap

# 3. Decrypt
mcap-encrypt decrypt --key mykey.priv.pem encrypted.mcap output.mcap
```

If the output file already exists, both commands fail with an error. Pass `--force` to overwrite.

---

## CLI reference

> **TLDR:** Three subcommands. Multi-recipient via repeatable `--key`. Progress spinner with throughput. Safe-by-default (no silent overwrites, magic-byte check on input).

```
mcap-encrypt keygen  --out <basename>
mcap-encrypt encrypt --key <pub.pem> [--key <pub2.pem>...] [--force] <input.mcap> <output.mcap>
mcap-encrypt decrypt --key <priv.pem> [--force] <input.mcap> <output.mcap>
```

### keygen

Generates an RSA-2048 key pair.

| Flag | Description |
|---|---|
| `--out <basename>` | Output basename. Writes `<basename>.pub.pem` and `<basename>.priv.pem`. Default: `mcap-key`. |

### encrypt

Encrypts a standard MCAP file. Input must be a chunked MCAP (non-chunked files are rejected with a clear error). Validates magic bytes before starting. Chunks are encrypted in parallel using all available CPU cores.

| Flag | Description |
|---|---|
| `--key <pub.pem>` | Path to RSA public key. Repeatable for multi-recipient. Required. |
| `--force` | Overwrite output file if it exists. |

To encrypt for multiple recipients, repeat `--key`:

```bash
mcap-encrypt encrypt --key alice.pub.pem --key bob.pub.pem input.mcap encrypted.mcap
# Either alice.priv.pem or bob.priv.pem can decrypt the result.
```

### decrypt

Decrypts an encrypted MCAP file. Produces a standard, fully-indexed MCAP readable by any MCAP-compatible tool. The CLI prints a progress spinner and reports throughput on completion.

| Flag | Description |
|---|---|
| `--key <priv.pem>` | Path to RSA private key. Required. |
| `--force` | Overwrite output file if it exists. |

---

## Go library

> **TLDR:** Four functions: `GenerateKeyPair`, `Encrypt`, `EncryptMulti`, `Decrypt`. All take file paths. Thread-safe; chunks encrypted in parallel.

```go
import "github.com/remete618/mcap-encrypt/pkg/mcapencrypt"

// Generate a key pair, writes <base>.pub.pem and <base>.priv.pem
if err := mcapencrypt.GenerateKeyPair("mykey"); err != nil { ... }

// Encrypt for a single recipient
if err := mcapencrypt.Encrypt("input.mcap", "encrypted.mcap", "mykey.pub.pem"); err != nil { ... }

// Encrypt for multiple recipients; any private key can decrypt
if err := mcapencrypt.EncryptMulti("input.mcap", "encrypted.mcap", []string{
    "alice.pub.pem",
    "bob.pub.pem",
}); err != nil { ... }

// Decrypt: produces a standard indexed MCAP
if err := mcapencrypt.Decrypt("encrypted.mcap", "output.mcap", "mykey.priv.pem"); err != nil { ... }
```

**Input/output:**

- `Encrypt` is a convenience wrapper for `EncryptMulti` with a single key.
- `EncryptMulti` wraps the same symmetric key for each public key in the list. The file can be decrypted with any of the corresponding private keys.
- Chunks are encrypted in parallel using `runtime.NumCPU()` goroutines. Output order is deterministic.
- `Decrypt` takes an encrypted MCAP and writes a standard indexed MCAP with zstd-compressed chunks. It tries all wrapped-key attachments and succeeds when one matches.
- If `Encrypt`, `EncryptMulti`, or `Decrypt` fails partway, the output file is automatically removed.

---

## TypeScript library

> **TLDR:** In-memory API: pass `Uint8Array` in, get `Uint8Array` out. `iterateMessages` streams without materializing a full output file.

```typescript
import { generateKeyPair, encryptMcap, decryptMcap, iterateMessages } from "mcap-encrypt";
import { readFileSync, writeFileSync } from "node:fs";

// Generate a key pair (in-memory PEM strings)
const { publicKeyPem, privateKeyPem } = await generateKeyPair();

// Encrypt for a single recipient
const plain = new Uint8Array(readFileSync("input.mcap"));
const encrypted = await encryptMcap(plain, publicKeyPem);
writeFileSync("encrypted.mcap", encrypted);

// Encrypt for multiple recipients; any private key can decrypt
const encrypted2 = await encryptMcap(plain, [alicePubPem, bobPubPem]);

// Decrypt to a fully-indexed MCAP buffer (with ChunkIndex and summary section)
const enc = new Uint8Array(readFileSync("encrypted.mcap"));
const decrypted = await decryptMcap(enc, privateKeyPem);
writeFileSync("output.mcap", decrypted);

// Stream messages directly, no intermediate file
for await (const { schema, channel, message } of iterateMessages(enc, privateKeyPem)) {
  console.log(channel.topic, message.logTime, message.data);
}
```

**API surface:**

| Export | Signature | Description |
|---|---|---|
| `generateKeyPair` | `() => Promise<KeyPair>` | Generates RSA-2048 key pair, returns PEM strings. |
| `encryptMcap` | `(input: Uint8Array, pubKeyPem: string \| string[]) => Promise<Uint8Array>` | Encrypts a chunked MCAP in memory. Pass an array for multi-recipient. |
| `decryptMcap` | `(input: Uint8Array, privKeyPem: string) => Promise<Uint8Array>` | Decrypts to a fully-indexed MCAP buffer with ChunkIndex and summary section. |
| `iterateMessages` | `(input: Uint8Array, privKeyPem: string) => AsyncGenerator<{schema, channel, message}>` | Streams decrypted messages without materializing output. |

**Browser compatibility:** Uses the Web Crypto API and `fzstd` (pure-TypeScript zstd). No WASM, no Node-specific APIs. Works in Chromium 89+, Firefox 90+, Safari 15+.

---

## Cross-language compatibility

> **TLDR:** Go and TypeScript use the same wire format. A file encrypted by the CLI can be decrypted by the TypeScript library, and vice versa. Verified by automated interop tests.

Keys and encrypted files produced by the Go CLI are fully compatible with the TypeScript library:

```bash
# Go encrypts, TypeScript decrypts
mcap-encrypt encrypt --key mykey.pub.pem input.mcap enc.mcap
# → decryptMcap(readFileSync("enc.mcap"), privKeyPem) works

# TypeScript encrypts, Go decrypts
# encryptMcap(data, pubKeyPem) → write to ts-enc.mcap
mcap-encrypt decrypt --key mykey.priv.pem ts-enc.mcap output.mcap
```

Both implementations agree on:
- XChaCha20-Poly1305 nonce size (24 bytes), key size (32 bytes)
- AEAD AAD encoding (16-byte little-endian `start_time || end_time`)
- RSA-OAEP-SHA-256 key wrapping
- `EncryptedChunk` wire format (opcode `0x81`)
- Wrapped key attachment format (version byte + length-prefixed fields)
- PKCS#8 private key format (PEM label `PRIVATE KEY`)

**Compression note:** Source MCAP files that use LZ4 chunk compression are automatically re-compressed to zstd during encryption. The Go library supports both LZ4 and zstd as decompression targets; the TypeScript library supports zstd only. Re-compression happens transparently and does not change decompressed content.

---

## Encrypted file format

> **TLDR:** Valid MCAP file with one custom record type (opcode `0x81`). Standard tools can open it but get no messages.

```
[magic] [Header] [Schema]* [Channel]* [WrappedKeyAttachment]+ [EncryptedChunk]* [DataEnd] [Footer] [magic]
```

The outer file is a valid MCAP. Standard MCAP readers can open it and inspect schemas and channels. They will not find any messages because the `EncryptedChunk` opcode (`0x81`) is not a standard MCAP record type.

There is one `WrappedKeyAttachment` per recipient. All wrapped copies encode the same symmetric key, wrapped separately for each public key.

### WrappedKeyAttachment

A standard MCAP Attachment record (opcode `0x09`) with:

| Field | Value |
|---|---|
| `name` | `mcap_encryption_key` |
| `media_type` | `application/x-mcap-wrapped-key` |
| `data` | Version byte (`0x01`) + length-prefixed fields |

The `data` payload encodes (in order): `key_id`, `algorithm` (`xchacha20poly1305`), `kek_alg` (`rsa-oaep-sha256`), `wrapped_key` (256 bytes for RSA-2048).

### EncryptedChunk (opcode `0x81`)

| Field | Type | Description |
|---|---|---|
| `message_start_time` | `uint64 LE` | Plaintext; used as AAD |
| `message_end_time` | `uint64 LE` | Plaintext; used as AAD |
| `uncompressed_size` | `uint64 LE` | Size of decompressed records |
| `uncompressed_crc` | `uint32 LE` | CRC32-IEEE of decompressed records (0 = not set) |
| `compression` | `string` | Compression format of the original records (`zstd` or `""`) |
| `key_id` | `string` | Key identifier matching the attachment |
| `nonce` | `bytes (4B len + 24B)` | XChaCha20 nonce |
| `encrypted_data` | `bytes (4B len + N)` | Ciphertext of compressed records + 16-byte Poly1305 tag |

All `WrappedKeyAttachment` records appear before the first `EncryptedChunk`. Decoders can begin streaming decryption in a single pass without buffering chunks.

---

## Known limitations

> **TLDR:** No key rotation, no attachment encryption, TypeScript is in-memory only. These are current constraints. The implementation uses standard AEAD primitives (XChaCha20-Poly1305) and has adversarial tests; it has not been externally audited.

The following are current constraints, not bugs. The cryptographic core is correct and passes adversarial tests.

### Functional limitations

| Limitation | Impact | Workaround |
|---|---|---|
| **No key rotation** | To change the key, you must re-encrypt the entire file. | Re-run `encrypt` with the new public key after decrypting with the old one. |
| **Attachments are not encrypted** | Attachment content passes through in plaintext. | Encrypt sensitive attachments before writing to the MCAP. |
| **Input must be chunked** | Non-chunked MCAP files are rejected. | Re-encode with chunking enabled (the Foxglove CLI and most MCAP writers produce chunked output by default). |

### TypeScript-specific limitations

| Limitation | Impact | Notes |
|---|---|---|
| **In-memory only** | The TypeScript API holds the entire file in a `Uint8Array`. | Use the Go CLI for files larger than available RAM. |
| **No LZ4 decompression** | Cannot decompress LZ4-compressed chunks directly. | Non-issue in practice: `encryptMcap()` normalizes LZ4 to zstd at encryption time. Only relevant if you hand-craft an encrypted file with LZ4 chunks. |

### Not yet implemented

- Python library.

---

## License

MIT License. Copyright (c) 2026 Radu Cioplea. See [LICENSE](LICENSE) for the full text.

Contact: radu@cioplea.com · [github.com/remete618](https://github.com/remete618) · [www.eyepaq.com](https://www.eyepaq.com)

---

> **Contributing:** Issues and PRs welcome at [github.com/remete618/mcap-encrypt](https://github.com/remete618/mcap-encrypt).
