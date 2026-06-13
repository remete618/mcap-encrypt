<h1>
<img src="assets/logo-E-golden-key-transparent.svg" width="56" height="56" valign="middle" alt="">
mcap-encrypt
</h1>

**Public-key encryption for MCAP robotics logs.**

**Build**  
[![CI](https://github.com/remete618/mcap-encrypt/actions/workflows/ci.yml/badge.svg)](https://github.com/remete618/mcap-encrypt/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/remete618/mcap-encrypt?logo=github)](https://github.com/remete618/mcap-encrypt/releases/latest)
[![npm](https://img.shields.io/npm/v/mcap-encrypt?logo=npm&logoColor=white)](https://www.npmjs.com/package/mcap-encrypt)
[![Go](https://img.shields.io/badge/go-1.26%2B-00ADD8?logo=go&logoColor=white)](https://pkg.go.dev/github.com/remete618/mcap-encrypt)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)

**Security**  
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/remete618/mcap-encrypt/badge)](https://scorecard.dev/viewer/?uri=github.com/remete618/mcap-encrypt)
[![FOSSA License](https://app.fossa.com/api/projects/custom%2B62363%2Fgithub.com%2Fremete618%2Fmcap-encrypt.svg?type=shield&issueType=license)](https://app.fossa.com/projects/custom%2B62363%2Fgithub.com%2Fremete618%2Fmcap-encrypt?ref=badge_shield&issueType=license)
[![FOSSA Security](https://app.fossa.com/api/projects/custom%2B62363%2Fgithub.com%2Fremete618%2Fmcap-encrypt.svg?type=shield&issueType=security)](https://app.fossa.com/projects/custom%2B62363%2Fgithub.com%2Fremete618%2Fmcap-encrypt?ref=badge_shield&issueType=security)
[![Renovate](https://img.shields.io/badge/renovate-enabled-brightgreen?logo=renovatebot)](https://renovatebot.com)

MCAP is the native format for [Foxglove Studio](https://foxglove.dev/studio) and ROS 2. It has excellent tooling but no built-in encryption. `mcap-encrypt` protects chunk payloads with XChaCha20-Poly1305 while keeping schemas, channels, and timestamps readable for routing and inspection without a key.

📌 **Status:** v0.x, experimental, not externally audited.  
✅ **Best for:** MCAP logs at rest; Foxglove Studio visualization via bridge; schemas and channels always accessible.  
🚫 **Not for:** hiding ROS topic names, schema definitions, or chunk-level timestamps. Those stay readable by design regardless of which encryption level you choose.

---

## What it does

<table>
<tr>
<td width="160" nowrap><img src="assets/logo-E-golden-key-transparent.svg" width="32" align="absmiddle"> <strong>1 · Encrypt</strong></td>
<td>Every chunk is encrypted with <strong>XChaCha20-Poly1305</strong>. A fresh random 32-byte key and 24-byte nonce are generated per file and per chunk. Nonce reuse is impossible.</td>
</tr>
<tr>
<td width="160" nowrap><img src="assets/logo-F-key-ribbon-transparent.svg" width="32" align="absmiddle"> <strong>2 · Wrap</strong></td>
<td>The symmetric key is wrapped separately for each recipient (<strong>RSA-4096</strong> or <strong>X25519</strong>) and stored before the first chunk. Any matching private key decrypts the whole file. Mixed-algorithm recipient lists are supported.</td>
</tr>
<tr>
<td width="160" nowrap><img src="assets/logo-G-heart-lock-transparent.svg" width="32" align="absmiddle"> <strong>3 · Seek</strong></td>
<td>An unencrypted <strong>ChunkIndex</strong> in the summary section lets any MCAP reader navigate by time range without decrypting. Foxglove Studio shows the recording timeline without a key.</td>
</tr>
<tr>
<td width="160" nowrap><img src="assets/logo-H-pixel-owl-transparent.svg" width="32" align="absmiddle"> <strong>4 · Visualize</strong></td>
<td>The <strong>bridge</strong> command decrypts to memory and serves over the Foxglove WebSocket protocol. Connect Foxglove Studio exactly as you would to a live ROS 2 robot. No persistent decrypted file remains on disk.</td>
</tr>
</table>

### Foxglove Studio bridge

`mcap-encrypt bridge` is built into this project. No separate install, no extra dependency. It works the same way as `foxglove-bridge` for ROS 2 -- start it, connect Studio, done.

```bash
mcap-encrypt bridge --key mykey.priv.pem recording.mcap
# listening: ws://localhost:8765
```

Open Foxglove Studio, add a Foxglove WebSocket connection, enter `ws://localhost:8765`. Camera feeds, lidar, plots, timeline scrubbing -- everything works. The decrypted data stays in RAM on your machine. No persistent decrypted file is written to disk. Nothing reaches Foxglove's servers.

| | `foxglove-bridge` | `mcap-encrypt bridge` |
|---|---|---|
| Data source | Live ROS 2 robot | Encrypted MCAP file |
| Studio connection | `ws://localhost:8765` | `ws://localhost:8765` |
| Private key required | No | Yes |
| Decrypted file on disk | n/a | Never |
| Multiple Studio clients | Yes | Yes |

Full walkthrough and Go API: [docs/foxglove.md](docs/foxglove.md).

### Encryption levels

| Level | CLI flag | Encrypted | Readable without a key |
|---|---|---|---|
| 1️⃣ Data only | *(default)* | Chunk payloads (sensor data, camera, lidar) | Schemas, channels, timestamps, Metadata records |
| 2️⃣ Data + metadata map | `--metadata encrypt` | Chunk payloads + Metadata key-value pairs | Schemas, channels, timestamps, Metadata names |
| 3️⃣ Data + full metadata | `--metadata encrypt-all` | Chunk payloads + Metadata names + map | Schemas, channels, timestamps only |

Each chunk gets its own random 24-byte nonce; nonce reuse is impossible. The symmetric key is wrapped once per recipient and stored before the first chunk. An unencrypted ChunkIndex lets any MCAP reader seek by time range without a key.

---

## Quick start

```bash
# Generate a key pair (RSA-4096)
mcap-encrypt keygen --out mykey

# Encrypt
mcap-encrypt encrypt --key mykey.pub.pem input.mcap encrypted.mcap

# Decrypt to a standard MCAP file
mcap-encrypt decrypt --key mykey.priv.pem encrypted.mcap output.mcap

# Visualize in Foxglove Studio without decrypting to disk
mcap-encrypt bridge --key mykey.priv.pem encrypted.mcap
# Connect Foxglove Studio to ws://localhost:8765
```

If the output file already exists, `encrypt` and `decrypt` fail. Pass `--force` to overwrite.

**Need a test MCAP?** This repo ships [`examples/sample.mcap`](examples/sample.mcap) (4.7 KB, 100 messages, two channels). Use it as the input above. To regenerate or modify the sample, run `go run ./examples/gen-sample` from the repo root.

For Foxglove-blessed test data, the [`foxglove/mcap` conformance suite](https://github.com/foxglove/mcap/tree/main/tests/conformance/data) holds hundreds of structural variants. The files are stored in Git LFS, so clone with `git lfs install && git clone https://github.com/foxglove/mcap` to pull the binaries. For real-world ROS recordings, the [Foxglove documentation](https://docs.foxglove.dev) and the [Foxglove community](https://foxglove.dev/slack) link to public datasets.

---

## Install

**Go CLI**

```bash
go install github.com/remete618/mcap-encrypt/cmd/mcap-encrypt@latest
```

**Go library**

```bash
go get github.com/remete618/mcap-encrypt/pkg/mcapencrypt
```

Requires Go 1.26+.

**TypeScript / Node.js**

```bash
npm install mcap-encrypt
```

Requires Node.js 18+. Works in modern browsers without polyfills.

**Python**

```bash
pip install mcap-encrypt
```

Requires Python 3.10+.

---

## CLI reference

```
mcap-encrypt keygen   --out <basename>
mcap-encrypt encrypt  --key <pub.pem> [--key <pub2.pem>...] [--metadata plaintext|encrypt|encrypt-all] [--force] <input.mcap> <output.mcap>
mcap-encrypt decrypt  --key <priv.pem> [--force] <input.mcap> <output.mcap>
mcap-encrypt rotate   --old-key <priv.pem> --new-key <pub.pem> [--new-key <pub2.pem>...] [--force] <input.mcap> <output.mcap>
mcap-encrypt inspect  <input.mcap>
mcap-encrypt bridge   --key <priv.pem> [--addr <host:port>] <encrypted.mcap>
```

### keygen

Generates an RSA-4096 key pair. Writes `<basename>.pub.pem` (0644) and `<basename>.priv.pem` (0600). For X25519 key pairs use `GenerateX25519KeyPair` in the Go library.

### encrypt

Accepts RSA-4096 and X25519 public keys. Repeat `--key` for multiple recipients; any private key from the set decrypts the file.

```bash
# Single recipient
mcap-encrypt encrypt --key alice.pub.pem input.mcap encrypted.mcap

# Multiple recipients
mcap-encrypt encrypt --key alice.pub.pem --key bob.pub.pem input.mcap encrypted.mcap

# Encrypt metadata key-value map (name stays readable)
mcap-encrypt encrypt --key alice.pub.pem --metadata encrypt input.mcap encrypted.mcap

# Encrypt metadata fully (name + map both hidden)
mcap-encrypt encrypt --key alice.pub.pem --metadata encrypt-all input.mcap encrypted.mcap
```

A live progress bar shows throughput and ETA. Press Ctrl-Z to pause mid-operation; `fg` to resume.

### decrypt

Produces a standard, fully-indexed MCAP readable by any MCAP tool. Accepts `--force` to overwrite.

### rotate

Re-wraps the symmetric key for new recipients without decrypting any chunk data. O(file size) I/O; zero message decryption.

```bash
mcap-encrypt rotate --old-key old.priv.pem --new-key new.pub.pem enc.mcap rotated.mcap
```

Note: `rotate` changes who can decrypt. To replace the data-encryption key itself, decrypt then re-encrypt.

### inspect

Prints file metadata (encryption status, format version, file ID, chunk count, recipients) without decrypting. No private key required. Runs at disk read speed.

### bridge

Decrypts to memory, serves over the Foxglove WebSocket protocol. Connect Foxglove Studio to `ws://localhost:8765`. No persistent decrypted file on disk. See [docs/foxglove.md](docs/foxglove.md) for the full walkthrough and comparison with `foxglove-bridge`.

---

## Go library

```go
import "github.com/remete618/mcap-encrypt/pkg/mcapencrypt"

// Key generation
mcapencrypt.GenerateKeyPair("mykey")           // RSA-4096: mykey.pub.pem + mykey.priv.pem
mcapencrypt.GenerateX25519KeyPair("mykey-x25519")

// Encrypt
mcapencrypt.Encrypt("input.mcap", "encrypted.mcap", "mykey.pub.pem")

mcapencrypt.EncryptMulti("input.mcap", "encrypted.mcap", []string{
    "alice.pub.pem", "bob.pub.pem",
})

mcapencrypt.EncryptWithOptions("input.mcap", "enc.mcap", []string{"mykey.pub.pem"}, mcapencrypt.EncryptOptions{
    MetadataMode: mcapencrypt.MetadataEncrypt,
    Progress:     func(n int64) { fmt.Printf("%d bytes\n", n) },
})

// Encrypt from any io.Reader / io.Writer (PEM strings, no file I/O)
mcapencrypt.EncryptStream(r, w, []string{pubKeyPem})

// Decrypt
mcapencrypt.Decrypt("encrypted.mcap", "output.mcap", "mykey.priv.pem")

mcapencrypt.DecryptWithOptions(r, w, "mykey.priv.pem", mcapencrypt.DecryptOptions{
    WarnFunc: func(msg string) { log.Println(msg) },
})

// Rotate keys
mcapencrypt.RotateKeyFile("encrypted.mcap", "rotated.mcap", "old.priv.pem", []string{"new.pub.pem"})

// Inspect without a key
res, _ := mcapencrypt.InspectFile("encrypted.mcap")
// res.IsEncrypted, res.FileID, res.ChunkCount, res.Recipients

// Bridge
state, _ := mcapencrypt.LoadBridgeState("encrypted.mcap", "mykey.priv.pem")
mcapencrypt.ServeBridge(ctx, state, "localhost:8765")
```

Full API reference: [docs/api.md](docs/api.md).

---

## TypeScript library

```typescript
import { generateKeyPair, generateX25519KeyPair, encryptMcap, decryptMcap, rotateMcapKeys, inspectMcap, iterateMessages } from "mcap-encrypt";

const { publicKeyPem, privateKeyPem } = await generateKeyPair(); // RSA-4096

// Encrypt (single or multi-recipient)
const encrypted = await encryptMcap(plain, publicKeyPem);
const encrypted2 = await encryptMcap(plain, [alicePem, bobPem]);
const encrypted3 = await encryptMcap(plain, publicKeyPem, { metadataMode: "encrypt" });

// Decrypt to a fully-indexed MCAP buffer
const decrypted = await decryptMcap(encrypted, privateKeyPem);

// Rotate keys without re-encrypting
const rotated = await rotateMcapKeys(encrypted, oldPrivKeyPem, [newPubKeyPem]);

// Inspect without a key
const info = inspectMcap(encrypted);

// Stream messages without materializing output
for await (const { schema, channel, message } of iterateMessages(encrypted, privateKeyPem)) {
  console.log(channel.topic, message.logTime);
}
```

Works in Node.js 18+ and modern browsers (Web Crypto API, no WASM). Does not support LZ4 source files; use the Go CLI to normalize those first. Full API reference: [docs/api.md](docs/api.md).

---

## Python library

```python
from mcap_encrypt import (
    encrypt_mcap, decrypt_mcap, iterate_messages,
    inspect_mcap, rotate_mcap_keys,
    generate_key_pair, generate_x25519_key_pair,
)

pub_pem, priv_pem = generate_key_pair()  # RSA-4096

# Encrypt (single or multi-recipient, optional metadata encryption)
encrypted = encrypt_mcap(plain_bytes, pub_pem)
encrypted2 = encrypt_mcap(plain_bytes, [alice_pem, bob_pem])
encrypted3 = encrypt_mcap(plain_bytes, pub_pem, metadata="encrypt")

# Decrypt
decrypted = decrypt_mcap(encrypted, priv_pem)

# Rotate keys
rotated = rotate_mcap_keys(encrypted, old_priv_pem, [new_pub_pem])

# Inspect without a key
info = inspect_mcap(encrypted)

# Stream messages
for schema, channel, message in iterate_messages(encrypted, priv_pem):
    print(channel.topic, message.log_time)
```

Server-side only. Requires libsodium via `pynacl`. Full API reference: [docs/api.md](docs/api.md).

---

## Security model

| Layer | Algorithm | Purpose |
|---|---|---|
| Chunk encryption | XChaCha20-Poly1305 | Authenticated encryption; 24-byte nonce eliminates random-nonce collision risk at scale |
| Key wrapping (RSA) | RSA-4096-OAEP-SHA-256 | Wraps the per-file symmetric key for RSA recipients |
| Key wrapping (X25519) | X25519-HKDF-SHA256-XChaCha20Poly1305 | Wraps the per-file symmetric key for X25519 recipients |
| Integrity binding | AEAD additional data | Binds each chunk to its file, position, timing, and compression metadata |
| Truncation detection | HMAC-SHA-256 manifest | Detects tail truncation and manifest strip attacks |

**Protected:** message payloads, attachment data, Metadata records (when requested), ciphertext integrity, chunk order, cross-file transplants, tail truncation.

**Not protected (readable without a key):**

| Data | Why |
|---|---|
| Schemas and channels | Required for MCAP tooling compatibility |
| Topic names and message timestamps | Required for timeline indexing |
| Attachment name and media type | Plaintext for enumeration; data is encrypted |
| Metadata records | Plaintext by default; use `--metadata` flags to protect them |
| Ciphertext length | Chunks are not padded |

For the full threat model, algorithm rationale, and test coverage details see [SECURITY.md](.github/SECURITY.md).

This project has not been externally audited. Do not use it as the only protection layer for highly sensitive production data without independent review.

---

## Performance

Benchmarks on **Apple M3** (arm64), Go 1.24, zstd compression.

| Scenario | File size | Encrypt | Decrypt |
|---|---|---|---|
| Small: 100 msgs x 1 KB | ~105 KB | 5 MB/s | 0.4 MB/s |
| Medium: 1,000 msgs x 4 KB | ~4 MB | 16 MB/s | 1.4 MB/s |
| Large: 5,000 msgs x 64 KB | ~236 MB | 6.5 MB/s | 0.9 MB/s |

```bash
go test ./pkg/mcapencrypt/ -run='^$' -bench='BenchmarkEncrypt|BenchmarkDecrypt' -benchtime=5s
```

Decrypt is slower because it decompresses and rebuilds a fully-indexed MCAP from scratch. TypeScript bulk cipher is 2-4x slower than Go for large files; use the Go CLI for recordings over 500 MB.

---

## Known limitations

| Limitation | Workaround |
|---|---|
| `rotate` re-wraps the same DEK; to replace the key itself, decrypt then re-encrypt | `mcap-encrypt decrypt ... && mcap-encrypt encrypt ...` |
| Input must be a chunked MCAP | Re-encode with chunking enabled (Foxglove CLI and most writers do this by default) |
| `EncryptStream` spools input to a temp file (two passes); peak RAM is O(1 chunk) but disk usage is proportional to input size | Use file-based `Encrypt`/`EncryptMulti` if temp disk overhead is not acceptable |
| Bridge loads the decrypted file into memory; the bridge hard-rejects input files larger than 5 GiB | Use `decrypt` to produce a standard file and open it in Foxglove Studio directly |
| TypeScript: in-memory only; no LZ4 source support | Use the Go CLI for large files or LZ4 sources |

---

## Troubleshooting

| Message | What it means | What to do |
|---|---|---|
| `warning: private key file ... has insecure permissions 0644` | The private key file is readable by others on the system. The CLI continues, but treat the key as compromised. | `chmod 600 mykey.priv.pem` |
| `private key does not match any of the N recipient key(s) in this file` | The private key you passed was not used at encrypt time. | Use a private key whose matching public key was passed via `--key` during encrypt. |
| `input is not an encrypted MCAP file (no wrapped key attachment present)` | You ran `decrypt` on a plain MCAP. There is nothing to decrypt. | Open the file directly, or check you meant a different file. |
| `RSA public key is N bits; minimum is 4096 bits` | The public key you provided is shorter than the format requires. | Use `mcap-encrypt keygen` (which always produces RSA-4096) or generate `openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:4096`. |
| `input file is X.X GiB which exceeds the bridge limit of 5 GiB` | The bridge loads everything into RAM. Above 5 GiB this is likely to OOM. | Run `decrypt` to write a plaintext MCAP and open it in Foxglove Studio directly. |
| Lost private key | There is no recovery path. The chunks are encrypted with a symmetric key that only the private key can unwrap. | Restore from a backup, or re-encrypt the original from source if available. Always back up `.priv.pem` files. |

---

## File format

The outer file is a valid MCAP. Standard readers open it and see schemas, channels, and the timeline. Chunk data is opaque without a key.

```
[magic] [Header] [Schema]* [Channel]* [WrappedKeyAttachment]+
[EncryptedChunk (0x81)]* [EncryptedAttachment (0x82)]* [EncryptedMetadata (0x83)]* [ManifestAttachment] [DataEnd]
[Schema]* [Channel]* [Statistics] [ChunkIndex]* [SummaryOffset]* [Footer]
[magic]
```

Full binary specification: [FORMAT.md](FORMAT.md).

---

## Contributing

Issues and PRs welcome at [github.com/remete618/mcap-encrypt](https://github.com/remete618/mcap-encrypt). Please read [CONTRIBUTING.md](CONTRIBUTING.md) first.

```bash
go test ./...                                          # Go
cd ts && npm test                                      # TypeScript
cd py && pip install -e ".[dev]" && pytest             # Python
cd ts && npm run test:interop                          # cross-language interop
```

Test counts: 85+ Go, 83 TypeScript, 43 Python (39 unit + 4 interop), 4 fuzz targets, 8 Go/TypeScript interop tests.

---

## License

[MIT](LICENSE).

Radu Cioplea · [radu@cioplea.com](mailto:radu@cioplea.com) · [eyepaq.com](https://www.eyepaq.com) · [github.com/remete618](https://github.com/remete618)
