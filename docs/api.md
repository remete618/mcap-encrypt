# API reference

Full function signatures and descriptions for the Go, TypeScript, and Python libraries.

---

## Go (`pkg/mcapencrypt`)

```go
import "github.com/remete618/mcap-encrypt/pkg/mcapencrypt"
```

### Key generation

| Function | Description |
|---|---|
| `GenerateKeyPair(basename string) error` | Generates RSA-4096 key pair. Writes `<basename>.pub.pem` (0644) and `<basename>.priv.pem` (0600). Errors if either file already exists. |
| `GenerateX25519KeyPair(basename string) error` | Generates X25519 key pair. Same file conventions as RSA. |
| `ParsePublicKeyPEM(pem string) (any, error)` | Parses a PEM-encoded RSA or X25519 public key from a string. Returns `*rsa.PublicKey` or `*ecdh.PublicKey`. |
| `LoadPublicKeyAny(path string) (any, error)` | Loads a public key from a PEM file. |
| `SPKIFingerprint(pub any) (string, error)` | Returns the hex-encoded SHA-256 of the SPKI DER encoding. Used as `key_id` in wrapped key attachments. |

### Encryption

| Function | Description |
|---|---|
| `Encrypt(inputPath, outputPath, pubKeyPath string) error` | Encrypts a single-recipient MCAP file. Convenience wrapper for `EncryptMulti`. |
| `EncryptMulti(inputPath, outputPath string, pubKeyPaths []string, progress ...func(int64)) error` | Encrypts for one or more recipients. Any of the corresponding private keys can decrypt. |
| `EncryptWithOptions(inputPath, outputPath string, pubKeyPaths []string, opts EncryptOptions) error` | Like `EncryptMulti` with full options. |
| `EncryptStream(r io.Reader, w io.Writer, pubKeyPems []string, progress ...func(int64)) error` | Encrypts from any `io.Reader` to any `io.Writer`. Takes PEM strings directly. Spools input to a temp file for two-pass processing; peak RAM is O(1 chunk). |
| `EncryptStreamWithOptions(r io.Reader, w io.Writer, pubKeyPems []string, opts EncryptOptions) error` | Like `EncryptStream` with full options. |

**`EncryptOptions`**

```go
type EncryptOptions struct {
    MetadataMode MetadataMode    // MetadataPlaintext (default), MetadataEncrypt, MetadataEncryptAll
    Progress     func(int64)     // called with cumulative bytes written after each chunk
}
```

### Decryption

| Function | Description |
|---|---|
| `Decrypt(inputPath, outputPath, privKeyPath string, progress ...func(int64)) error` | Decrypts to a fully-indexed MCAP file. Tries all wrapped-key slots; fails if none match. |
| `DecryptWithOptions(r io.Reader, w io.Writer, privKeyPath string, opts DecryptOptions) error` | Decrypts from a reader/writer pair with options. |

**`DecryptOptions`**

```go
type DecryptOptions struct {
    WarnFunc func(string)    // called for non-fatal issues (e.g. malformed key slots); silent by default
}
```

### Key rotation

| Function | Description |
|---|---|
| `RotateKeyFile(inputPath, outputPath, oldPrivKeyPath string, newPubKeyPaths []string) error` | Re-wraps the symmetric key for new recipients without touching chunk ciphertext. O(file size) I/O; zero chunk decryption. |
| `RotateKeys(r io.Reader, w io.Writer, oldPrivKeyPem string, newPubKeyPems []string) error` | Like `RotateKeyFile` but from reader/writer. |

### Inspection

| Function | Description |
|---|---|
| `InspectFile(path string) (*InspectResult, error)` | Returns file metadata without decrypting any chunk data. No private key required. |
| `Inspect(r io.Reader) (*InspectResult, error)` | Like `InspectFile` from a reader. |

**`InspectResult`**

```go
type InspectResult struct {
    IsEncrypted bool
    FormatVersion uint8
    FileID      string
    ChunkCount  int
    Compression string
    Recipients  []RecipientInfo
}
type RecipientInfo struct {
    KeyID      string
    KEKAlg     string
}
```

### Bridge

| Function | Description |
|---|---|
| `LoadBridgeState(mcapPath, privKeyPath string) (*BridgeState, error)` | Decrypts the file into memory and prepares the WebSocket state. |
| `ServeBridge(ctx context.Context, state *BridgeState, addr string) error` | Starts the Foxglove WebSocket server. Blocks until `ctx` is cancelled. |

---

## TypeScript (`mcap-encrypt`)

```typescript
import { ... } from "mcap-encrypt";
```

| Export | Signature | Description |
|---|---|---|
| `generateKeyPair` | `() => Promise<KeyPair>` | Generates RSA-4096 key pair. Returns `{ publicKeyPem, privateKeyPem }`. |
| `generateX25519KeyPair` | `() => Promise<X25519KeyPair>` | Generates X25519 key pair. Same shape as RSA result. |
| `encryptMcap` | `(input: Uint8Array, pubKeyPem: string \| string[], options?: EncryptMcapOptions) => Promise<Uint8Array>` | Encrypts a chunked MCAP in memory. Accepts RSA and X25519 public keys; mixed arrays are supported. |
| `decryptMcap` | `(input: Uint8Array, privKeyPem: string, onWarn?: (msg: string) => void) => Promise<Uint8Array>` | Decrypts to a fully-indexed MCAP buffer. Optional warn callback for non-fatal issues. |
| `rotateMcapKeys` | `(input: Uint8Array, oldPrivKeyPem: string, newPubKeyPems: string \| string[]) => Promise<Uint8Array>` | Re-wraps the symmetric key for new recipients without decrypting chunk data. |
| `inspectMcap` | `(input: Uint8Array) => InspectResult` | Returns metadata (file_id, chunk count, compression, recipients) without decrypting. |
| `iterateMessages` | `(input: Uint8Array, privKeyPem: string) => AsyncGenerator<{schema, channel, message}>` | Streams decrypted messages without materializing a full output buffer. |

**`EncryptMcapOptions`**

```typescript
interface EncryptMcapOptions {
  metadataMode?: "plaintext" | "encrypt" | "encrypt-all"; // default: "plaintext"
}
```

**Browser compatibility:** Uses the Web Crypto API and `fzstd` (pure-TypeScript zstd). No WASM, no Node-specific APIs. Works in Chromium 89+, Firefox 90+, Safari 15+. Does not support LZ4 source files; use the Go CLI to normalize those first.

---

## Python (`mcap_encrypt`)

```python
from mcap_encrypt import ...
```

| Export | Signature | Description |
|---|---|---|
| `generate_key_pair` | `() -> tuple[str, str]` | Generates RSA-4096 key pair. Returns `(pub_pem, priv_pem)`. |
| `generate_x25519_key_pair` | `() -> tuple[str, str]` | Generates X25519 key pair. Same shape. |
| `encrypt_mcap` | `(data: bytes, pub_key_pem: str \| list[str], *, metadata: str = "plaintext") -> bytes` | Encrypts a chunked MCAP. `metadata` controls Metadata record handling: `"plaintext"` (default), `"encrypt"`, `"encrypt-all"`. |
| `decrypt_mcap` | `(data: bytes, priv_key_pem: str) -> bytes` | Decrypts to a fully-indexed MCAP buffer. |
| `rotate_mcap_keys` | `(data: bytes, old_priv_pem: str, new_pub_pems: list[str]) -> bytes` | Re-wraps the symmetric key without touching chunk data. |
| `inspect_mcap` | `(data: bytes) -> InspectResult` | Returns metadata without decrypting. |
| `iterate_messages` | `(data: bytes, priv_key_pem: str) -> Iterator[tuple[Schema, Channel, Message]]` | Streams messages without materializing a full output buffer. |

**Dependencies:** `cryptography>=41`, `pynacl>=1.5` (XChaCha20-Poly1305 via libsodium), `zstandard>=0.19`, `lz4>=4.0`.

Server-side only. Requires libsodium (installed automatically via `pynacl`). Does not run in WASM or browser environments.

---

## Cross-language compatibility

Keys and encrypted files produced by any implementation are fully compatible with all others.

All three implementations agree on:
- XChaCha20-Poly1305 nonce size (24 bytes), key size (32 bytes)
- AEAD AAD: `file_id (16B) || chunk_index (uint64 LE) || slot_id (str) || compression (str) || uncompressed_size (uint64 LE) || uncompressed_crc (uint32 LE) || message_start_time (uint64 LE) || message_end_time (uint64 LE)`
- RSA-4096-OAEP-SHA-256 key wrapping
- X25519-HKDF-SHA256-XChaCha20Poly1305 key wrapping: HKDF salt `nil`, info `"mcap-encrypt x25519 v1"`, wire `ephem_pub(32) || nonce(24) || ciphertext(48)`
- `EncryptedChunk` wire format (opcode `0x81`)
- `EncryptedAttachment` wire format (opcode `0x82`)
- `EncryptedMetadata` wire format (opcode `0x83`)
- PKCS#8 private key PEM (`PRIVATE KEY`) and SPKI public key PEM (`PUBLIC KEY`) for both RSA and X25519

Compatibility is verified by 8 automated interop tests on every CI push. An HKDF test vector pins the X25519 key derivation to the Go reference implementation.
