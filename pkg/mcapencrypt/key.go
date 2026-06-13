package mcapencrypt

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/ssh"
)

const (
	AttachmentName      = "mcap_encryption_key"
	AttachmentMediaType = "application/x-mcap-wrapped-key"
	// wrappedKeyVersion is the current version written by this library.
	// Version 2 is legacy (no manifest requirement on decrypt).
	// Version 3 requires a manifest during decryption; without it, decryption fails.
	wrappedKeyVersion   = byte(3)
	wrappedKeyVersionV2 = byte(2) // legacy: manifest optional
	fileIDSize          = 16

	ManifestAttachmentName      = "mcap_encryption_manifest"
	ManifestAttachmentMediaType = "application/x-mcap-manifest"
	// manifestPayloadSize is chunk_count (uint64 LE) + HMAC-SHA256 (32 bytes).
	manifestPayloadSize = 8 + 32
	// manifestDataOffsetInPayload is the byte offset of the data field within a
	// manifest attachment inner payload (as produced by buildAttachmentBytes).
	// logTime(8)+createTime(8)+nameLen(4)+name(24)+mediaTypeLen(4)+mediaType(27)+dataSize(8) = 83
	manifestDataOffsetInPayload = 8 + 8 + 4 + len(ManifestAttachmentName) + 4 + len(ManifestAttachmentMediaType) + 8

	x25519HKDFInfo = "mcap-encrypt x25519 v1"
)

// WrappedKeyData is the binary payload stored inside the WrappedKey Attachment.
type WrappedKeyData struct {
	Version    byte   // 2 = legacy (manifest optional); 3 = manifest required
	FileID     []byte // 16 random bytes, same for every recipient of a given file
	KeyID      string
	Algorithm  string // "xchacha20poly1305"
	KEKAlg     string // "rsa-oaep-sha256" | "x25519-hkdf-xchacha20poly1305"
	WrappedKey []byte
}

func (k *WrappedKeyData) Encode() []byte {
	keyID := []byte(k.KeyID)
	alg := []byte(k.Algorithm)
	kekAlg := []byte(k.KEKAlg)

	n := 1 +
		fileIDSize +
		4 + len(keyID) +
		4 + len(alg) +
		4 + len(kekAlg) +
		4 + len(k.WrappedKey)

	buf := make([]byte, n)
	o := 0

	buf[o] = wrappedKeyVersion
	o++
	copy(buf[o:], k.FileID)
	o += fileIDSize
	putBytes := func(b []byte) {
		binary.LittleEndian.PutUint32(buf[o:], uint32(len(b)))
		o += 4
		copy(buf[o:], b)
		o += len(b)
	}
	putBytes(keyID)
	putBytes(alg)
	putBytes(kekAlg)
	putBytes(k.WrappedKey)
	return buf
}

func DecodeWrappedKeyData(data []byte) (*WrappedKeyData, error) {
	if len(data) < 1 {
		return nil, fmt.Errorf("empty wrapped key data")
	}
	ver := data[0]
	if ver != wrappedKeyVersion && ver != wrappedKeyVersionV2 {
		return nil, fmt.Errorf("unsupported wrapped key version %d (want %d or %d)", ver, wrappedKeyVersionV2, wrappedKeyVersion)
	}
	if len(data) < 1+fileIDSize {
		return nil, fmt.Errorf("truncated: too short for file_id")
	}
	k := &WrappedKeyData{Version: ver}
	k.FileID = make([]byte, fileIDSize)
	copy(k.FileID, data[1:1+fileIDSize])
	o := 1 + fileIDSize

	getBytes := func() ([]byte, error) {
		if o+4 > len(data) {
			return nil, fmt.Errorf("truncated")
		}
		n := int(binary.LittleEndian.Uint32(data[o:]))
		o += 4
		if o+n > len(data) {
			return nil, fmt.Errorf("truncated")
		}
		v := make([]byte, n)
		copy(v, data[o:o+n])
		o += n
		return v, nil
	}
	getString := func() (string, error) { b, err := getBytes(); return string(b), err }

	var err error
	if k.KeyID, err = getString(); err != nil {
		return nil, fmt.Errorf("read key_id: %w", err)
	}
	if k.Algorithm, err = getString(); err != nil {
		return nil, fmt.Errorf("read algorithm: %w", err)
	}
	if k.KEKAlg, err = getString(); err != nil {
		return nil, fmt.Errorf("read kek_algorithm: %w", err)
	}
	if k.WrappedKey, err = getBytes(); err != nil {
		return nil, fmt.Errorf("read wrapped_key: %w", err)
	}

	if k.Algorithm != "xchacha20poly1305" {
		return nil, fmt.Errorf("unsupported encryption algorithm %q (want xchacha20poly1305)", k.Algorithm)
	}
	switch k.KEKAlg {
	case "rsa-oaep-sha256", "x25519-hkdf-xchacha20poly1305":
	default:
		return nil, fmt.Errorf("unsupported key-wrapping algorithm %q", k.KEKAlg)
	}
	return k, nil
}

// GenerateKeyPair writes a 4096-bit RSA key pair:
// basename.priv.pem (0600) and basename.pub.pem (0644).
func GenerateKeyPair(basename string) error {
	privPath := basename + ".priv.pem"
	pubPath := basename + ".pub.pem"
	if _, err := os.Stat(privPath); err == nil {
		return fmt.Errorf("key file already exists: %q (delete it first or choose a different basename)", privPath)
	}
	if _, err := os.Stat(pubPath); err == nil {
		return fmt.Errorf("key file already exists: %q (delete it first or choose a different basename)", pubPath)
	}
	priv, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return fmt.Errorf("generate RSA key: %w", err)
	}
	privDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return fmt.Errorf("marshal private key: %w", err)
	}
	defer clear(privDER)
	privPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER})
	defer clear(privPEM)
	if err := os.WriteFile(privPath, privPEM, 0600); err != nil {
		return fmt.Errorf("write private key: %w", err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		return fmt.Errorf("marshal public key: %w", err)
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})
	if err := os.WriteFile(pubPath, pubPEM, 0644); err != nil {
		return fmt.Errorf("write public key: %w", err)
	}
	return nil
}

// GenerateX25519KeyPair writes an X25519 key pair:
// basename.priv.pem (0600) and basename.pub.pem (0644).
func GenerateX25519KeyPair(basename string) error {
	privPath := basename + ".priv.pem"
	pubPath := basename + ".pub.pem"
	if _, err := os.Stat(privPath); err == nil {
		return fmt.Errorf("key file already exists: %q (delete it first or choose a different basename)", privPath)
	}
	if _, err := os.Stat(pubPath); err == nil {
		return fmt.Errorf("key file already exists: %q (delete it first or choose a different basename)", pubPath)
	}
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("generate X25519 key: %w", err)
	}
	privDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return fmt.Errorf("marshal private key: %w", err)
	}
	defer clear(privDER)
	privPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER})
	defer clear(privPEM)
	if err := os.WriteFile(privPath, privPEM, 0600); err != nil {
		return fmt.Errorf("write private key: %w", err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(priv.PublicKey())
	if err != nil {
		return fmt.Errorf("marshal public key: %w", err)
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})
	if err := os.WriteFile(pubPath, pubPEM, 0644); err != nil {
		return fmt.Errorf("write public key: %w", err)
	}
	return nil
}

// SPKIFingerprint returns the hex-encoded SHA-256 of the SPKI encoding of pub.
// pub must be *rsa.PublicKey or *ecdh.PublicKey.
func SPKIFingerprint(pub any) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", fmt.Errorf("marshal SPKI: %w", err)
	}
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:]), nil
}

// LoadPublicKey loads an RSA public key from a PEM file.
// Kept for backwards compatibility; new code should use LoadPublicKeyAny.
func LoadPublicKey(path string) (*rsa.PublicKey, error) {
	pub, err := LoadPublicKeyAny(path)
	if err != nil {
		return nil, err
	}
	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("%s does not contain an RSA public key", path)
	}
	return rsaPub, nil
}

// LoadPublicKeyAny loads an RSA or X25519 public key from a PEM file, or an
// OpenSSH public key (single line starting with "ssh-rsa" or "ssh-ed25519").
// Ed25519 SSH keys are converted to X25519 internally per RFC 7748 section 5
// so they can be used with the X25519-HKDF-XChaCha20Poly1305 wrap path.
func LoadPublicKeyAny(path string) (any, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if isSSHPublicKey(data) {
		return parseSSHPublicKey(data, path)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block in %s", path)
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	switch pub.(type) {
	case *rsa.PublicKey, *ecdh.PublicKey:
		return pub, nil
	default:
		return nil, fmt.Errorf("%s contains unsupported key type %T", path, pub)
	}
}

// ParsePublicKeyPEM parses an RSA or X25519 public key from a PEM-encoded string.
// Use this when the key is already in memory; use LoadPublicKeyAny when it is on disk.
func ParsePublicKeyPEM(pemStr string) (any, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, fmt.Errorf("no PEM block found in provided key string")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	switch pub.(type) {
	case *rsa.PublicKey, *ecdh.PublicKey:
		return pub, nil
	default:
		return nil, fmt.Errorf("unsupported public key type %T", pub)
	}
}

// LoadPrivateKey loads an RSA private key from a PEM file.
// Kept for backwards compatibility; new code should use LoadPrivateKeyAny.
func LoadPrivateKey(path string) (*rsa.PrivateKey, error) {
	priv, err := LoadPrivateKeyAny(path)
	if err != nil {
		return nil, err
	}
	rsaPriv, ok := priv.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("%s does not contain an RSA private key", path)
	}
	return rsaPriv, nil
}

// LoadPrivateKeyAny loads an RSA or X25519 private key from a PEM file, or
// an OpenSSH private key block ("-----BEGIN OPENSSH PRIVATE KEY-----").
// Ed25519 SSH keys are converted to X25519 internally per RFC 7748 section 5.
// Passphrase-protected SSH keys are rejected with a clear error; decrypt the
// key first with ssh-keygen -p -f <keyfile>.
// The raw PEM and DER bytes are zeroed immediately after parsing.
func LoadPrivateKeyAny(path string) (any, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	defer clear(data) // zero PEM text (contains base64 of the key material)
	if isSSHPrivateKey(data) {
		return parseSSHPrivateKey(data, path)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block in %s", path)
	}
	defer clear(block.Bytes) // zero DER bytes (raw key material)
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	switch key.(type) {
	case *rsa.PrivateKey, *ecdh.PrivateKey:
		return key, nil
	default:
		return nil, fmt.Errorf("%s contains unsupported key type %T", path, key)
	}
}

// parsePrivateKeyPEM parses an RSA or X25519 private key from a PEM string.
// The DER bytes are zeroed immediately after parsing.
func parsePrivateKeyPEM(pemStr string) (any, error) {
	data := []byte(pemStr)
	defer clear(data)
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found in provided key string")
	}
	defer clear(block.Bytes)
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	switch key.(type) {
	case *rsa.PrivateKey, *ecdh.PrivateKey:
		return key, nil
	default:
		return nil, fmt.Errorf("unsupported private key type %T", key)
	}
}

// isSSHPublicKey reports whether data looks like an OpenSSH authorized-keys
// line, e.g. "ssh-ed25519 AAAA... user@host" or "ssh-rsa AAAA... user@host".
// Detection trims leading whitespace and checks for the well-known prefixes.
func isSSHPublicKey(data []byte) bool {
	t := bytes.TrimLeft(data, " \t\r\n")
	return bytes.HasPrefix(t, []byte("ssh-rsa ")) ||
		bytes.HasPrefix(t, []byte("ssh-ed25519 ")) ||
		bytes.HasPrefix(t, []byte("ecdsa-sha2-")) ||
		bytes.HasPrefix(t, []byte("sk-ssh-ed25519@")) ||
		bytes.HasPrefix(t, []byte("sk-ecdsa-sha2-"))
}

// isSSHPrivateKey reports whether data looks like an OpenSSH private key
// block. OpenSSH always uses the literal armor header below regardless of
// the inner algorithm.
func isSSHPrivateKey(data []byte) bool {
	return bytes.Contains(data, []byte("-----BEGIN OPENSSH PRIVATE KEY-----"))
}

// parseSSHPublicKey parses an authorized-keys-format public key and returns
// an *rsa.PublicKey or *ecdh.PublicKey suitable for mcap-encrypt's wrap
// functions. Ed25519 keys are converted to X25519 per RFC 7748 section 5.
//
// RSA SSH keys are accepted as-is; the minimum-bits check is enforced later
// in WrapSymmetricKey, but we surface a clearer error here for the common
// case of a default 3072-bit ssh-keygen RSA key.
func parseSSHPublicKey(data []byte, path string) (any, error) {
	pubKey, _, _, _, err := ssh.ParseAuthorizedKey(data)
	if err != nil {
		return nil, fmt.Errorf("parse SSH public key %s: %w", path, err)
	}
	cryptoPub, ok := pubKey.(ssh.CryptoPublicKey)
	if !ok {
		return nil, fmt.Errorf("%s: SSH key type %q does not expose a crypto.PublicKey", path, pubKey.Type())
	}
	raw := cryptoPub.CryptoPublicKey()
	switch k := raw.(type) {
	case *rsa.PublicKey:
		if k.N.BitLen() < minRSAKeyBits {
			return nil, fmt.Errorf("SSH RSA public key in %s is %d bits; minimum is %d bits (regenerate with: ssh-keygen -t rsa -b 4096)", path, k.N.BitLen(), minRSAKeyBits)
		}
		return k, nil
	case ed25519.PublicKey:
		xPub, err := ed25519SSHKeyToX25519PublicKey(k)
		if err != nil {
			return nil, fmt.Errorf("convert Ed25519 SSH key to X25519: %w", err)
		}
		return xPub, nil
	default:
		return nil, fmt.Errorf("%s: unsupported SSH key algorithm %q (supported: ssh-rsa, ssh-ed25519)", path, pubKey.Type())
	}
}

// parseSSHPrivateKey parses an OpenSSH private key block and returns an
// *rsa.PrivateKey or *ecdh.PrivateKey. Ed25519 keys are converted to X25519
// per RFC 7748 section 5. Encrypted (passphrase-protected) keys are rejected
// with a clear error pointing at ssh-keygen -p.
func parseSSHPrivateKey(data []byte, path string) (any, error) {
	raw, err := ssh.ParseRawPrivateKey(data)
	if err != nil {
		var pmErr *ssh.PassphraseMissingError
		if errors.As(err, &pmErr) {
			return nil, fmt.Errorf("SSH private key %s is passphrase-protected; decrypt it first with: ssh-keygen -p -f %s", path, path)
		}
		return nil, fmt.Errorf("parse SSH private key %s: %w", path, err)
	}
	switch k := raw.(type) {
	case *rsa.PrivateKey:
		if k.N.BitLen() < minRSAKeyBits {
			return nil, fmt.Errorf("SSH RSA private key in %s is %d bits; minimum is %d bits (regenerate with: ssh-keygen -t rsa -b 4096)", path, k.N.BitLen(), minRSAKeyBits)
		}
		return k, nil
	case *ed25519.PrivateKey:
		xPriv, err := ed25519SSHKeyToX25519PrivateKey(*k)
		if err != nil {
			return nil, fmt.Errorf("convert Ed25519 SSH key to X25519: %w", err)
		}
		return xPriv, nil
	case ed25519.PrivateKey:
		xPriv, err := ed25519SSHKeyToX25519PrivateKey(k)
		if err != nil {
			return nil, fmt.Errorf("convert Ed25519 SSH key to X25519: %w", err)
		}
		return xPriv, nil
	default:
		return nil, fmt.Errorf("%s: unsupported SSH private key type %T (supported: RSA, Ed25519)", path, raw)
	}
}

// minRSAKeyBits is the minimum RSA modulus size accepted for key wrapping.
// Format v3+ assumes RSA-4096 throughout. Accepting smaller keys would
// silently weaken the file below documented strength.
const minRSAKeyBits = 4096

// WrapSymmetricKey wraps symKey using RSA-OAEP-SHA256. Public keys smaller
// than minRSAKeyBits are rejected.
func WrapSymmetricKey(symKey []byte, pub *rsa.PublicKey) ([]byte, error) {
	if pub.N.BitLen() < minRSAKeyBits {
		return nil, fmt.Errorf("RSA public key is %d bits; minimum is %d bits", pub.N.BitLen(), minRSAKeyBits)
	}
	return rsa.EncryptOAEP(sha256.New(), rand.Reader, pub, symKey, nil)
}

// UnwrapSymmetricKey unwraps a symmetric key using RSA-OAEP-SHA256.
func UnwrapSymmetricKey(wrapped []byte, priv *rsa.PrivateKey) ([]byte, error) {
	return rsa.DecryptOAEP(sha256.New(), rand.Reader, priv, wrapped, nil)
}

// WrapSymmetricKeyX25519 wraps symKey using X25519-HKDF-XChaCha20Poly1305.
// Output format: ephemeral_pub(32) || nonce(24) || ciphertext(32+16=48) = 104 bytes.
//
// This construction is equivalent to HPKE (RFC 9180) with ciphersuite
// DHKEM(X25519, HKDF-SHA256) / HKDF-SHA256 / ChaCha20Poly1305 (0x0020).
// A custom HKDF info label ("mcap-encrypt x25519 v1") is used instead of
// the HPKE suite_id encoding because golang.org/x/crypto does not yet expose
// a stable HPKE API; the underlying DH math and AEAD are identical.
func WrapSymmetricKeyX25519(symKey []byte, recipientPub *ecdh.PublicKey) ([]byte, error) {
	if recipientPub.Curve() != ecdh.X25519() {
		return nil, fmt.Errorf("recipient key must use X25519 curve")
	}
	ephemPriv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate ephemeral key: %w", err)
	}
	shared, err := ephemPriv.ECDH(recipientPub)
	if err != nil {
		return nil, fmt.Errorf("X25519 ECDH: %w", err)
	}
	defer clear(shared)
	kek, err := deriveX25519KEK(shared)
	if err != nil {
		return nil, err
	}
	defer clear(kek)

	aead, err := chacha20poly1305.NewX(kek)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, chacha20poly1305.NonceSizeX)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	ciphertext := aead.Seal(nil, nonce, symKey, nil)

	result := make([]byte, 32+chacha20poly1305.NonceSizeX+len(ciphertext))
	copy(result[0:32], ephemPriv.PublicKey().Bytes())
	copy(result[32:32+chacha20poly1305.NonceSizeX], nonce)
	copy(result[32+chacha20poly1305.NonceSizeX:], ciphertext)
	return result, nil
}

// UnwrapSymmetricKeyX25519 unwraps a symmetric key wrapped with WrapSymmetricKeyX25519.
func UnwrapSymmetricKeyX25519(wrapped []byte, priv *ecdh.PrivateKey) ([]byte, error) {
	const minLen = 32 + chacha20poly1305.NonceSizeX + 32 + 16
	if len(wrapped) < minLen {
		return nil, fmt.Errorf("wrapped key too short for X25519 (%d bytes, need %d)", len(wrapped), minLen)
	}
	ephemPubBytes := wrapped[0:32]
	nonce := wrapped[32 : 32+chacha20poly1305.NonceSizeX]
	ciphertext := wrapped[32+chacha20poly1305.NonceSizeX:]

	ephemPub, err := ecdh.X25519().NewPublicKey(ephemPubBytes)
	if err != nil {
		return nil, fmt.Errorf("parse ephemeral public key: %w", err)
	}
	shared, err := priv.ECDH(ephemPub)
	if err != nil {
		return nil, fmt.Errorf("X25519 ECDH: %w", err)
	}
	defer clear(shared)
	kek, err := deriveX25519KEK(shared)
	if err != nil {
		return nil, err
	}
	defer clear(kek)

	aead, err := chacha20poly1305.NewX(kek)
	if err != nil {
		return nil, err
	}
	return aead.Open(nil, nonce, ciphertext, nil)
}

// deriveX25519KEK derives a 32-byte key encryption key from an X25519 shared secret
// using HKDF-SHA256.
func deriveX25519KEK(shared []byte) ([]byte, error) {
	kdf := hkdf.New(sha256.New, shared, nil, []byte(x25519HKDFInfo))
	kek := make([]byte, 32)
	if _, err := io.ReadFull(kdf, kek); err != nil {
		return nil, fmt.Errorf("HKDF-SHA256: %w", err)
	}
	return kek, nil
}

// ComputeManifestHMAC computes HMAC-SHA256(symKey, chunkCount_le8 || fileID).
// This binds the chunk count to the file identity, enabling truncation detection.
func ComputeManifestHMAC(symKey []byte, chunkCount uint64, fileID []byte) []byte {
	h := hmac.New(sha256.New, symKey)
	var countBuf [8]byte
	binary.LittleEndian.PutUint64(countBuf[:], chunkCount)
	h.Write(countBuf[:])
	h.Write(fileID)
	return h.Sum(nil)
}
