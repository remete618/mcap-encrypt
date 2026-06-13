// Package kms defines the Decrypter interface used by mcapencrypt to unwrap
// the per-file symmetric key via a remote key management service.
//
// Background
//
// Enterprises typically refuse to keep RSA-4096 private keys on disk. Instead
// they store the private half in an HSM-backed service (AWS KMS, GCP KMS,
// Azure Key Vault, Vault, PKCS#11) and only ever expose a "decrypt this
// blob" operation. The wire format produced by WrapSymmetricKey is exactly
// what those services expect for RSA-OAEP-SHA-256 unwrap, so mcapencrypt's
// decrypt path can be re-pointed at a KMS without changing on-disk bytes.
//
// This package only contains the abstraction (Decrypter) plus an in-memory
// Fake for unit tests. Concrete backends live in subfiles (aws.go,
// gcp.go, etc.) and are guarded by build tags only when their SDK is heavy
// enough to warrant it.
package kms

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

// KEKAlgRSAOAEPSHA256 is the only KEK algorithm currently supported by any
// production KMS backend. X25519 is not supported because no major KMS
// exposes raw X25519 decrypt.
const KEKAlgRSAOAEPSHA256 = "rsa-oaep-sha256"

// Decrypter unwraps a symmetric key by calling out to a remote KMS service.
//
// Implementations must be safe for concurrent use by multiple goroutines.
// The wrapped-key bytes are exactly what WrapSymmetricKey produced; the
// remote service holds the private half and performs the RSA-OAEP-SHA-256
// decrypt server-side. The plaintext symmetric key crosses the boundary
// only on the response path.
type Decrypter interface {
	// Decrypt unwraps a single wrapped-key payload. kekAlg comes from the
	// wrapped-key attachment and is normally "rsa-oaep-sha256". Implementations
	// must reject any other algorithm to prevent an attacker from downgrading
	// a recipient to a non-existent algorithm by tampering with the attachment.
	Decrypt(ctx context.Context, kekAlg string, wrappedKey []byte) ([]byte, error)

	// PublicKey returns the public half of the KMS-held key, PEM-encoded in
	// PKIX SubjectPublicKeyInfo form. The caller passes this to
	// mcapencrypt.Encrypt (or the CLI --key flag) when wrapping new files for
	// this recipient.
	PublicKey(ctx context.Context) (pemBytes []byte, err error)
}

// Fake is an in-memory Decrypter backed by a local *rsa.PrivateKey. It exists
// for unit tests that need to exercise the KMS code path without standing up
// a real backend.
//
// Fake is deliberately NOT safe to expose as a production option: it defeats
// the entire point of using a KMS (keep the private key off the host).
type Fake struct {
	// Priv is the private key. The public half is derived on demand.
	// Must be at least 2048 bits; tests should use 4096 to match the
	// constraint enforced by mcapencrypt at encrypt time.
	Priv *rsa.PrivateKey
}

// NewFake constructs a Fake with a freshly generated RSA-4096 key pair.
// Use NewFakeWithKey to inject a deterministic key in tests.
func NewFake() (*Fake, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, fmt.Errorf("kms: generate fake RSA key: %w", err)
	}
	return &Fake{Priv: priv}, nil
}

// NewFakeWithKey wraps an existing private key.
func NewFakeWithKey(priv *rsa.PrivateKey) *Fake {
	return &Fake{Priv: priv}
}

// Decrypt implements Decrypter.
func (f *Fake) Decrypt(ctx context.Context, kekAlg string, wrappedKey []byte) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if kekAlg != KEKAlgRSAOAEPSHA256 {
		return nil, fmt.Errorf("kms: fake only supports %q, got %q", KEKAlgRSAOAEPSHA256, kekAlg)
	}
	if f.Priv == nil {
		return nil, fmt.Errorf("kms: fake has no private key")
	}
	plain, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, f.Priv, wrappedKey, nil)
	if err != nil {
		return nil, fmt.Errorf("kms: fake decrypt: %w", err)
	}
	return plain, nil
}

// PublicKey implements Decrypter, returning the public half as a PEM-encoded
// SubjectPublicKeyInfo block.
func (f *Fake) PublicKey(ctx context.Context) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if f.Priv == nil {
		return nil, fmt.Errorf("kms: fake has no private key")
	}
	der, err := x509.MarshalPKIXPublicKey(&f.Priv.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("kms: marshal fake public key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), nil
}

// SPKIToPEM wraps an SPKI DER blob in a PEM "PUBLIC KEY" block. Backend
// implementations (AWS, GCP, ...) typically receive raw SPKI DER from their
// SDK; this helper centralises the PEM framing so the output is consistent
// with what mcapencrypt's encrypt path expects.
func SPKIToPEM(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
}
