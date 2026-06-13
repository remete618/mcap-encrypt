package kms

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/pem"
	"testing"
)

func TestFakeRoundTrip(t *testing.T) {
	fake, err := NewFake()
	if err != nil {
		t.Fatalf("NewFake: %v", err)
	}

	pubPEM, err := fake.PublicKey(context.Background())
	if err != nil {
		t.Fatalf("PublicKey: %v", err)
	}
	block, _ := pem.Decode(pubPEM)
	if block == nil || block.Type != "PUBLIC KEY" {
		t.Fatalf("PublicKey did not return a PEM PUBLIC KEY block")
	}

	symKey := make([]byte, 32)
	if _, err := rand.Read(symKey); err != nil {
		t.Fatalf("rand: %v", err)
	}

	// Encrypt locally using the fake's public key, then unwrap via the Fake.
	wrapped, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, &fake.Priv.PublicKey, symKey, nil)
	if err != nil {
		t.Fatalf("EncryptOAEP: %v", err)
	}

	got, err := fake.Decrypt(context.Background(), KEKAlgRSAOAEPSHA256, wrapped)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if string(got) != string(symKey) {
		t.Fatalf("Decrypt returned wrong plaintext")
	}
}

func TestFakeRejectsUnknownKEKAlg(t *testing.T) {
	fake, err := NewFake()
	if err != nil {
		t.Fatalf("NewFake: %v", err)
	}
	_, err = fake.Decrypt(context.Background(), "x25519-hkdf-xchacha20poly1305", []byte("ignored"))
	if err == nil {
		t.Fatalf("expected error for unsupported kekAlg")
	}
}

func TestFakeRejectsCancelledContext(t *testing.T) {
	fake, err := NewFake()
	if err != nil {
		t.Fatalf("NewFake: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := fake.Decrypt(ctx, KEKAlgRSAOAEPSHA256, []byte("x")); err == nil {
		t.Fatal("expected context error from Decrypt")
	}
	if _, err := fake.PublicKey(ctx); err == nil {
		t.Fatal("expected context error from PublicKey")
	}
}
