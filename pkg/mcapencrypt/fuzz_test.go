package mcapencrypt

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"io"
	"testing"
)

// FuzzDecodeEncryptedChunk verifies the EncryptedChunk parser does not panic on arbitrary input.
func FuzzDecodeEncryptedChunk(f *testing.F) {
	valid := &EncryptedChunk{
		MessageStartTime: 1_000,
		MessageEndTime:   2_000,
		UncompressedSize: 100,
		UncompressedCRC:  0,
		Compression:      "zstd",
		KeyID:            "key-1",
		Nonce:            make([]byte, 24),
		EncryptedData:    make([]byte, 64),
	}
	f.Add(valid.Encode())
	f.Add([]byte{})
	f.Add([]byte{0, 0, 0, 0})

	f.Fuzz(func(t *testing.T, data []byte) {
		ec, err := DecodeEncryptedChunk(data)
		if err == nil {
			_ = ec.Encode()
		}
	})
}

// FuzzDecodeWrappedKeyData verifies the WrappedKeyData parser does not panic on arbitrary input.
func FuzzDecodeWrappedKeyData(f *testing.F) {
	valid := &WrappedKeyData{
		FileID:     make([]byte, fileIDSize),
		KeyID:      "aabbccdd",
		Algorithm:  "xchacha20poly1305",
		KEKAlg:     "rsa-oaep-sha256",
		WrappedKey: make([]byte, 256),
	}
	f.Add(valid.Encode())
	f.Add([]byte{})
	f.Add([]byte{2}) // valid version byte, truncated after

	f.Fuzz(func(t *testing.T, data []byte) {
		wkd, err := DecodeWrappedKeyData(data)
		if err == nil {
			_ = wkd.Encode()
		}
	})
}

// FuzzStreamDecrypt verifies the full decrypt pipeline does not panic on arbitrary byte input.
func FuzzStreamDecrypt(f *testing.F) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		f.Fatalf("generate RSA key: %v", err)
	}

	// Seed: bare MCAP magic only — produces "no wrapped key" error, not a panic.
	f.Add([]byte{0x89, 0x4D, 0x43, 0x41, 0x50, 0x30, 0x0D, 0x0A})
	f.Add([]byte{})
	f.Add([]byte("not mcap at all"))

	f.Fuzz(func(t *testing.T, data []byte) {
		_ = streamDecrypt(bytes.NewReader(data), io.Discard, priv)
	})
}
