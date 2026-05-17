package mcapencrypt

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// TestX25519KDFTestVector anchors the HKDF parameters used in deriveX25519KEK.
// The expected value was computed once with:
//
//	hkdf.New(sha256.New, shared, nil, []byte("mcap-encrypt x25519 v1"))
//
// If the info string, hash function, or salt in deriveX25519KEK ever changes,
// this test will fail, flagging a wire-incompatible key derivation change.
func TestX25519KDFTestVector(t *testing.T) {
	shared := make([]byte, 32)
	for i := range shared {
		shared[i] = byte(i + 1)
	}

	expected := []byte{
		0xce, 0x10, 0x14, 0x08, 0x49, 0x24, 0x09, 0x58,
		0x06, 0x93, 0x0f, 0x17, 0xa6, 0xf6, 0xab, 0x8a,
		0x0d, 0x85, 0x00, 0x44, 0xbc, 0xc0, 0x90, 0x38,
		0xf6, 0x40, 0x74, 0x55, 0xae, 0x9b, 0xa9, 0x00,
	}

	kek, err := deriveX25519KEK(shared)
	require.NoError(t, err)
	require.Equal(t, expected, kek,
		"KDF output does not match test vector; info string, hash, or salt may have changed")
}
