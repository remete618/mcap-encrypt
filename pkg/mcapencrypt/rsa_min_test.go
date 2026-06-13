package mcapencrypt

import (
	"crypto/rand"
	"crypto/rsa"
	"strings"
	"testing"
)

func TestWrapSymmetricKeyRejectsUndersizedRSA(t *testing.T) {
	cases := []struct {
		name string
		bits int
		ok   bool
	}{
		{"rsa_1024_rejected", 1024, false},
		{"rsa_2048_rejected", 2048, false},
		{"rsa_3072_rejected", 3072, false},
		{"rsa_4096_accepted", 4096, true},
	}
	symKey := make([]byte, 32)
	_, _ = rand.Read(symKey)

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			priv, err := rsa.GenerateKey(rand.Reader, tc.bits)
			if err != nil {
				t.Fatalf("generate %d-bit key: %v", tc.bits, err)
			}
			_, wrapErr := WrapSymmetricKey(symKey, &priv.PublicKey)
			if tc.ok && wrapErr != nil {
				t.Fatalf("wrap with %d-bit key failed: %v", tc.bits, wrapErr)
			}
			if !tc.ok {
				if wrapErr == nil {
					t.Fatalf("wrap with %d-bit key was accepted; expected rejection", tc.bits)
				}
				msg := wrapErr.Error()
				if !strings.Contains(msg, "minimum") || !strings.Contains(msg, "4096") {
					t.Errorf("error should mention minimum 4096; got %q", msg)
				}
			}
		})
	}
}
