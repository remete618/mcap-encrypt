package mcapencrypt_test

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/remete618/mcap-encrypt/pkg/mcapencrypt"
)

// TestDecryptPlainMcapReturnsClearError verifies the user gets a friendly
// message when they accidentally try to decrypt an unencrypted MCAP file.
func TestDecryptPlainMcapReturnsClearError(t *testing.T) {
	dir := t.TempDir()
	plainPath := filepath.Join(dir, "plain.mcap")
	outPath := filepath.Join(dir, "out.mcap")
	keyBase := filepath.Join(dir, "key")

	buildTestMCAP(t, plainPath)
	if err := mcapencrypt.GenerateKeyPair(keyBase); err != nil {
		t.Fatalf("generate key pair: %v", err)
	}
	privPath := keyBase + ".priv.pem"

	err := mcapencrypt.Decrypt(plainPath, outPath, privPath)
	if err == nil {
		t.Fatal("expected error decrypting a plain MCAP, got nil")
	}
	msg := err.Error()
	// The error must clearly indicate the input is not encrypted. Both the
	// current and improved wording are acceptable; the test pins the contract.
	if !strings.Contains(msg, "encrypted MCAP") && !strings.Contains(msg, "not encrypted") {
		t.Errorf("error should mention encryption status of input; got %q", msg)
	}
}
