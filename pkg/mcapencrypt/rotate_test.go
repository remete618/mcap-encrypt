package mcapencrypt_test

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/remete618/mcap-encrypt/pkg/mcapencrypt"
)

// loadPEM reads a PEM file and returns its contents as a string.
func loadPEM(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	return string(data)
}

// TestRotateKeysRoundTrip encrypts with key A, rotates to key B, decrypts with key B.
// Messages must match the original plaintext.
func TestRotateKeysRoundTrip(t *testing.T) {
	dir := t.TempDir()
	plainPath := filepath.Join(dir, "plain.mcap")
	encPath := filepath.Join(dir, "encrypted.mcap")
	rotatedPath := filepath.Join(dir, "rotated.mcap")
	decPath := filepath.Join(dir, "decrypted.mcap")

	buildTestMCAP(t, plainPath)

	keyA := filepath.Join(dir, "keyA")
	keyB := filepath.Join(dir, "keyB")
	require.NoError(t, mcapencrypt.GenerateX25519KeyPair(keyA))
	require.NoError(t, mcapencrypt.GenerateX25519KeyPair(keyB))

	// Encrypt with key A.
	require.NoError(t, mcapencrypt.Encrypt(plainPath, encPath, keyA+".pub.pem"))

	// Rotate to key B.
	oldPrivPEM := loadPEM(t, keyA+".priv.pem")
	newPubPEM := loadPEM(t, keyB+".pub.pem")

	inFile, err := os.Open(encPath)
	require.NoError(t, err)
	defer inFile.Close()
	var outBuf bytes.Buffer
	require.NoError(t, mcapencrypt.RotateKeys(inFile, &outBuf, oldPrivPEM, []string{newPubPEM}))
	require.NoError(t, os.WriteFile(rotatedPath, outBuf.Bytes(), 0644))

	// Decrypt with key B.
	require.NoError(t, mcapencrypt.Decrypt(rotatedPath, decPath, keyB+".priv.pem"))

	// Messages must match original.
	origMsgs := readAllMessages(t, plainPath)
	decMsgs := readAllMessages(t, decPath)
	require.Equal(t, len(origMsgs), len(decMsgs), "message count must match")
	for i, om := range origMsgs {
		dm := decMsgs[i]
		require.Equal(t, om.ChannelID, dm.ChannelID)
		require.Equal(t, om.Sequence, dm.Sequence)
		require.Equal(t, om.LogTime, dm.LogTime)
		require.Equal(t, om.Data, dm.Data)
	}
}

// TestRotateKeysOldKeyCannotDecrypt verifies that after rotation to key B,
// key A can no longer decrypt the rotated file.
func TestRotateKeysOldKeyCannotDecrypt(t *testing.T) {
	dir := t.TempDir()
	plainPath := filepath.Join(dir, "plain.mcap")
	encPath := filepath.Join(dir, "encrypted.mcap")
	rotatedPath := filepath.Join(dir, "rotated.mcap")
	decPath := filepath.Join(dir, "decrypted.mcap")

	buildTestMCAP(t, plainPath)

	keyA := filepath.Join(dir, "keyA")
	keyB := filepath.Join(dir, "keyB")
	require.NoError(t, mcapencrypt.GenerateX25519KeyPair(keyA))
	require.NoError(t, mcapencrypt.GenerateX25519KeyPair(keyB))

	require.NoError(t, mcapencrypt.Encrypt(plainPath, encPath, keyA+".pub.pem"))

	oldPrivPEM := loadPEM(t, keyA+".priv.pem")
	newPubPEM := loadPEM(t, keyB+".pub.pem")

	inFile, err := os.Open(encPath)
	require.NoError(t, err)
	defer inFile.Close()
	var outBuf bytes.Buffer
	require.NoError(t, mcapencrypt.RotateKeys(inFile, &outBuf, oldPrivPEM, []string{newPubPEM}))
	require.NoError(t, os.WriteFile(rotatedPath, outBuf.Bytes(), 0644))

	// Key A must not decrypt the rotated file.
	err = mcapencrypt.Decrypt(rotatedPath, decPath, keyA+".priv.pem")
	require.Error(t, err, "old key A must not decrypt after rotation")
}

// TestRotateKeysMultiRecipient rotates to [key B, key C]; both must decrypt
// and yield identical messages.
func TestRotateKeysMultiRecipient(t *testing.T) {
	dir := t.TempDir()
	plainPath := filepath.Join(dir, "plain.mcap")
	encPath := filepath.Join(dir, "encrypted.mcap")
	rotatedPath := filepath.Join(dir, "rotated.mcap")
	decBPath := filepath.Join(dir, "decB.mcap")
	decCPath := filepath.Join(dir, "decC.mcap")

	buildTestMCAP(t, plainPath)

	keyA := filepath.Join(dir, "keyA")
	keyB := filepath.Join(dir, "keyB")
	keyC := filepath.Join(dir, "keyC")
	require.NoError(t, mcapencrypt.GenerateKeyPair(keyA))
	require.NoError(t, mcapencrypt.GenerateX25519KeyPair(keyB))
	require.NoError(t, mcapencrypt.GenerateX25519KeyPair(keyC))

	require.NoError(t, mcapencrypt.Encrypt(plainPath, encPath, keyA+".pub.pem"))

	oldPrivPEM := loadPEM(t, keyA+".priv.pem")
	pubBPEM := loadPEM(t, keyB+".pub.pem")
	pubCPEM := loadPEM(t, keyC+".pub.pem")

	inFile, err := os.Open(encPath)
	require.NoError(t, err)
	defer inFile.Close()
	var outBuf bytes.Buffer
	require.NoError(t, mcapencrypt.RotateKeys(inFile, &outBuf, oldPrivPEM, []string{pubBPEM, pubCPEM}))
	require.NoError(t, os.WriteFile(rotatedPath, outBuf.Bytes(), 0644))

	require.NoError(t, mcapencrypt.Decrypt(rotatedPath, decBPath, keyB+".priv.pem"))
	require.NoError(t, mcapencrypt.Decrypt(rotatedPath, decCPath, keyC+".priv.pem"))

	origMsgs := readAllMessages(t, plainPath)
	msgsB := readAllMessages(t, decBPath)
	msgsC := readAllMessages(t, decCPath)

	require.Equal(t, len(origMsgs), len(msgsB))
	require.Equal(t, len(origMsgs), len(msgsC))
	for i := range origMsgs {
		require.Equal(t, origMsgs[i].Data, msgsB[i].Data)
		require.Equal(t, origMsgs[i].Data, msgsC[i].Data)
	}
}

// TestRotateKeysNotEncrypted verifies that passing a plain (non-encrypted) MCAP
// returns a clear error.
func TestRotateKeysNotEncrypted(t *testing.T) {
	dir := t.TempDir()
	plainPath := filepath.Join(dir, "plain.mcap")
	buildTestMCAP(t, plainPath)

	keyA := filepath.Join(dir, "keyA")
	require.NoError(t, mcapencrypt.GenerateX25519KeyPair(keyA))
	oldPrivPEM := loadPEM(t, keyA+".priv.pem")
	newPubPEM := loadPEM(t, keyA+".pub.pem")

	inFile, err := os.Open(plainPath)
	require.NoError(t, err)
	defer inFile.Close()
	var outBuf bytes.Buffer
	err = mcapencrypt.RotateKeys(inFile, &outBuf, oldPrivPEM, []string{newPubPEM})
	require.Error(t, err)
	require.True(t,
		strings.Contains(err.Error(), "no wrapped key attachment") ||
			strings.Contains(err.Error(), "old private key"),
		"error should mention missing key attachment or key mismatch, got: %v", err)
}

// TestRotateKeyFileAtomic verifies that RotateKeyFile leaves no temp file on
// failure (invalid old key path is used to force failure).
func TestRotateKeyFileAtomic(t *testing.T) {
	dir := t.TempDir()
	plainPath := filepath.Join(dir, "plain.mcap")
	encPath := filepath.Join(dir, "encrypted.mcap")
	rotatedPath := filepath.Join(dir, "rotated.mcap")

	buildTestMCAP(t, plainPath)

	keyA := filepath.Join(dir, "keyA")
	keyB := filepath.Join(dir, "keyB")
	require.NoError(t, mcapencrypt.GenerateX25519KeyPair(keyA))
	require.NoError(t, mcapencrypt.GenerateX25519KeyPair(keyB))
	require.NoError(t, mcapencrypt.Encrypt(plainPath, encPath, keyA+".pub.pem"))

	// Use keyB's private key (wrong key) to force failure.
	wrongPrivPEM := loadPEM(t, keyB+".priv.pem")
	newPubPEM := loadPEM(t, keyB+".pub.pem")

	err := mcapencrypt.RotateKeyFile(encPath, rotatedPath, wrongPrivPEM, []string{newPubPEM})
	require.Error(t, err)

	// No output file should exist.
	_, statErr := os.Stat(rotatedPath)
	require.True(t, os.IsNotExist(statErr), "output file must not exist after failure")

	// No temp file should remain in the output directory.
	entries, readErr := os.ReadDir(dir)
	require.NoError(t, readErr)
	for _, e := range entries {
		require.False(t,
			strings.HasPrefix(e.Name(), ".mcap-rotate-tmp-"),
			"temp file %q must have been cleaned up", e.Name())
	}
}
