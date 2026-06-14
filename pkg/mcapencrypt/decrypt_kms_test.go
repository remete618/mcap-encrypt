package mcapencrypt_test

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/remete618/mcap-encrypt/pkg/mcapencrypt"
	"github.com/remete618/mcap-encrypt/pkg/mcapencrypt/kms"
)

// TestRoundTripViaFakeKMS encrypts an MCAP with the fake KMS's public key
// (as returned by PublicKey()), then decrypts it via DecryptWithKMS using
// the same fake as a stand-in for an HSM. This is the critical test: it
// proves the KMS code path is byte-equivalent to the on-disk path.
func TestRoundTripViaFakeKMS(t *testing.T) {
	dir := t.TempDir()
	plainPath := filepath.Join(dir, "plain.mcap")
	encPath := filepath.Join(dir, "encrypted.mcap")
	decPath := filepath.Join(dir, "decrypted.mcap")

	buildTestMCAP(t, plainPath)

	// Generate a fake KMS-held key pair.
	fake, err := kms.NewFake()
	require.NoError(t, err)
	pubPEM, err := fake.PublicKey(context.Background())
	require.NoError(t, err)

	// Encrypt locally using the public key fetched from the fake KMS.
	pubKeyPath := filepath.Join(dir, "kms.pub.pem")
	require.NoError(t, os.WriteFile(pubKeyPath, pubPEM, 0o644))
	require.NoError(t, mcapencrypt.Encrypt(plainPath, encPath, pubKeyPath))

	// Decrypt via DecryptWithKMS using the fake as the Decrypter.
	encFile, err := os.Open(encPath)
	require.NoError(t, err)
	defer encFile.Close()
	decFile, err := os.Create(decPath)
	require.NoError(t, err)
	defer decFile.Close()
	require.NoError(t, mcapencrypt.DecryptWithKMS(context.Background(), encFile, decFile, fake, mcapencrypt.DecryptOptions{}))
	require.NoError(t, decFile.Close())

	// Verify round-trip.
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

// TestDecryptFileWithKMS exercises the file-path entry point.
func TestDecryptFileWithKMS(t *testing.T) {
	dir := t.TempDir()
	plainPath := filepath.Join(dir, "plain.mcap")
	encPath := filepath.Join(dir, "encrypted.mcap")
	decPath := filepath.Join(dir, "decrypted.mcap")

	buildTestMCAP(t, plainPath)

	fake, err := kms.NewFake()
	require.NoError(t, err)
	pubPEM, err := fake.PublicKey(context.Background())
	require.NoError(t, err)
	pubKeyPath := filepath.Join(dir, "kms.pub.pem")
	require.NoError(t, os.WriteFile(pubKeyPath, pubPEM, 0o644))
	require.NoError(t, mcapencrypt.Encrypt(plainPath, encPath, pubKeyPath))

	require.NoError(t, mcapencrypt.DecryptFileWithKMS(context.Background(), encPath, decPath, fake))

	require.FileExists(t, decPath)
	require.Equal(t, len(readAllMessages(t, plainPath)), len(readAllMessages(t, decPath)))
}

// TestWrongKMSKeyFails confirms that a Fake whose private key does NOT match
// the public key used at encrypt time fails with the same "no matching key"
// error path as the on-disk equivalent.
func TestWrongKMSKeyFails(t *testing.T) {
	dir := t.TempDir()
	plainPath := filepath.Join(dir, "plain.mcap")
	encPath := filepath.Join(dir, "encrypted.mcap")
	buildTestMCAP(t, plainPath)

	// Encrypt for key A.
	fakeA, err := kms.NewFake()
	require.NoError(t, err)
	pubPEM, err := fakeA.PublicKey(context.Background())
	require.NoError(t, err)
	pubKeyPath := filepath.Join(dir, "a.pub.pem")
	require.NoError(t, os.WriteFile(pubKeyPath, pubPEM, 0o644))
	require.NoError(t, mcapencrypt.Encrypt(plainPath, encPath, pubKeyPath))

	// Try to decrypt with key B.
	fakeB, err := kms.NewFake()
	require.NoError(t, err)

	encFile, err := os.Open(encPath)
	require.NoError(t, err)
	defer encFile.Close()
	var buf bytes.Buffer
	err = mcapencrypt.DecryptWithKMS(context.Background(), encFile, &buf, fakeB, mcapencrypt.DecryptOptions{})
	require.Error(t, err)
	require.Contains(t, err.Error(), "does not match")
}

// TestKMSRefusesWrongKEKAlg confirms that the Fake correctly rejects a
// non-RSA-OAEP-SHA-256 KEK algorithm. We can't easily construct such a file
// via the public API (the library only writes the two algs it supports), so
// we drive Decrypt() directly on the Decrypter.
func TestKMSRefusesWrongKEKAlg(t *testing.T) {
	fake, err := kms.NewFake()
	require.NoError(t, err)
	_, err = fake.Decrypt(context.Background(), "x25519-hkdf-xchacha20poly1305", []byte("anything"))
	require.Error(t, err)
}
