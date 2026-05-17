package mcapencrypt_test

import (
	"encoding/hex"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/remete618/mcap-encrypt/pkg/mcapencrypt"
)

func TestInspect_EncryptedRSA(t *testing.T) {
	dir := t.TempDir()
	plain := filepath.Join(dir, "plain.mcap")
	enc := filepath.Join(dir, "enc.mcap")
	key := filepath.Join(dir, "key")

	buildTestMCAP(t, plain)
	require.NoError(t, mcapencrypt.GenerateKeyPair(key))
	require.NoError(t, mcapencrypt.Encrypt(plain, enc, key+".pub.pem"))

	res, err := mcapencrypt.InspectFile(enc)
	require.NoError(t, err)

	require.True(t, res.IsEncrypted)
	require.Equal(t, byte(3), res.FormatVersion)
	require.Len(t, res.FileID, 16)
	require.Greater(t, res.ChunkCount, uint64(0))
	require.Equal(t, res.ChunkCount, res.EncryptedChunkCount)
	require.Equal(t, "zstd", res.Compression)
	require.Len(t, res.Recipients, 1)
	require.Equal(t, "rsa-oaep-sha256", res.Recipients[0].KEKAlg)
	require.Equal(t, "xchacha20poly1305", res.Recipients[0].Algorithm)

	// KeyID must be a valid 64-hex-char SHA-256 SPKI fingerprint.
	fp, err := hex.DecodeString(res.Recipients[0].KeyID)
	require.NoError(t, err)
	require.Len(t, fp, 32)
}

func TestInspect_MultiRecipient(t *testing.T) {
	dir := t.TempDir()
	plain := filepath.Join(dir, "plain.mcap")
	enc := filepath.Join(dir, "enc.mcap")
	rsaKey := filepath.Join(dir, "rsa")
	x25519Key := filepath.Join(dir, "x25519")

	buildTestMCAP(t, plain)
	require.NoError(t, mcapencrypt.GenerateKeyPair(rsaKey))
	require.NoError(t, mcapencrypt.GenerateX25519KeyPair(x25519Key))

	require.NoError(t, mcapencrypt.EncryptMulti(plain, enc, []string{
		rsaKey + ".pub.pem",
		x25519Key + ".pub.pem",
	}, nil))

	res, err := mcapencrypt.InspectFile(enc)
	require.NoError(t, err)

	require.True(t, res.IsEncrypted)
	require.Len(t, res.Recipients, 2)

	algSet := map[string]bool{}
	for _, r := range res.Recipients {
		algSet[r.KEKAlg] = true
	}
	require.True(t, algSet["rsa-oaep-sha256"], "expected RSA recipient")
	require.True(t, algSet["x25519-hkdf-xchacha20poly1305"], "expected X25519 recipient")
}

func TestInspect_PlainMCAP(t *testing.T) {
	dir := t.TempDir()
	plain := filepath.Join(dir, "plain.mcap")
	buildTestMCAP(t, plain)

	res, err := mcapencrypt.InspectFile(plain)
	require.NoError(t, err)

	require.False(t, res.IsEncrypted)
	require.Nil(t, res.FileID)
	require.Equal(t, uint64(0), res.ChunkCount)
	require.Empty(t, res.Recipients)
}
