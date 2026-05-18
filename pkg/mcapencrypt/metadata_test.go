package mcapencrypt_test

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/foxglove/mcap/go/mcap"
	"github.com/stretchr/testify/require"

	"github.com/remete618/mcap-encrypt/pkg/mcapencrypt"
)

// generateTestKeyPair generates an RSA-4096 key pair in dir and returns
// (pubPath, privPath).
func generateTestKeyPair(t *testing.T, dir string) (pub, priv string) {
	t.Helper()
	base := filepath.Join(dir, "testkey")
	require.NoError(t, mcapencrypt.GenerateKeyPair(base))
	return base + ".pub.pem", base + ".priv.pem"
}

// buildTestMCAPWithCustomMetadata writes a MCAP file containing one metadata record.
func buildTestMCAPWithCustomMetadata(t *testing.T, path string, name string, kv map[string]string) {
	t.Helper()
	f, err := os.Create(path)
	require.NoError(t, err)
	defer f.Close()

	w, err := mcap.NewWriter(f, &mcap.WriterOptions{Chunked: true, ChunkSize: 4096, Compression: mcap.CompressionZSTD})
	require.NoError(t, err)
	require.NoError(t, w.WriteHeader(&mcap.Header{Profile: "ros2", Library: "test"}))
	require.NoError(t, w.WriteSchema(&mcap.Schema{ID: 1, Name: "sensor", Encoding: "json", Data: []byte(`{}`)}))
	require.NoError(t, w.WriteChannel(&mcap.Channel{ID: 1, SchemaID: 1, Topic: "/s", MessageEncoding: "json"}))
	require.NoError(t, w.WriteMessage(&mcap.Message{ChannelID: 1, LogTime: 1_000, Data: []byte(`{"v":1}`)}))
	require.NoError(t, w.WriteMetadata(&mcap.Metadata{Name: name, Metadata: kv}))
	require.NoError(t, w.Close())
}

// roundTripWithMetadataMode encrypts with the given mode and decrypts, returning
// the decrypted MCAP bytes and any metadata records found in the data section.
func roundTripWithMetadataMode(t *testing.T, mode mcapencrypt.MetadataMode) (encPath, decPath string, decryptedBytes []byte) {
	t.Helper()
	dir := t.TempDir()

	plainPath := filepath.Join(dir, "plain.mcap")
	buildTestMCAPWithCustomMetadata(t, plainPath, "robot_info", map[string]string{
		"serial": "SN-42",
		"site":   "lab-west",
	})

	pub, priv := generateTestKeyPair(t, dir)
	encPath = filepath.Join(dir, "encrypted.mcap")
	decPath = filepath.Join(dir, "decrypted.mcap")

	require.NoError(t, mcapencrypt.EncryptWithOptions(plainPath, encPath, []string{pub}, mcapencrypt.EncryptOptions{
		MetadataMode: mode,
	}))
	require.NoError(t, mcapencrypt.Decrypt(encPath, decPath, priv))

	data, err := os.ReadFile(decPath)
	require.NoError(t, err)
	return encPath, decPath, data
}

// TestMetadataPlaintextPassthrough verifies that MetadataPlaintext keeps the
// metadata record in plaintext and survives round-trip unchanged.
func TestMetadataPlaintextPassthrough(t *testing.T) {
	_, _, decBytes := roundTripWithMetadataMode(t, mcapencrypt.MetadataPlaintext)
	metas := extractMetadataRecords(t, decBytes)
	require.Len(t, metas, 1)
	require.Equal(t, "robot_info", metas[0].Name)
	require.Equal(t, "SN-42", metas[0].Metadata["serial"])
	require.Equal(t, "lab-west", metas[0].Metadata["site"])
}

// TestMetadataEncryptRoundTrip verifies that MetadataEncrypt produces an
// EncryptedMetadata record (opcode 0x83) in the encrypted file with the name
// visible, and that decryption restores the full metadata.
func TestMetadataEncryptRoundTrip(t *testing.T) {
	encPath, _, decBytes := roundTripWithMetadataMode(t, mcapencrypt.MetadataEncrypt)

	// Verify name is visible in the encrypted file.
	encRaw, err := os.ReadFile(encPath)
	require.NoError(t, err)
	require.True(t, bytes.Contains(encRaw, []byte("robot_info")), "metadata name should be visible in encrypt mode")

	metas := extractMetadataRecords(t, decBytes)
	require.Len(t, metas, 1)
	require.Equal(t, "robot_info", metas[0].Name)
	require.Equal(t, "SN-42", metas[0].Metadata["serial"])
}

// TestMetadataEncryptAllRoundTrip verifies that MetadataEncryptAll makes both
// name and map invisible, and that decryption restores everything.
func TestMetadataEncryptAllRoundTrip(t *testing.T) {
	encPath, _, decBytes := roundTripWithMetadataMode(t, mcapencrypt.MetadataEncryptAll)

	// Verify name is NOT visible in the encrypted file.
	encRaw, err := os.ReadFile(encPath)
	require.NoError(t, err)
	require.False(t, bytes.Contains(encRaw, []byte("robot_info")), "metadata name must not appear in encrypt-all mode")

	metas := extractMetadataRecords(t, decBytes)
	require.Len(t, metas, 1)
	require.Equal(t, "robot_info", metas[0].Name)
	require.Equal(t, "SN-42", metas[0].Metadata["serial"])
}

// TestMetadataEncryptCiphertextTamper verifies that tampering with the ciphertext
// of an EncryptedMetadata record causes decryption to fail.
func TestMetadataEncryptCiphertextTamper(t *testing.T) {
	dir := t.TempDir()
	plainPath := filepath.Join(dir, "plain.mcap")
	buildTestMCAPWithCustomMetadata(t, plainPath, "secrets", map[string]string{"key": "value"})

	pub, priv := generateTestKeyPair(t, dir)
	encPath := filepath.Join(dir, "enc.mcap")
	decPath := filepath.Join(dir, "dec.mcap")

	require.NoError(t, mcapencrypt.EncryptWithOptions(plainPath, encPath, []string{pub}, mcapencrypt.EncryptOptions{
		MetadataMode: mcapencrypt.MetadataEncrypt,
	}))

	// Flip a byte in the encrypted file.
	raw, err := os.ReadFile(encPath)
	require.NoError(t, err)
	raw[len(raw)/2] ^= 0xff
	require.NoError(t, os.WriteFile(encPath, raw, 0600))

	err = mcapencrypt.Decrypt(encPath, decPath, priv)
	require.Error(t, err)
}

// TestMetadataEncryptAllCiphertextTamper verifies the same for encrypt-all mode.
func TestMetadataEncryptAllCiphertextTamper(t *testing.T) {
	dir := t.TempDir()
	plainPath := filepath.Join(dir, "plain.mcap")
	buildTestMCAPWithCustomMetadata(t, plainPath, "secrets", map[string]string{"key": "value"})

	pub, priv := generateTestKeyPair(t, dir)
	encPath := filepath.Join(dir, "enc.mcap")
	decPath := filepath.Join(dir, "dec.mcap")

	require.NoError(t, mcapencrypt.EncryptWithOptions(plainPath, encPath, []string{pub}, mcapencrypt.EncryptOptions{
		MetadataMode: mcapencrypt.MetadataEncryptAll,
	}))

	raw, err := os.ReadFile(encPath)
	require.NoError(t, err)
	raw[len(raw)/2] ^= 0xff
	require.NoError(t, os.WriteFile(encPath, raw, 0600))

	err = mcapencrypt.Decrypt(encPath, decPath, priv)
	require.Error(t, err)
}

// TestMetadataEncryptNameTamper verifies that altering the plaintext name field
// in an EncryptedMetadata record causes AEAD authentication to fail on decrypt.
func TestMetadataEncryptNameTamper(t *testing.T) {
	dir := t.TempDir()
	plainPath := filepath.Join(dir, "plain.mcap")
	buildTestMCAPWithCustomMetadata(t, plainPath, "robot_info", map[string]string{"serial": "SN-1"})

	pub, priv := generateTestKeyPair(t, dir)
	encPath := filepath.Join(dir, "enc.mcap")
	decPath := filepath.Join(dir, "dec.mcap")

	require.NoError(t, mcapencrypt.EncryptWithOptions(plainPath, encPath, []string{pub}, mcapencrypt.EncryptOptions{
		MetadataMode: mcapencrypt.MetadataEncrypt,
	}))

	// Replace "robot_info" with "robot_x999" in the encrypted file.
	raw, err := os.ReadFile(encPath)
	require.NoError(t, err)
	raw = bytes.ReplaceAll(raw, []byte("robot_info"), []byte("robot_x999"))
	require.NoError(t, os.WriteFile(encPath, raw, 0600))

	err = mcapencrypt.Decrypt(encPath, decPath, priv)
	require.Error(t, err)
}

// extractMetadataRecords reads a standard MCAP and returns all Metadata records.
func extractMetadataRecords(t *testing.T, data []byte) []*mcap.Metadata {
	t.Helper()
	r := bytes.NewReader(data)
	lex, err := mcap.NewLexer(r)
	require.NoError(t, err)
	var metas []*mcap.Metadata
	var buf []byte
	for {
		tok, d, err := lex.Next(buf)
		if err != nil {
			break
		}
		buf = d
		if tok == mcap.TokenMetadata {
			m, parseErr := mcap.ParseMetadata(d)
			require.NoError(t, parseErr)
			metas = append(metas, m)
		}
	}
	return metas
}
