package mcapencrypt_test

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"

	"github.com/foxglove/mcap/go/mcap"
	"github.com/stretchr/testify/require"

	"github.com/remete618/mcap-encrypt/pkg/mcapencrypt"
)

func findFirstEncryptedChunk(t *testing.T, data []byte) (recStart, recLen int) {
	t.Helper()
	pos := 8
	for pos+9 <= len(data) {
		opcode := data[pos]
		n := int(binary.LittleEndian.Uint64(data[pos+1:]))
		if opcode == 0x81 {
			return pos + 9, n
		}
		pos += 9 + n
	}
	t.Fatal("no encrypted chunk (0x81) found")
	return 0, 0
}

func TestTamperedNonce(t *testing.T) {
	dir := t.TempDir()
	plainPath := filepath.Join(dir, "plain.mcap")
	encPath := filepath.Join(dir, "enc.mcap")
	decPath := filepath.Join(dir, "dec.mcap")
	keyBase := filepath.Join(dir, "key")

	buildTestMCAP(t, plainPath)
	require.NoError(t, mcapencrypt.GenerateKeyPair(keyBase))
	require.NoError(t, mcapencrypt.Encrypt(plainPath, encPath, keyBase+".pub.pem"))

	data, err := os.ReadFile(encPath)
	require.NoError(t, err)
	recStart, _ := findFirstEncryptedChunk(t, data)

	// Nonce is at offset 49 inside the record data:
	// 8+8+8+4 (timestamps+sizes+crc) + 4+4 (compression "zstd") + 4+5 (keyId "key-1") + 4 (nonce len prefix) = 49
	tampered := make([]byte, len(data))
	copy(tampered, data)
	tampered[recStart+49] ^= 0xFF

	require.NoError(t, os.WriteFile(encPath, tampered, 0o644))
	err = mcapencrypt.Decrypt(encPath, decPath, keyBase+".priv.pem")
	require.Error(t, err)
	require.Contains(t, err.Error(), "authentication failed")
}

func TestTamperedAAD(t *testing.T) {
	dir := t.TempDir()
	plainPath := filepath.Join(dir, "plain.mcap")
	encPath := filepath.Join(dir, "enc.mcap")
	decPath := filepath.Join(dir, "dec.mcap")
	keyBase := filepath.Join(dir, "key")

	buildTestMCAP(t, plainPath)
	require.NoError(t, mcapencrypt.GenerateKeyPair(keyBase))
	require.NoError(t, mcapencrypt.Encrypt(plainPath, encPath, keyBase+".pub.pem"))

	data, err := os.ReadFile(encPath)
	require.NoError(t, err)
	recStart, _ := findFirstEncryptedChunk(t, data)

	// Flip the first byte of message_start_time (offset 0 in record data).
	// The decrypt side computes AAD from message_start_time and message_end_time,
	// so changing this field changes the AAD, causing AEAD authentication failure.
	tampered := make([]byte, len(data))
	copy(tampered, data)
	tampered[recStart] ^= 0xFF

	require.NoError(t, os.WriteFile(encPath, tampered, 0o644))
	err = mcapencrypt.Decrypt(encPath, decPath, keyBase+".priv.pem")
	require.Error(t, err)
	require.Contains(t, err.Error(), "authentication failed")
}

func TestNonChunkedInputRejected(t *testing.T) {
	dir := t.TempDir()
	flatPath := filepath.Join(dir, "flat.mcap")
	encPath := filepath.Join(dir, "enc.mcap")
	keyBase := filepath.Join(dir, "key")

	f, createErr := os.Create(flatPath)
	require.NoError(t, createErr)
	w, err := mcap.NewWriter(f, &mcap.WriterOptions{Chunked: false})
	require.NoError(t, err)
	require.NoError(t, w.WriteHeader(&mcap.Header{Profile: "test"}))
	require.NoError(t, w.WriteSchema(&mcap.Schema{ID: 1, Name: "s", Encoding: "json", Data: []byte(`{}`)}))
	require.NoError(t, w.WriteChannel(&mcap.Channel{ID: 1, SchemaID: 1, Topic: "/t", MessageEncoding: "json"}))
	require.NoError(t, w.WriteMessage(&mcap.Message{ChannelID: 1, Data: []byte(`{}`)}))
	require.NoError(t, w.Close())
	f.Close()

	require.NoError(t, mcapencrypt.GenerateKeyPair(keyBase))
	err = mcapencrypt.Encrypt(flatPath, encPath, keyBase+".pub.pem")
	require.Error(t, err)
	require.Contains(t, err.Error(), "not chunked")
}
