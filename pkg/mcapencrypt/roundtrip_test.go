package mcapencrypt_test

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/foxglove/mcap/go/mcap"
	"github.com/stretchr/testify/require"

	"github.com/remete618/mcap-encrypt/pkg/mcapencrypt"
)

// buildTestMCAP writes a small MCAP file with 2 schemas, 2 channels, and N messages.
func buildTestMCAP(t *testing.T, path string) {
	t.Helper()
	f, err := os.Create(path)
	require.NoError(t, err)
	defer f.Close()

	w, err := mcap.NewWriter(f, &mcap.WriterOptions{
		Chunked:     true,
		ChunkSize:   1024,
		Compression: mcap.CompressionZSTD,
	})
	require.NoError(t, err)
	require.NoError(t, w.WriteHeader(&mcap.Header{Profile: "test"}))
	require.NoError(t, w.WriteSchema(&mcap.Schema{ID: 1, Name: "sensor", Encoding: "json", Data: []byte(`{"type":"object"}`)}))
	require.NoError(t, w.WriteSchema(&mcap.Schema{ID: 2, Name: "cmd", Encoding: "json", Data: []byte(`{"type":"object"}`)}))
	require.NoError(t, w.WriteChannel(&mcap.Channel{ID: 1, SchemaID: 1, Topic: "/sensor", MessageEncoding: "json"}))
	require.NoError(t, w.WriteChannel(&mcap.Channel{ID: 2, SchemaID: 2, Topic: "/cmd", MessageEncoding: "json"}))

	for i := 0; i < 50; i++ {
		ts := uint64(time.Now().UnixNano()) + uint64(i)*1_000_000
		require.NoError(t, w.WriteMessage(&mcap.Message{
			ChannelID:   1,
			Sequence:    uint32(i),
			LogTime:     ts,
			PublishTime: ts,
			Data:        []byte(`{"x":1,"y":2}`),
		}))
		require.NoError(t, w.WriteMessage(&mcap.Message{
			ChannelID:   2,
			Sequence:    uint32(i),
			LogTime:     ts + 500_000,
			PublishTime: ts + 500_000,
			Data:        []byte(`{"v":42}`),
		}))
	}
	require.NoError(t, w.Close())
}

// readAllMessages returns all messages from a standard MCAP file.
func readAllMessages(t *testing.T, path string) []*mcap.Message {
	t.Helper()
	f, err := os.Open(path)
	require.NoError(t, err)
	defer f.Close()

	r, err := mcap.NewReader(f)
	require.NoError(t, err)
	it, err := r.Messages()
	require.NoError(t, err)

	var msgs []*mcap.Message
	for {
		_, _, msg, err := it.NextInto(nil)
		if err != nil {
			break
		}
		if msg != nil {
			msgs = append(msgs, msg)
		}
	}
	return msgs
}

func TestRoundTrip(t *testing.T) {
	dir := t.TempDir()
	plainPath := filepath.Join(dir, "plain.mcap")
	encPath := filepath.Join(dir, "encrypted.mcap")
	decPath := filepath.Join(dir, "decrypted.mcap")
	keyBase := filepath.Join(dir, "testkey")

	// Build source MCAP.
	buildTestMCAP(t, plainPath)

	// Generate key pair.
	require.NoError(t, mcapencrypt.GenerateKeyPair(keyBase))

	// Encrypt.
	require.NoError(t, mcapencrypt.Encrypt(plainPath, encPath, keyBase+".pub.pem"))

	// Encrypted file must be different from the original.
	plain, err := os.ReadFile(plainPath)
	require.NoError(t, err)
	enc, err := os.ReadFile(encPath)
	require.NoError(t, err)
	require.False(t, bytes.Equal(plain, enc), "encrypted file should differ from plaintext")

	// Decrypt.
	require.NoError(t, mcapencrypt.Decrypt(encPath, decPath, keyBase+".priv.pem"))

	// Messages must be identical before and after round-trip.
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

func TestWrongKeyFails(t *testing.T) {
	dir := t.TempDir()
	plainPath := filepath.Join(dir, "plain.mcap")
	encPath := filepath.Join(dir, "encrypted.mcap")
	decPath := filepath.Join(dir, "decrypted.mcap")

	buildTestMCAP(t, plainPath)

	keyA := filepath.Join(dir, "keyA")
	keyB := filepath.Join(dir, "keyB")
	require.NoError(t, mcapencrypt.GenerateKeyPair(keyA))
	require.NoError(t, mcapencrypt.GenerateKeyPair(keyB))

	// Encrypt with key A, decrypt with key B, must fail.
	require.NoError(t, mcapencrypt.Encrypt(plainPath, encPath, keyA+".pub.pem"))
	err := mcapencrypt.Decrypt(encPath, decPath, keyB+".priv.pem")
	require.Error(t, err, "decrypting with wrong key must fail")
}

func TestEncryptedFileIsNotReadableAsStandardMCAP(t *testing.T) {
	dir := t.TempDir()
	plainPath := filepath.Join(dir, "plain.mcap")
	encPath := filepath.Join(dir, "encrypted.mcap")
	keyBase := filepath.Join(dir, "key")

	buildTestMCAP(t, plainPath)
	require.NoError(t, mcapencrypt.GenerateKeyPair(keyBase))
	require.NoError(t, mcapencrypt.Encrypt(plainPath, encPath, keyBase+".pub.pem"))

	// The encrypted file should open as MCAP (magic is valid) but yield no messages
	// or error when a standard reader hits the unknown 0x81 opcode.
	f, err := os.Open(encPath)
	require.NoError(t, err)
	defer f.Close()

	r, err := mcap.NewReader(f)
	if err != nil {
		return // Acceptable: reader may reject the file entirely.
	}
	it, err := r.Messages()
	if err != nil {
		return // Acceptable.
	}
	var msgCount int
	var buf mcap.Message
	for {
		_, _, msg, iterErr := it.NextInto(&buf)
		if iterErr != nil {
			break
		}
		if msg != nil {
			msgCount++
		}
	}
	// A standard reader must not be able to read any messages from an encrypted file.
	require.Equal(t, 0, msgCount, "standard reader must not expose encrypted messages")
}
