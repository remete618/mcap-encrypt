package mcapencrypt_test

import (
	"bytes"
	"io"
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

// TestEncryptStreamRoundTrip verifies that EncryptStream produces an encrypted
// MCAP that can be decrypted back to the original messages. Uses X25519 keys
// so the test runs fast without RSA key generation overhead.
func TestEncryptStreamRoundTrip(t *testing.T) {
	dir := t.TempDir()
	plainPath := filepath.Join(dir, "plain.mcap")
	decPath := filepath.Join(dir, "decrypted.mcap")
	keyBase := filepath.Join(dir, "key")

	buildTestMCAP(t, plainPath)
	require.NoError(t, mcapencrypt.GenerateX25519KeyPair(keyBase))

	pubPEM, err := os.ReadFile(keyBase + ".pub.pem")
	require.NoError(t, err)
	plainBytes, err := os.ReadFile(plainPath)
	require.NoError(t, err)

	// Encrypt via stream API.
	var encBuf bytes.Buffer
	require.NoError(t, mcapencrypt.EncryptStream(bytes.NewReader(plainBytes), &encBuf, []string{string(pubPEM)}))
	require.Greater(t, encBuf.Len(), 0)

	// Write encrypted bytes to a file for decryption.
	encPath := filepath.Join(dir, "encrypted.mcap")
	require.NoError(t, os.WriteFile(encPath, encBuf.Bytes(), 0644))

	// Decrypt and compare messages.
	require.NoError(t, mcapencrypt.Decrypt(encPath, decPath, keyBase+".priv.pem"))
	origMsgs := readAllMessages(t, plainPath)
	decMsgs := readAllMessages(t, decPath)
	require.Equal(t, len(origMsgs), len(decMsgs), "message count must match")
	for i, om := range origMsgs {
		dm := decMsgs[i]
		require.Equal(t, om.ChannelID, dm.ChannelID)
		require.Equal(t, om.LogTime, dm.LogTime)
		require.Equal(t, om.Data, dm.Data)
	}
}

// TestEncryptStreamMultiRecipient verifies that when EncryptStream is called
// with two public keys, the encrypted file can be decrypted by either key.
func TestEncryptStreamMultiRecipient(t *testing.T) {
	dir := t.TempDir()
	plainPath := filepath.Join(dir, "plain.mcap")
	keyA := filepath.Join(dir, "keyA")
	keyB := filepath.Join(dir, "keyB")

	buildTestMCAP(t, plainPath)
	require.NoError(t, mcapencrypt.GenerateX25519KeyPair(keyA))
	require.NoError(t, mcapencrypt.GenerateX25519KeyPair(keyB))

	pubA, err := os.ReadFile(keyA + ".pub.pem")
	require.NoError(t, err)
	pubB, err := os.ReadFile(keyB + ".pub.pem")
	require.NoError(t, err)
	plainBytes, err := os.ReadFile(plainPath)
	require.NoError(t, err)

	var encBuf bytes.Buffer
	require.NoError(t, mcapencrypt.EncryptStream(bytes.NewReader(plainBytes), &encBuf, []string{string(pubA), string(pubB)}))

	encPath := filepath.Join(dir, "encrypted.mcap")
	require.NoError(t, os.WriteFile(encPath, encBuf.Bytes(), 0644))

	origMsgs := readAllMessages(t, plainPath)

	for _, keyFile := range []string{keyA, keyB} {
		decPath := keyFile + ".dec.mcap"
		require.NoError(t, mcapencrypt.Decrypt(encPath, decPath, keyFile+".priv.pem"),
			"decryption with %s must succeed", filepath.Base(keyFile))
		decMsgs := readAllMessages(t, decPath)
		require.Equal(t, len(origMsgs), len(decMsgs))
	}
}

// TestEncryptStreamWrongKeyFails verifies that a file encrypted via EncryptStream
// cannot be decrypted with a different key.
func TestEncryptStreamWrongKeyFails(t *testing.T) {
	dir := t.TempDir()
	plainPath := filepath.Join(dir, "plain.mcap")
	keyA := filepath.Join(dir, "keyA")
	keyB := filepath.Join(dir, "keyB")

	buildTestMCAP(t, plainPath)
	require.NoError(t, mcapencrypt.GenerateX25519KeyPair(keyA))
	require.NoError(t, mcapencrypt.GenerateX25519KeyPair(keyB))

	pubA, err := os.ReadFile(keyA + ".pub.pem")
	require.NoError(t, err)
	plainBytes, err := os.ReadFile(plainPath)
	require.NoError(t, err)

	var encBuf bytes.Buffer
	require.NoError(t, mcapencrypt.EncryptStream(bytes.NewReader(plainBytes), &encBuf, []string{string(pubA)}))

	encPath := filepath.Join(dir, "encrypted.mcap")
	require.NoError(t, os.WriteFile(encPath, encBuf.Bytes(), 0644))

	decPath := filepath.Join(dir, "decrypted.mcap")
	err = mcapencrypt.Decrypt(encPath, decPath, keyB+".priv.pem")
	require.Error(t, err, "decryption with wrong key must fail")
}

// TestEncryptStreamRejectsAlreadyEncrypted verifies that feeding an already-encrypted
// MCAP to EncryptStream returns an error and produces no output.
func TestEncryptStreamRejectsAlreadyEncrypted(t *testing.T) {
	dir := t.TempDir()
	plainPath := filepath.Join(dir, "plain.mcap")
	encPath := filepath.Join(dir, "encrypted.mcap")
	keyBase := filepath.Join(dir, "key")

	buildTestMCAP(t, plainPath)
	require.NoError(t, mcapencrypt.GenerateX25519KeyPair(keyBase))

	pubPEM, err := os.ReadFile(keyBase + ".pub.pem")
	require.NoError(t, err)
	require.NoError(t, mcapencrypt.Encrypt(plainPath, encPath, keyBase+".pub.pem"))

	encBytes, err := os.ReadFile(encPath)
	require.NoError(t, err)

	var out bytes.Buffer
	err = mcapencrypt.EncryptStream(bytes.NewReader(encBytes), &out, []string{string(pubPEM)})
	require.Error(t, err, "re-encrypting an already-encrypted file must fail")
	require.ErrorContains(t, err, "already encrypted")
}

// TestEncryptStreamRequiresAtLeastOneKey verifies that calling EncryptStream
// with an empty key list returns an error immediately, before any I/O.
func TestEncryptStreamRequiresAtLeastOneKey(t *testing.T) {
	err := mcapencrypt.EncryptStream(bytes.NewReader(nil), io.Discard, []string{})
	require.Error(t, err)
	require.ErrorContains(t, err, "at least one public key")
}
