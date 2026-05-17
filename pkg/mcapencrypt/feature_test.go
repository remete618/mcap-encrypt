package mcapencrypt_test

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"

	"github.com/foxglove/mcap/go/mcap"
	"github.com/stretchr/testify/require"

	"github.com/remete618/mcap-encrypt/pkg/mcapencrypt"
)

// buildTestMCAPWithAttachment writes a MCAP file that includes a non-key attachment.
func buildTestMCAPWithAttachment(t *testing.T, path string) {
	t.Helper()
	f, err := os.Create(path)
	require.NoError(t, err)
	defer f.Close()

	w, err := mcap.NewWriter(f, &mcap.WriterOptions{Chunked: true, ChunkSize: 4096, Compression: mcap.CompressionZSTD})
	require.NoError(t, err)
	require.NoError(t, w.WriteHeader(&mcap.Header{Profile: "ros2", Library: "test-lib"}))
	require.NoError(t, w.WriteSchema(&mcap.Schema{ID: 1, Name: "sensor", Encoding: "json", Data: []byte(`{}`)}))
	require.NoError(t, w.WriteChannel(&mcap.Channel{ID: 1, SchemaID: 1, Topic: "/s", MessageEncoding: "json"}))
	require.NoError(t, w.WriteMessage(&mcap.Message{ChannelID: 1, LogTime: 1_000, Data: []byte(`{"v":1}`)}))
	payload := []byte(`{"k":"v"}`)
	require.NoError(t, w.WriteAttachment(&mcap.Attachment{
		LogTime:    500,
		CreateTime: 0,
		Name:       "config.json",
		MediaType:  "application/json",
		DataSize:   uint64(len(payload)),
		Data:       bytes.NewReader(payload),
	}))
	require.NoError(t, w.Close())
}

// buildTestMCAPWithKeyNamedAttachment writes a MCAP that contains an attachment
// whose name matches mcap_encryption_key but whose media type is NOT the wrapped-key
// type. This attachment must survive encrypt/decrypt unchanged.
func buildTestMCAPWithKeyNamedAttachment(t *testing.T, path string) {
	t.Helper()
	f, err := os.Create(path)
	require.NoError(t, err)
	defer f.Close()

	w, err := mcap.NewWriter(f, &mcap.WriterOptions{Chunked: true, ChunkSize: 4096, Compression: mcap.CompressionZSTD})
	require.NoError(t, err)
	require.NoError(t, w.WriteHeader(&mcap.Header{Profile: "test"}))
	require.NoError(t, w.WriteSchema(&mcap.Schema{ID: 1, Name: "s", Encoding: "json", Data: []byte("{}")}))
	require.NoError(t, w.WriteChannel(&mcap.Channel{ID: 1, SchemaID: 1, Topic: "/t", MessageEncoding: "json"}))
	require.NoError(t, w.WriteMessage(&mcap.Message{ChannelID: 1, LogTime: 1_000, Data: []byte(`{}`)}))
	payload := []byte("user data")
	require.NoError(t, w.WriteAttachment(&mcap.Attachment{
		LogTime:    500,
		CreateTime: 0,
		Name:       mcapencrypt.AttachmentName,      // same name as key attachment
		MediaType:  "application/octet-stream",      // different media type
		DataSize:   uint64(len(payload)),
		Data:       bytes.NewReader(payload),
	}))
	require.NoError(t, w.Close())
}

// buildEmptyMCAP writes a MCAP with header/footer but no messages.
func buildEmptyMCAP(t *testing.T, path string) {
	t.Helper()
	f, err := os.Create(path)
	require.NoError(t, err)
	defer f.Close()

	w, err := mcap.NewWriter(f, &mcap.WriterOptions{Chunked: true, ChunkSize: 4096})
	require.NoError(t, err)
	require.NoError(t, w.WriteHeader(&mcap.Header{Profile: "empty"}))
	require.NoError(t, w.Close())
}

// readAttachments returns all attachment names from a standard MCAP file.
func readAttachments(t *testing.T, path string) []string {
	t.Helper()
	f, err := os.Open(path)
	require.NoError(t, err)
	defer f.Close()
	r, err := mcap.NewReader(f)
	require.NoError(t, err)
	info, err := r.Info()
	require.NoError(t, err)
	var names []string
	for _, idx := range info.AttachmentIndexes {
		names = append(names, idx.Name)
	}
	return names
}

// TestMultiRecipient verifies that any recipient private key can decrypt the file.
func TestMultiRecipient(t *testing.T) {
	dir := t.TempDir()
	plainPath := filepath.Join(dir, "plain.mcap")
	encPath := filepath.Join(dir, "enc.mcap")
	keyA := filepath.Join(dir, "keyA")
	keyB := filepath.Join(dir, "keyB")

	buildTestMCAP(t, plainPath)
	require.NoError(t, mcapencrypt.GenerateKeyPair(keyA))
	require.NoError(t, mcapencrypt.GenerateKeyPair(keyB))

	require.NoError(t, mcapencrypt.EncryptMulti(plainPath, encPath, []string{keyA + ".pub.pem", keyB + ".pub.pem"}))

	origMsgs := readAllMessages(t, plainPath)

	for _, priv := range []string{keyA + ".priv.pem", keyB + ".priv.pem"} {
		decPath := filepath.Join(dir, filepath.Base(priv)+".dec.mcap")
		require.NoError(t, mcapencrypt.Decrypt(encPath, decPath, priv))
		decMsgs := readAllMessages(t, decPath)
		require.Equal(t, len(origMsgs), len(decMsgs))
		for i, om := range origMsgs {
			require.Equal(t, om.Data, decMsgs[i].Data)
		}
	}
}

// TestThirdKeyRejected verifies a key that was not a recipient cannot decrypt.
func TestThirdKeyRejected(t *testing.T) {
	dir := t.TempDir()
	plainPath := filepath.Join(dir, "plain.mcap")
	encPath := filepath.Join(dir, "enc.mcap")
	keyA := filepath.Join(dir, "keyA")
	keyC := filepath.Join(dir, "keyC")

	buildTestMCAP(t, plainPath)
	require.NoError(t, mcapencrypt.GenerateKeyPair(keyA))
	require.NoError(t, mcapencrypt.GenerateKeyPair(keyC))
	require.NoError(t, mcapencrypt.Encrypt(plainPath, encPath, keyA+".pub.pem"))

	err := mcapencrypt.Decrypt(encPath, filepath.Join(dir, "out.mcap"), keyC+".priv.pem")
	require.Error(t, err)
	require.Contains(t, err.Error(), "private key does not match")
}

// TestAttachmentPassthrough verifies non-key attachments survive encrypt/decrypt.
func TestAttachmentPassthrough(t *testing.T) {
	dir := t.TempDir()
	plainPath := filepath.Join(dir, "plain.mcap")
	encPath := filepath.Join(dir, "enc.mcap")
	decPath := filepath.Join(dir, "dec.mcap")
	keyBase := filepath.Join(dir, "key")

	buildTestMCAPWithAttachment(t, plainPath)
	require.NoError(t, mcapencrypt.GenerateKeyPair(keyBase))
	require.NoError(t, mcapencrypt.Encrypt(plainPath, encPath, keyBase+".pub.pem"))
	require.NoError(t, mcapencrypt.Decrypt(encPath, decPath, keyBase+".priv.pem"))

	names := readAttachments(t, decPath)
	require.Contains(t, names, "config.json", "non-key attachment must survive round-trip")
}

// TestHeaderProfilePreserved verifies the profile and library fields survive decrypt.
func TestHeaderProfilePreserved(t *testing.T) {
	dir := t.TempDir()
	plainPath := filepath.Join(dir, "plain.mcap")
	encPath := filepath.Join(dir, "enc.mcap")
	decPath := filepath.Join(dir, "dec.mcap")
	keyBase := filepath.Join(dir, "key")

	buildTestMCAPWithAttachment(t, plainPath) // writes profile="ros2", library="test-lib"
	require.NoError(t, mcapencrypt.GenerateKeyPair(keyBase))
	require.NoError(t, mcapencrypt.Encrypt(plainPath, encPath, keyBase+".pub.pem"))
	require.NoError(t, mcapencrypt.Decrypt(encPath, decPath, keyBase+".priv.pem"))

	f, err := os.Open(decPath)
	require.NoError(t, err)
	defer f.Close()
	r, err := mcap.NewReader(f)
	require.NoError(t, err)
	info, err := r.Info()
	require.NoError(t, err)
	require.Equal(t, "ros2", info.Header.Profile)
}

// TestEmptyMCAPRoundTrip verifies encrypt/decrypt works on a MCAP with no messages.
func TestEmptyMCAPRoundTrip(t *testing.T) {
	dir := t.TempDir()
	plainPath := filepath.Join(dir, "empty.mcap")
	encPath := filepath.Join(dir, "enc.mcap")
	decPath := filepath.Join(dir, "dec.mcap")
	keyBase := filepath.Join(dir, "key")

	buildEmptyMCAP(t, plainPath)
	require.NoError(t, mcapencrypt.GenerateKeyPair(keyBase))
	require.NoError(t, mcapencrypt.Encrypt(plainPath, encPath, keyBase+".pub.pem"))
	require.NoError(t, mcapencrypt.Decrypt(encPath, decPath, keyBase+".priv.pem"))

	msgs := readAllMessages(t, decPath)
	require.Empty(t, msgs)
}

// TestTruncatedFileReturnsError verifies parsing errors are reported, not panicked.
func TestTruncatedFileReturnsError(t *testing.T) {
	dir := t.TempDir()
	plainPath := filepath.Join(dir, "plain.mcap")
	encPath := filepath.Join(dir, "enc.mcap")
	keyBase := filepath.Join(dir, "key")

	buildTestMCAP(t, plainPath)
	require.NoError(t, mcapencrypt.GenerateKeyPair(keyBase))
	require.NoError(t, mcapencrypt.Encrypt(plainPath, encPath, keyBase+".pub.pem"))

	data, err := os.ReadFile(encPath)
	require.NoError(t, err)

	// Write only the first half of the encrypted file.
	truncPath := filepath.Join(dir, "trunc.mcap")
	require.NoError(t, os.WriteFile(truncPath, data[:len(data)/2], 0o644))

	err = mcapencrypt.Decrypt(truncPath, filepath.Join(dir, "out.mcap"), keyBase+".priv.pem")
	require.Error(t, err, "truncated file must return an error")
}

// TestOutputNotCreatedOnFailure verifies no output file is left when decryption fails.
func TestOutputNotCreatedOnFailure(t *testing.T) {
	dir := t.TempDir()
	plainPath := filepath.Join(dir, "plain.mcap")
	encPath := filepath.Join(dir, "enc.mcap")
	decPath := filepath.Join(dir, "dec.mcap")
	keyA := filepath.Join(dir, "keyA")
	keyB := filepath.Join(dir, "keyB")

	buildTestMCAP(t, plainPath)
	require.NoError(t, mcapencrypt.GenerateKeyPair(keyA))
	require.NoError(t, mcapencrypt.GenerateKeyPair(keyB))
	require.NoError(t, mcapencrypt.Encrypt(plainPath, encPath, keyA+".pub.pem"))

	err := mcapencrypt.Decrypt(encPath, decPath, keyB+".priv.pem")
	require.Error(t, err)
	_, statErr := os.Stat(decPath)
	require.True(t, os.IsNotExist(statErr), "output file must not exist after failed decryption")
}

// TestNoRecipientsRejected verifies EncryptMulti rejects an empty key list.
func TestNoRecipientsRejected(t *testing.T) {
	dir := t.TempDir()
	plainPath := filepath.Join(dir, "plain.mcap")
	buildTestMCAP(t, plainPath)
	err := mcapencrypt.EncryptMulti(plainPath, filepath.Join(dir, "out.mcap"), nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "at least one public key")
}

// TestSameInputOutputRejected verifies Encrypt rejects identical input/output paths.
func TestSameInputOutputRejected(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "file.mcap")
	buildTestMCAP(t, path)
	keyBase := filepath.Join(dir, "key")
	require.NoError(t, mcapencrypt.GenerateKeyPair(keyBase))
	err := mcapencrypt.Encrypt(path, path, keyBase+".pub.pem")
	require.Error(t, err)
	require.Contains(t, err.Error(), "must differ")
}

// TestEncryptRefusesExistingOutput verifies Encrypt returns an error when the output path already exists.
func TestEncryptRefusesExistingOutput(t *testing.T) {
	dir := t.TempDir()
	plainPath := filepath.Join(dir, "plain.mcap")
	encPath := filepath.Join(dir, "encrypted.mcap")
	keyBase := filepath.Join(dir, "key")

	buildTestMCAP(t, plainPath)
	require.NoError(t, mcapencrypt.GenerateKeyPair(keyBase))

	existing, err := os.Create(encPath)
	require.NoError(t, err)
	require.NoError(t, existing.Close())

	err = mcapencrypt.Encrypt(plainPath, encPath, keyBase+".pub.pem")
	require.Error(t, err)
	require.Contains(t, err.Error(), "already exists")
}

// TestDecryptRefusesExistingOutput verifies Decrypt returns an error when the output path already exists.
func TestDecryptRefusesExistingOutput(t *testing.T) {
	dir := t.TempDir()
	plainPath := filepath.Join(dir, "plain.mcap")
	encPath := filepath.Join(dir, "encrypted.mcap")
	decPath := filepath.Join(dir, "decrypted.mcap")
	keyBase := filepath.Join(dir, "key")

	buildTestMCAP(t, plainPath)
	require.NoError(t, mcapencrypt.GenerateKeyPair(keyBase))
	require.NoError(t, mcapencrypt.Encrypt(plainPath, encPath, keyBase+".pub.pem"))

	existing, err := os.Create(decPath)
	require.NoError(t, err)
	require.NoError(t, existing.Close())

	err = mcapencrypt.Decrypt(encPath, decPath, keyBase+".priv.pem")
	require.Error(t, err)
	require.Contains(t, err.Error(), "already exists")
}

// TestMetadataRoundTrip verifies metadata records are preserved through encrypt/decrypt.
func TestMetadataRoundTrip(t *testing.T) {
	dir := t.TempDir()
	plainPath := filepath.Join(dir, "plain.mcap")
	encPath := filepath.Join(dir, "encrypted.mcap")
	decPath := filepath.Join(dir, "decrypted.mcap")
	keyBase := filepath.Join(dir, "key")

	buildTestMCAPWithMetadata(t, plainPath)
	require.NoError(t, mcapencrypt.GenerateKeyPair(keyBase))
	require.NoError(t, mcapencrypt.Encrypt(plainPath, encPath, keyBase+".pub.pem"))
	require.NoError(t, mcapencrypt.Decrypt(encPath, decPath, keyBase+".priv.pem"))

	f, err := os.Open(decPath)
	require.NoError(t, err)
	defer f.Close()
	r, err := mcap.NewReader(f)
	require.NoError(t, err)
	info, err := r.Info()
	require.NoError(t, err)
	require.Len(t, info.MetadataIndexes, 1, "expected exactly 1 metadata record after round-trip")
	require.Equal(t, "robot_info", info.MetadataIndexes[0].Name)

	m, getErr := r.GetMetadata(info.MetadataIndexes[0].Offset)
	require.NoError(t, getErr)
	require.Equal(t, "ABC-123", m.Metadata["serial"])
	require.Equal(t, "1.2.3", m.Metadata["version"])
}

func buildTestMCAPWithMetadata(t *testing.T, path string) {
	t.Helper()
	f, err := os.Create(path)
	require.NoError(t, err)
	defer f.Close()
	w, err := mcap.NewWriter(f, &mcap.WriterOptions{Chunked: true, ChunkSize: 1024, Compression: mcap.CompressionZSTD})
	require.NoError(t, err)
	require.NoError(t, w.WriteHeader(&mcap.Header{Profile: "test"}))
	require.NoError(t, w.WriteSchema(&mcap.Schema{ID: 1, Name: "s", Encoding: "json", Data: []byte("{}")}))
	require.NoError(t, w.WriteChannel(&mcap.Channel{ID: 1, SchemaID: 1, Topic: "/t", MessageEncoding: "json"}))
	require.NoError(t, w.WriteMessage(&mcap.Message{
		ChannelID: 1, Sequence: 0, LogTime: 1_000_000, PublishTime: 1_000_000, Data: []byte(`{}`),
	}))
	require.NoError(t, w.WriteMetadata(&mcap.Metadata{
		Name:     "robot_info",
		Metadata: map[string]string{"serial": "ABC-123", "version": "1.2.3"},
	}))
	require.NoError(t, w.Close())
}

// TestKeyNamedAttachmentSurvivesEncrypt verifies that a user attachment whose name
// matches mcap_encryption_key but whose media type is not the key wrapper type is
// not silently dropped during encryption/decryption.
func TestKeyNamedAttachmentSurvivesEncrypt(t *testing.T) {
	dir := t.TempDir()
	plainPath := filepath.Join(dir, "plain.mcap")
	encPath := filepath.Join(dir, "enc.mcap")
	decPath := filepath.Join(dir, "dec.mcap")
	keyBase := filepath.Join(dir, "key")

	buildTestMCAPWithKeyNamedAttachment(t, plainPath)
	require.NoError(t, mcapencrypt.GenerateKeyPair(keyBase))
	require.NoError(t, mcapencrypt.Encrypt(plainPath, encPath, keyBase+".pub.pem"))
	require.NoError(t, mcapencrypt.Decrypt(encPath, decPath, keyBase+".priv.pem"))

	names := readAttachments(t, decPath)
	require.Contains(t, names, mcapencrypt.AttachmentName,
		"attachment with key name but different media type must survive round-trip")
}

// TestOverwriteRejectedByLibrary verifies the library itself refuses to overwrite an
// existing output file. This is the guard the CLI --force fix works around.
func TestOverwriteRejectedByLibrary(t *testing.T) {
	dir := t.TempDir()
	plainPath := filepath.Join(dir, "plain.mcap")
	encPath := filepath.Join(dir, "enc.mcap")
	keyBase := filepath.Join(dir, "key")

	buildTestMCAP(t, plainPath)
	require.NoError(t, mcapencrypt.GenerateKeyPair(keyBase))
	require.NoError(t, mcapencrypt.Encrypt(plainPath, encPath, keyBase+".pub.pem"))

	// Second encrypt call with same output must fail.
	err := mcapencrypt.Encrypt(plainPath, encPath, keyBase+".pub.pem")
	require.Error(t, err)
	require.Contains(t, err.Error(), "already exists")

	// After removing the file the call must succeed — this is what --force does.
	require.NoError(t, os.Remove(encPath))
	require.NoError(t, mcapencrypt.Encrypt(plainPath, encPath, keyBase+".pub.pem"))
}

// TestOverwriteDecryptRejectedByLibrary is the decrypt counterpart.
func TestOverwriteDecryptRejectedByLibrary(t *testing.T) {
	dir := t.TempDir()
	plainPath := filepath.Join(dir, "plain.mcap")
	encPath := filepath.Join(dir, "enc.mcap")
	decPath := filepath.Join(dir, "dec.mcap")
	keyBase := filepath.Join(dir, "key")

	buildTestMCAP(t, plainPath)
	require.NoError(t, mcapencrypt.GenerateKeyPair(keyBase))
	require.NoError(t, mcapencrypt.Encrypt(plainPath, encPath, keyBase+".pub.pem"))
	require.NoError(t, mcapencrypt.Decrypt(encPath, decPath, keyBase+".priv.pem"))

	// Second decrypt call with same output must fail.
	err := mcapencrypt.Decrypt(encPath, decPath, keyBase+".priv.pem")
	require.Error(t, err)
	require.Contains(t, err.Error(), "already exists")

	// After removing the file the call must succeed.
	require.NoError(t, os.Remove(decPath))
	require.NoError(t, mcapencrypt.Decrypt(encPath, decPath, keyBase+".priv.pem"))
}

// TestEncryptedChunkOpcodePresent verifies 0x81 records appear in the output.
func TestEncryptedChunkOpcodePresent(t *testing.T) {
	dir := t.TempDir()
	plainPath := filepath.Join(dir, "plain.mcap")
	encPath := filepath.Join(dir, "enc.mcap")
	keyBase := filepath.Join(dir, "key")

	buildTestMCAP(t, plainPath)
	require.NoError(t, mcapencrypt.GenerateKeyPair(keyBase))
	require.NoError(t, mcapencrypt.Encrypt(plainPath, encPath, keyBase+".pub.pem"))

	data, err := os.ReadFile(encPath)
	require.NoError(t, err)
	found := false
	pos := 8
	for pos+9 <= len(data) {
		if data[pos] == 0x81 {
			found = true
			break
		}
		n := int(binary.LittleEndian.Uint64(data[pos+1:]))
		pos += 9 + n
	}
	require.True(t, found, "encrypted file must contain at least one EncryptedChunk (0x81)")
}
