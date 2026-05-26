package mcapencrypt_test

import (
	"bytes"
	"encoding/binary"
	"io"
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
		Name:       mcapencrypt.AttachmentName, // same name as key attachment
		MediaType:  "application/octet-stream", // different media type
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

// TestEncryptedFileSummarySection verifies the structural guarantees of an encrypted file:
// summary records (ChunkIndex, Statistics, Schema, Channel) are present and readable
// without a key, no plaintext Message records appear, and EncryptedChunk records are present.
func TestEncryptedFileSummarySection(t *testing.T) {
	dir := t.TempDir()
	plainPath := filepath.Join(dir, "plain.mcap")
	encPath := filepath.Join(dir, "enc.mcap")
	keyBase := filepath.Join(dir, "key")

	buildTestMCAP(t, plainPath)
	require.NoError(t, mcapencrypt.GenerateKeyPair(keyBase))
	require.NoError(t, mcapencrypt.Encrypt(plainPath, encPath, keyBase+".pub.pem"))

	data, err := os.ReadFile(encPath)
	require.NoError(t, err)

	seen := map[byte]bool{}
	pos := 8
	for pos+9 <= len(data) {
		op := data[pos]
		seen[op] = true
		n := int(binary.LittleEndian.Uint64(data[pos+1:]))
		pos += 9 + n
	}

	require.True(t, seen[0x81], "EncryptedChunk (0x81) must be present")
	require.True(t, seen[0x08], "ChunkIndex (0x08) must be present in summary section")
	require.True(t, seen[0x0a], "Statistics (0x0a) must be present in summary section")
	require.True(t, seen[0x03], "Schema (0x03) must be readable without a key")
	require.True(t, seen[0x04], "Channel (0x04) must be readable without a key")
	require.True(t, seen[0x09], "WrappedKeyAttachment (0x09) must be present")
	require.False(t, seen[0x05], "plaintext Message (0x05) must not appear in encrypted file")
}

// TestLZ4InputNormalized verifies that an LZ4-compressed source MCAP is accepted
// and transparently re-compressed to zstd in the encrypted output. Go normalizes
// LZ4 because no pure-JS LZ4 decoder exists, so all encrypted files must use
// compression formats that both Go and TypeScript can decode. The round-trip must
// preserve all messages.
func TestLZ4InputNormalized(t *testing.T) {
	dir := t.TempDir()
	lz4Path := filepath.Join(dir, "lz4.mcap")
	encPath := filepath.Join(dir, "enc.mcap")
	decPath := filepath.Join(dir, "dec.mcap")
	keyBase := filepath.Join(dir, "key")

	f, err := os.Create(lz4Path)
	require.NoError(t, err)
	w, err := mcap.NewWriter(f, &mcap.WriterOptions{
		Chunked:     true,
		ChunkSize:   512,
		Compression: mcap.CompressionLZ4,
	})
	require.NoError(t, err)
	require.NoError(t, w.WriteHeader(&mcap.Header{Profile: "ros2"}))
	require.NoError(t, w.WriteSchema(&mcap.Schema{ID: 1, Name: "s", Encoding: "json", Data: []byte(`{}`)}))
	require.NoError(t, w.WriteChannel(&mcap.Channel{ID: 1, SchemaID: 1, Topic: "/t", MessageEncoding: "json"}))
	for i := range 10 {
		require.NoError(t, w.WriteMessage(&mcap.Message{
			ChannelID: 1,
			LogTime:   uint64(i) * 1_000_000,
			Data:      []byte(`{"v":1}`),
		}))
	}
	require.NoError(t, w.Close())
	f.Close()

	require.NoError(t, mcapencrypt.GenerateKeyPair(keyBase))
	require.NoError(t, mcapencrypt.Encrypt(lz4Path, encPath, keyBase+".pub.pem"))

	// All EncryptedChunks must use "zstd", not "lz4".
	encData, readErr := os.ReadFile(encPath)
	require.NoError(t, readErr)
	pos := 8
	for pos+9 <= len(encData) {
		opcode := encData[pos]
		n := int(binary.LittleEndian.Uint64(encData[pos+1:]))
		if opcode == mcapencrypt.OpcodeEncryptedChunk {
			ec, parseErr := mcapencrypt.DecodeEncryptedChunk(encData[pos+9 : pos+9+n])
			require.NoError(t, parseErr)
			require.Equal(t, "zstd", ec.Compression, "LZ4 input must be normalized to zstd in EncryptedChunk")
		}
		pos += 9 + n
	}

	require.NoError(t, mcapencrypt.Decrypt(encPath, decPath, keyBase+".priv.pem"))
	msgs := readAllMessages(t, decPath)
	require.Len(t, msgs, 10, "all messages must survive LZ4-to-zstd normalization")
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

// buildTestMCAPWithTwoAttachments writes a MCAP with two distinct user attachments.
func buildTestMCAPWithTwoAttachments(t *testing.T, path string) {
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
	p1 := []byte(`{"sensor":"lidar"}`)
	require.NoError(t, w.WriteAttachment(&mcap.Attachment{LogTime: 100, Name: "calibration.json", MediaType: "application/json", DataSize: uint64(len(p1)), Data: bytes.NewReader(p1)}))
	p2 := []byte("firmware v1.2.3")
	require.NoError(t, w.WriteAttachment(&mcap.Attachment{LogTime: 200, Name: "firmware.bin", MediaType: "application/octet-stream", DataSize: uint64(len(p2)), Data: bytes.NewReader(p2)}))
	require.NoError(t, w.Close())
}

// readDecryptedAttachments returns name→data pairs from a standard (decrypted) MCAP.
func readDecryptedAttachments(t *testing.T, path string) map[string][]byte {
	t.Helper()
	f, err := os.Open(path)
	require.NoError(t, err)
	defer f.Close()
	r, err := mcap.NewReader(f)
	require.NoError(t, err)
	info, err := r.Info()
	require.NoError(t, err)
	result := make(map[string][]byte)
	for _, idx := range info.AttachmentIndexes {
		ar, readErr := r.GetAttachmentReader(idx.Offset)
		require.NoError(t, readErr)
		data, readErr := io.ReadAll(ar.Data())
		require.NoError(t, readErr)
		result[idx.Name] = data
	}
	return result
}

// TestEncryptedAttachmentRoundTrip verifies that an attachment's data is
// faithfully preserved through encrypt → decrypt.
func TestEncryptedAttachmentRoundTrip(t *testing.T) {
	dir := t.TempDir()
	plainPath := filepath.Join(dir, "plain.mcap")
	encPath := filepath.Join(dir, "enc.mcap")
	decPath := filepath.Join(dir, "dec.mcap")
	keyBase := filepath.Join(dir, "key")

	buildTestMCAPWithAttachment(t, plainPath)
	require.NoError(t, mcapencrypt.GenerateKeyPair(keyBase))
	require.NoError(t, mcapencrypt.Encrypt(plainPath, encPath, keyBase+".pub.pem"))
	require.NoError(t, mcapencrypt.Decrypt(encPath, decPath, keyBase+".priv.pem"))

	got := readDecryptedAttachments(t, decPath)
	require.Contains(t, got, "config.json")
	require.Equal(t, []byte(`{"k":"v"}`), got["config.json"])
}

// TestMultipleEncryptedAttachmentsRoundTrip verifies all attachments survive
// when a file has more than one.
func TestMultipleEncryptedAttachmentsRoundTrip(t *testing.T) {
	dir := t.TempDir()
	plainPath := filepath.Join(dir, "plain.mcap")
	encPath := filepath.Join(dir, "enc.mcap")
	decPath := filepath.Join(dir, "dec.mcap")
	keyBase := filepath.Join(dir, "key")

	buildTestMCAPWithTwoAttachments(t, plainPath)
	require.NoError(t, mcapencrypt.GenerateKeyPair(keyBase))
	require.NoError(t, mcapencrypt.Encrypt(plainPath, encPath, keyBase+".pub.pem"))
	require.NoError(t, mcapencrypt.Decrypt(encPath, decPath, keyBase+".priv.pem"))

	got := readDecryptedAttachments(t, decPath)
	require.Equal(t, []byte(`{"sensor":"lidar"}`), got["calibration.json"])
	require.Equal(t, []byte("firmware v1.2.3"), got["firmware.bin"])
}

// TestAttachmentDataNotPlaintextInEncryptedFile verifies that attachment data
// is ciphertext in the encrypted file; the raw content must not appear verbatim.
func TestAttachmentDataNotPlaintextInEncryptedFile(t *testing.T) {
	dir := t.TempDir()
	plainPath := filepath.Join(dir, "plain.mcap")
	encPath := filepath.Join(dir, "enc.mcap")
	keyBase := filepath.Join(dir, "key")

	buildTestMCAPWithAttachment(t, plainPath)
	require.NoError(t, mcapencrypt.GenerateKeyPair(keyBase))
	require.NoError(t, mcapencrypt.Encrypt(plainPath, encPath, keyBase+".pub.pem"))

	encData, err := os.ReadFile(encPath)
	require.NoError(t, err)

	// Attachment name is intentionally plaintext (allows enumeration without key).
	require.True(t, bytes.Contains(encData, []byte("config.json")), "attachment name must remain plaintext")
	// Attachment data must not appear verbatim.
	require.False(t, bytes.Contains(encData, []byte(`{"k":"v"}`)), "attachment data must be encrypted")
}

// TestEncryptedAttachmentOpcodePresent verifies 0x82 records appear in the output
// TestEncryptAlreadyEncryptedReturnsError verifies that attempting to encrypt
// an already-encrypted MCAP returns a clear error instead of silently producing
// an output with no user attachments or chunks.
func TestEncryptAlreadyEncryptedReturnsError(t *testing.T) {
	dir := t.TempDir()
	plainPath := filepath.Join(dir, "plain.mcap")
	encPath := filepath.Join(dir, "enc.mcap")
	reencPath := filepath.Join(dir, "reenc.mcap")
	keyBase := filepath.Join(dir, "key")

	buildTestMCAPWithAttachment(t, plainPath)
	require.NoError(t, mcapencrypt.GenerateKeyPair(keyBase))
	require.NoError(t, mcapencrypt.Encrypt(plainPath, encPath, keyBase+".pub.pem"))

	err := mcapencrypt.Encrypt(encPath, reencPath, keyBase+".pub.pem")
	require.Error(t, err)
	require.Contains(t, err.Error(), "already encrypted")
	// The partial output must not be left on disk.
	_, statErr := os.Stat(reencPath)
	require.True(t, os.IsNotExist(statErr), "re-encrypt should not leave output file on disk")
}

// and that no user attachment (0x09 with a non-framework name) is present in plaintext.
func TestEncryptedAttachmentOpcodePresent(t *testing.T) {
	dir := t.TempDir()
	plainPath := filepath.Join(dir, "plain.mcap")
	encPath := filepath.Join(dir, "enc.mcap")
	keyBase := filepath.Join(dir, "key")

	buildTestMCAPWithAttachment(t, plainPath)
	require.NoError(t, mcapencrypt.GenerateKeyPair(keyBase))
	require.NoError(t, mcapencrypt.Encrypt(plainPath, encPath, keyBase+".pub.pem"))

	data, err := os.ReadFile(encPath)
	require.NoError(t, err)

	foundEncAtt := false
	pos := 8
	for pos+9 <= len(data) {
		opcode := data[pos]
		n := int(binary.LittleEndian.Uint64(data[pos+1:]))
		if opcode == mcapencrypt.OpcodeEncryptedAttachment {
			foundEncAtt = true
		}
		pos += 9 + n
	}
	require.True(t, foundEncAtt, "encrypted file must contain at least one EncryptedAttachment (0x82)")
}
