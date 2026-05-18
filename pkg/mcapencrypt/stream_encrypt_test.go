package mcapencrypt_test

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/foxglove/mcap/go/mcap"
	"github.com/stretchr/testify/require"

	"github.com/remete618/mcap-encrypt/pkg/mcapencrypt"
)

// buildManyChunkMCAP writes an MCAP file with many small chunks to exercise
// multi-chunk round-trips.
func buildManyChunkMCAP(t *testing.T, path string, chunks int) {
	t.Helper()
	f, err := os.Create(path)
	require.NoError(t, err)
	defer f.Close()

	// Small ChunkSize forces many chunks.
	w, err := mcap.NewWriter(f, &mcap.WriterOptions{
		Chunked:     true,
		ChunkSize:   256,
		Compression: mcap.CompressionZSTD,
	})
	require.NoError(t, err)
	require.NoError(t, w.WriteHeader(&mcap.Header{Profile: "test"}))
	require.NoError(t, w.WriteSchema(&mcap.Schema{ID: 1, Name: "msg", Encoding: "json", Data: []byte(`{}`)}))
	require.NoError(t, w.WriteChannel(&mcap.Channel{ID: 1, SchemaID: 1, Topic: "/x", MessageEncoding: "json"}))
	for i := 0; i < chunks; i++ {
		ts := uint64(time.Now().UnixNano()) + uint64(i)*1_000_000
		require.NoError(t, w.WriteMessage(&mcap.Message{
			ChannelID: 1, Sequence: uint32(i),
			LogTime: ts, PublishTime: ts,
			Data: []byte(`{"i":1}`),
		}))
	}
	require.NoError(t, w.Close())
}

func TestStreamEncryptRoundTrip(t *testing.T) {
	dir := t.TempDir()
	plainPath := filepath.Join(dir, "plain.mcap")
	decPath := filepath.Join(dir, "dec.mcap")
	keyBase := filepath.Join(dir, "key")

	buildTestMCAP(t, plainPath)
	require.NoError(t, mcapencrypt.GenerateX25519KeyPair(keyBase))

	pubPEM, err := os.ReadFile(keyBase + ".pub.pem")
	require.NoError(t, err)
	plainBytes, err := os.ReadFile(plainPath)
	require.NoError(t, err)

	var encBuf bytes.Buffer
	require.NoError(t, mcapencrypt.EncryptStream(bytes.NewReader(plainBytes), &encBuf, []string{string(pubPEM)}))
	require.Greater(t, encBuf.Len(), 0)

	encPath := filepath.Join(dir, "enc.mcap")
	require.NoError(t, os.WriteFile(encPath, encBuf.Bytes(), 0644))

	require.NoError(t, mcapencrypt.Decrypt(encPath, decPath, keyBase+".priv.pem"))

	orig := readAllMessages(t, plainPath)
	dec := readAllMessages(t, decPath)
	require.Equal(t, len(orig), len(dec))
	for i, om := range orig {
		dm := dec[i]
		require.Equal(t, om.ChannelID, dm.ChannelID)
		require.Equal(t, om.LogTime, dm.LogTime)
		require.Equal(t, om.Data, dm.Data)
	}
}

func TestStreamEncryptMultiRecipient(t *testing.T) {
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
	require.NoError(t, mcapencrypt.EncryptStream(
		bytes.NewReader(plainBytes), &encBuf,
		[]string{string(pubA), string(pubB)},
	))

	encPath := filepath.Join(dir, "enc.mcap")
	require.NoError(t, os.WriteFile(encPath, encBuf.Bytes(), 0644))

	orig := readAllMessages(t, plainPath)
	for _, keyFile := range []string{keyA, keyB} {
		decPath := keyFile + ".dec.mcap"
		require.NoError(t,
			mcapencrypt.Decrypt(encPath, decPath, keyFile+".priv.pem"),
			"decryption with %s must succeed", filepath.Base(keyFile),
		)
		dec := readAllMessages(t, decPath)
		require.Equal(t, len(orig), len(dec))
	}
}

func TestStreamEncryptLargeFile(t *testing.T) {
	dir := t.TempDir()
	plainPath := filepath.Join(dir, "plain.mcap")
	decPath := filepath.Join(dir, "dec.mcap")
	keyBase := filepath.Join(dir, "key")

	// 200 messages with a 256-byte chunk size produces ~20+ chunks.
	buildManyChunkMCAP(t, plainPath, 200)
	require.NoError(t, mcapencrypt.GenerateX25519KeyPair(keyBase))

	pubPEM, err := os.ReadFile(keyBase + ".pub.pem")
	require.NoError(t, err)
	plainBytes, err := os.ReadFile(plainPath)
	require.NoError(t, err)

	var encBuf bytes.Buffer
	require.NoError(t, mcapencrypt.EncryptStream(bytes.NewReader(plainBytes), &encBuf, []string{string(pubPEM)}))

	encPath := filepath.Join(dir, "enc.mcap")
	require.NoError(t, os.WriteFile(encPath, encBuf.Bytes(), 0644))

	require.NoError(t, mcapencrypt.Decrypt(encPath, decPath, keyBase+".priv.pem"))

	orig := readAllMessages(t, plainPath)
	dec := readAllMessages(t, decPath)
	require.Equal(t, len(orig), len(dec))
	for i, om := range orig {
		require.Equal(t, om.LogTime, dec[i].LogTime)
		require.Equal(t, om.Data, dec[i].Data)
	}
}

// TestStreamEncryptManifestPositionIsAfterDataEnd verifies that in the
// encrypted output the manifest attachment (mcap_encryption_manifest) appears
// after all EncryptedChunk records and after the DataEnd record.
func TestStreamEncryptManifestPositionIsAfterDataEnd(t *testing.T) {
	dir := t.TempDir()
	plainPath := filepath.Join(dir, "plain.mcap")
	keyBase := filepath.Join(dir, "key")

	buildTestMCAP(t, plainPath)
	require.NoError(t, mcapencrypt.GenerateX25519KeyPair(keyBase))

	pubPEM, err := os.ReadFile(keyBase + ".pub.pem")
	require.NoError(t, err)
	plainBytes, err := os.ReadFile(plainPath)
	require.NoError(t, err)

	var encBuf bytes.Buffer
	require.NoError(t, mcapencrypt.EncryptStream(bytes.NewReader(plainBytes), &encBuf, []string{string(pubPEM)}))

	raw := encBuf.Bytes()
	require.GreaterOrEqual(t, len(raw), 8)
	require.Equal(t, "\x89MCAP0\r\n", string(raw[:8]))

	const (
		opcodeAttach      = byte(0x09)
		opcodeDataEnd     = byte(0x0F)
		opcodeEncChunk    = byte(0x81)
		manifestMediaType = "application/x-mcap-manifest"
	)

	type rec struct {
		opcode byte
		offset int
		data   []byte
	}
	var records []rec

	pos := 8
	for pos+9 <= len(raw) {
		opcode := raw[pos]
		length := int(binary.LittleEndian.Uint64(raw[pos+1 : pos+9]))
		if pos+9+length > len(raw) {
			break
		}
		data := raw[pos+9 : pos+9+length]
		records = append(records, rec{opcode, pos, data})
		pos += 9 + length
		if opcode == 0x02 { // Footer
			break
		}
	}

	// Find the positions of last EncryptedChunk, DataEnd, and manifest attachment.
	lastChunkIdx := -1
	dataEndIdx := -1
	manifestIdx := -1

	for i, r := range records {
		switch r.opcode {
		case opcodeEncChunk:
			lastChunkIdx = i
		case opcodeDataEnd:
			dataEndIdx = i
		case opcodeAttach:
			// Parse enough to check media type.
			d := r.data
			if len(d) < 20 {
				continue
			}
			off := 16 // skip log_time + create_time
			readStr := func() string {
				if off+4 > len(d) {
					return ""
				}
				n := int(binary.LittleEndian.Uint32(d[off:]))
				off += 4
				if off+n > len(d) {
					return ""
				}
				s := string(d[off : off+n])
				off += n
				return s
			}
			_ = readStr() // name
			mt := readStr()
			if mt == manifestMediaType {
				manifestIdx = i
			}
		}
	}

	require.Greater(t, lastChunkIdx, 0, "must have at least one EncryptedChunk")
	require.Greater(t, dataEndIdx, lastChunkIdx, "DataEnd must appear after last EncryptedChunk")
	require.Greater(t, manifestIdx, dataEndIdx, "manifest must appear after DataEnd")
}

func TestStreamEncryptNoTempFiles(t *testing.T) {
	dir := t.TempDir()
	plainPath := filepath.Join(dir, "plain.mcap")
	keyBase := filepath.Join(dir, "key")

	buildTestMCAP(t, plainPath)
	require.NoError(t, mcapencrypt.GenerateX25519KeyPair(keyBase))

	pubPEM, err := os.ReadFile(keyBase + ".pub.pem")
	require.NoError(t, err)
	plainBytes, err := os.ReadFile(plainPath)
	require.NoError(t, err)

	tmpDir := os.TempDir()
	before, err := os.ReadDir(tmpDir)
	require.NoError(t, err)

	var encBuf bytes.Buffer
	require.NoError(t, mcapencrypt.EncryptStream(bytes.NewReader(plainBytes), &encBuf, []string{string(pubPEM)}))

	after, err := os.ReadDir(tmpDir)
	require.NoError(t, err)
	require.Equal(t, len(before), len(after), "EncryptStream must not leave temp files behind")
}
