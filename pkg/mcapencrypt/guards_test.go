package mcapencrypt

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/binary"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/foxglove/mcap/go/mcap"
	"github.com/stretchr/testify/require"
)

// TestWriteChunkMessagesOversizedInnerRecord verifies that the uint64-safe
// bounds check returns an error instead of allowing integer overflow when a
// crafted inner record claims a length that exceeds the remaining bytes.
func TestWriteChunkMessagesOversizedInnerRecord(t *testing.T) {
	// 9-byte payload: opcode 0x05 + max-uint64 length, 0 bytes of data follow.
	buf := make([]byte, 9)
	buf[0] = 0x05
	binary.LittleEndian.PutUint64(buf[1:], ^uint64(0))

	w, err := mcap.NewWriter(io.Discard, &mcap.WriterOptions{Chunked: false})
	require.NoError(t, err)

	err = writeChunkMessages(buf, "", 0, 0, w)
	require.ErrorContains(t, err, "truncated inner record data")
}

// TestWriteChunkMessagesLengthExceedsRemaining verifies the same guard with a
// realistic overcount: 1 byte of data present but length field says 2.
func TestWriteChunkMessagesLengthExceedsRemaining(t *testing.T) {
	buf := make([]byte, 10) // 9-byte header + 1 byte of data
	buf[0] = 0x05
	binary.LittleEndian.PutUint64(buf[1:], 2) // claims 2 bytes but only 1 follows

	w, err := mcap.NewWriter(io.Discard, &mcap.WriterOptions{Chunked: false})
	require.NoError(t, err)

	err = writeChunkMessages(buf, "", 0, 0, w)
	require.ErrorContains(t, err, "truncated inner record data")
}

// TestWriteChunkMessagesTruncatedHeader verifies that a buffer too short to
// hold a 9-byte inner record header returns the truncated-header error.
func TestWriteChunkMessagesTruncatedHeader(t *testing.T) {
	buf := []byte{0x05, 0x00} // 2 bytes; header needs 9

	w, err := mcap.NewWriter(io.Discard, &mcap.WriterOptions{Chunked: false})
	require.NoError(t, err)

	err = writeChunkMessages(buf, "", 0, 0, w)
	require.ErrorContains(t, err, "truncated inner record header")
}

// TestGenerateKeyPairNoOverwrite verifies that GenerateKeyPair refuses to write
// when either output file already exists, preventing silent key clobber.
func TestGenerateKeyPairNoOverwrite(t *testing.T) {
	t.Run("priv_exists", func(t *testing.T) {
		dir := t.TempDir()
		base := filepath.Join(dir, "key")
		require.NoError(t, os.WriteFile(base+".priv.pem", []byte("dummy"), 0600))

		err := GenerateKeyPair(base)
		require.Error(t, err)
		require.ErrorContains(t, err, "already exists")
		require.ErrorContains(t, err, ".priv.pem")
	})

	t.Run("pub_exists", func(t *testing.T) {
		dir := t.TempDir()
		base := filepath.Join(dir, "key")
		require.NoError(t, os.WriteFile(base+".pub.pem", []byte("dummy"), 0644))

		err := GenerateKeyPair(base)
		require.Error(t, err)
		require.ErrorContains(t, err, "already exists")
		require.ErrorContains(t, err, ".pub.pem")
	})

	t.Run("both_exist", func(t *testing.T) {
		dir := t.TempDir()
		base := filepath.Join(dir, "key")
		require.NoError(t, os.WriteFile(base+".priv.pem", []byte("dummy"), 0600))
		require.NoError(t, os.WriteFile(base+".pub.pem", []byte("dummy"), 0644))

		err := GenerateKeyPair(base)
		require.Error(t, err)
		require.ErrorContains(t, err, "already exists")
	})
}

// TestGenerateX25519KeyPairNoOverwrite verifies that GenerateX25519KeyPair
// refuses to write when either output file already exists.
func TestGenerateX25519KeyPairNoOverwrite(t *testing.T) {
	t.Run("priv_exists", func(t *testing.T) {
		dir := t.TempDir()
		base := filepath.Join(dir, "key")
		require.NoError(t, os.WriteFile(base+".priv.pem", []byte("dummy"), 0600))

		err := GenerateX25519KeyPair(base)
		require.Error(t, err)
		require.ErrorContains(t, err, "already exists")
		require.ErrorContains(t, err, ".priv.pem")
	})

	t.Run("pub_exists", func(t *testing.T) {
		dir := t.TempDir()
		base := filepath.Join(dir, "key")
		require.NoError(t, os.WriteFile(base+".pub.pem", []byte("dummy"), 0644))

		err := GenerateX25519KeyPair(base)
		require.Error(t, err)
		require.ErrorContains(t, err, "already exists")
		require.ErrorContains(t, err, ".pub.pem")
	})

	t.Run("both_exist", func(t *testing.T) {
		dir := t.TempDir()
		base := filepath.Join(dir, "key")
		require.NoError(t, os.WriteFile(base+".priv.pem", []byte("dummy"), 0600))
		require.NoError(t, os.WriteFile(base+".pub.pem", []byte("dummy"), 0644))

		err := GenerateX25519KeyPair(base)
		require.Error(t, err)
		require.ErrorContains(t, err, "already exists")
	})
}

// TestGenerateX25519KeyPairSecondCallRejected performs an actual key generation
// and confirms a second call with the same basename is rejected.
// Uses X25519 (not RSA) so the test stays fast.
func TestGenerateX25519KeyPairSecondCallRejected(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "key")

	require.NoError(t, GenerateX25519KeyPair(base))

	err := GenerateX25519KeyPair(base)
	require.Error(t, err)
	require.ErrorContains(t, err, "already exists")
}

// TestDecryptSkipsZeroSizeChunk verifies that a legitimately encrypted chunk
// with UncompressedSize == 0 is silently skipped by the decrypt loop rather
// than being forwarded to writeChunkMessages with a zero expected size.
// Uses X25519 keys so key generation stays fast.
func TestDecryptSkipsZeroSizeChunk(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "key")
	require.NoError(t, GenerateX25519KeyPair(base))

	privPEM, err := os.ReadFile(base + ".priv.pem")
	require.NoError(t, err)
	pub, err := LoadPublicKeyAny(base + ".pub.pem")
	require.NoError(t, err)

	symKey := make([]byte, 32)
	_, err = rand.Read(symKey)
	require.NoError(t, err)
	defer clear(symKey)

	fileID := make([]byte, fileIDSize)
	_, err = rand.Read(fileID)
	require.NoError(t, err)

	ecdhPub := pub.(*ecdh.PublicKey)
	fingerprint, err := SPKIFingerprint(ecdhPub)
	require.NoError(t, err)
	wrapped, err := WrapSymmetricKeyX25519(symKey, ecdhPub)
	require.NoError(t, err)

	wkd := &WrappedKeyData{
		Version:    wrappedKeyVersion,
		FileID:     fileID,
		KeyID:      fingerprint,
		Algorithm:  "xchacha20poly1305",
		KEKAlg:     "x25519-hkdf-xchacha20poly1305",
		WrappedKey: wrapped,
	}

	// encryptChunk uses chunk.UncompressedSize directly, so passing 0 creates a
	// genuine zero-size encrypted chunk that passes AEAD authentication.
	zeroChunk := &mcap.Chunk{
		MessageStartTime: 100,
		MessageEndTime:   100,
		UncompressedSize: 0,
		UncompressedCRC:  0,
		Compression:      "",
		Records:          nil,
	}
	ec, err := encryptChunk(zeroChunk, symKey, "key-1", fileID, 0)
	require.NoError(t, err)
	require.Equal(t, uint64(0), ec.UncompressedSize)

	// Build manifest: 1 chunk with a valid HMAC so streamDecrypt accepts it.
	var manifest [manifestPayloadSize]byte
	binary.LittleEndian.PutUint64(manifest[:8], 1)
	mac := ComputeManifestHMAC(symKey, 1, fileID)
	copy(manifest[8:], mac)

	// Assemble the complete encrypted MCAP binary in memory.
	var buf bytes.Buffer
	require.NoError(t, WriteMagic(&buf))
	// Header: two empty strings (profile="" library="").
	require.NoError(t, WriteRecord(&buf, opcodeHeader, []byte{0, 0, 0, 0, 0, 0, 0, 0}))
	require.NoError(t, WriteRecord(&buf, opcodeAttach,
		buildAttachmentBytes(0, 0, AttachmentName, AttachmentMediaType, wkd.Encode())))
	require.NoError(t, WriteRecord(&buf, opcodeAttach,
		buildAttachmentBytes(0, 0, ManifestAttachmentName, ManifestAttachmentMediaType, manifest[:])))
	require.NoError(t, WriteRecord(&buf, OpcodeEncryptedChunk, ec.Encode()))
	// Footer signals end of data section; content is unused by streamDecrypt.
	require.NoError(t, WriteRecord(&buf, opcodeFooter, make([]byte, 20)))
	require.NoError(t, WriteMagic(&buf))

	// Decryption must succeed: the zero-size chunk is skipped without error.
	var out bytes.Buffer
	require.NoError(t, DecryptWithOptions(bytes.NewReader(buf.Bytes()), &out, string(privPEM), DecryptOptions{}))
	require.Greater(t, out.Len(), 0, "output MCAP should be non-empty")
}
