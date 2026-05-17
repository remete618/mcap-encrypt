package mcapencrypt

import (
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
