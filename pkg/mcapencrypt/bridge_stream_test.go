package mcapencrypt_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/foxglove/mcap/go/mcap"
	"github.com/stretchr/testify/require"

	"github.com/remete618/mcap-encrypt/pkg/mcapencrypt"
)

// buildMultiChunkMCAP writes a small MCAP that the encrypt pipeline will
// split into many small encrypted chunks. messagesPerChunk controls the
// approximate granularity. The function returns the LogTime stamps written
// so the caller can pick exact time-range windows.
func buildMultiChunkMCAP(t *testing.T, path string, totalMessages int) []uint64 {
	t.Helper()
	f, err := os.Create(path)
	require.NoError(t, err)
	defer f.Close()

	w, err := mcap.NewWriter(f, &mcap.WriterOptions{
		Chunked: true,
		// Small chunk size so each message tends to land in its own chunk.
		ChunkSize:   64,
		Compression: mcap.CompressionZSTD,
	})
	require.NoError(t, err)
	require.NoError(t, w.WriteHeader(&mcap.Header{Profile: "test"}))
	require.NoError(t, w.WriteSchema(&mcap.Schema{ID: 1, Name: "sensor", Encoding: "json", Data: []byte(`{"type":"object"}`)}))
	require.NoError(t, w.WriteChannel(&mcap.Channel{ID: 1, SchemaID: 1, Topic: "/sensor", MessageEncoding: "json"}))

	stamps := make([]uint64, 0, totalMessages)
	for i := 0; i < totalMessages; i++ {
		ts := uint64(1_000_000_000) + uint64(i)*1_000_000_000 // 1s apart, deterministic
		stamps = append(stamps, ts)
		// Pad the data so each message exceeds the chunk-size threshold,
		// forcing a flush after roughly every message.
		payload := make([]byte, 256)
		for j := range payload {
			payload[j] = byte('a' + (i % 26))
		}
		require.NoError(t, w.WriteMessage(&mcap.Message{
			ChannelID:   1,
			Sequence:    uint32(i),
			LogTime:     ts,
			PublishTime: ts,
			Data:        payload,
		}))
	}
	require.NoError(t, w.Close())
	return stamps
}

// TestStreamingBridgeDecryptsOnlyRequestedChunks proves the streaming
// bridge's central win: iterating a small time window touches only the
// chunks that overlap that window, not the whole file.
func TestStreamingBridgeDecryptsOnlyRequestedChunks(t *testing.T) {
	dir := t.TempDir()
	plainPath := filepath.Join(dir, "plain.mcap")
	encPath := filepath.Join(dir, "encrypted.mcap")
	keyBase := filepath.Join(dir, "testkey")

	buildMultiChunkMCAP(t, plainPath, 30)
	require.NoError(t, mcapencrypt.GenerateKeyPair(keyBase))
	require.NoError(t, mcapencrypt.Encrypt(plainPath, encPath, keyBase+".pub.pem"))

	state, err := mcapencrypt.LoadStreamingBridgeState(encPath, keyBase+".priv.pem")
	require.NoError(t, err)
	defer state.Close()

	chunks := mcapencrypt.StreamingBridgeChunks(state)
	require.GreaterOrEqual(t, len(chunks), 10, "test needs at least 10 chunks; got %d", len(chunks))

	// Load no chunks yet.
	require.Equal(t, uint64(0), state.DecryptCount(), "no chunks should be decrypted at load time")

	// Pick a window that covers exactly chunks 7 and 8 (0-indexed).
	target := chunks[7:9]
	// Window: from the start of target[0] to the end of target[1]. Use
	// boundaries that fall strictly inside neighbouring chunks so we hit
	// only these two.
	winStart := target[0].MessageStartTime
	winEnd := target[1].MessageEndTime

	// Sanity-check the surrounding chunks don't overlap the window.
	if 7 > 0 {
		require.Less(t, chunks[6].MessageEndTime, winStart, "neighbour chunk overlaps window start")
	}
	if 8 < len(chunks)-1 {
		require.Greater(t, chunks[9].MessageStartTime, winEnd, "neighbour chunk overlaps window end")
	}

	got := 0
	require.NoError(t, mcapencrypt.StreamingBridgeIterate(state, winStart, winEnd, func(_ *mcap.Message) error {
		got++
		return nil
	}))
	require.Equal(t, uint64(2), state.DecryptCount(), "exactly 2 chunks should be decrypted for a 2-chunk window")
	require.Greater(t, got, 0, "should have received at least one message in the window")
}

// TestStreamingBridgeFullScanMatchesBatch checks that a full-range iterate
// over the streaming bridge returns the same number of messages as the batch
// load. This catches off-by-one chunk-boundary bugs without re-running
// the round-trip suite.
func TestStreamingBridgeFullScanMatchesBatch(t *testing.T) {
	dir := t.TempDir()
	plainPath := filepath.Join(dir, "plain.mcap")
	encPath := filepath.Join(dir, "encrypted.mcap")
	keyBase := filepath.Join(dir, "testkey")

	buildMultiChunkMCAP(t, plainPath, 20)
	require.NoError(t, mcapencrypt.GenerateKeyPair(keyBase))
	require.NoError(t, mcapencrypt.Encrypt(plainPath, encPath, keyBase+".pub.pem"))

	batch, err := mcapencrypt.LoadBridgeState(encPath, keyBase+".priv.pem")
	require.NoError(t, err)
	batchCount := mcapencrypt.BridgeStateMessageCount(batch)

	state, err := mcapencrypt.LoadStreamingBridgeState(encPath, keyBase+".priv.pem")
	require.NoError(t, err)
	defer state.Close()

	got := 0
	require.NoError(t, mcapencrypt.StreamingBridgeIterate(state, 0, ^uint64(0), func(_ *mcap.Message) error {
		got++
		return nil
	}))
	require.Equal(t, batchCount, got, "streaming iterate count must match batch loader")
}
