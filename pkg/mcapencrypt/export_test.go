package mcapencrypt

import "github.com/foxglove/mcap/go/mcap"

// ChunkIndexEntryView is the test-visible projection of chunkIndexEntry.
// It must stay in this _test.go file so the public surface does not gain a
// field of internal-only fields.
type ChunkIndexEntryView struct {
	ChunkIdx         uint64
	MessageStartTime uint64
	MessageEndTime   uint64
}

// StreamingBridgeChunks returns a snapshot of the streaming bridge's chunk
// index. Test-only.
func StreamingBridgeChunks(s *StreamingBridgeState) []ChunkIndexEntryView {
	out := make([]ChunkIndexEntryView, len(s.chunks))
	for i, c := range s.chunks {
		out[i] = ChunkIndexEntryView{
			ChunkIdx:         c.chunkIdx,
			MessageStartTime: c.messageStartTime,
			MessageEndTime:   c.messageEndTime,
		}
	}
	return out
}

// StreamingBridgeIterate invokes iterateMessages on a streaming bridge so
// tests can verify the on-demand decrypt path without going through the
// WebSocket layer.
func StreamingBridgeIterate(s *StreamingBridgeState, fromNanos, toNanos uint64, yield func(*mcap.Message) error) error {
	return s.iterateMessages(fromNanos, toNanos, yield)
}

// BridgeStateMessageCount returns the number of messages loaded into the
// batch bridge state. Test-only.
func BridgeStateMessageCount(s *BridgeState) int {
	return len(s.messages)
}
