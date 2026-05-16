package mcapencrypt_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/foxglove/mcap/go/mcap"
	"github.com/stretchr/testify/require"

	"github.com/remete618/mcap-encrypt/pkg/mcapencrypt"
)

// buildBenchMCAP creates a temporary MCAP file with msgCount messages of msgSize bytes each.
// Returns the path and the total payload size in bytes.
func buildBenchMCAP(b *testing.B, dir string, msgCount int, msgSize int) (path string, totalBytes int64) {
	b.Helper()
	path = filepath.Join(dir, "bench.mcap")
	f, err := os.Create(path)
	require.NoError(b, err)
	defer f.Close()

	w, err := mcap.NewWriter(f, &mcap.WriterOptions{
		Chunked:     true,
		ChunkSize:   4 * 1024 * 1024,
		Compression: mcap.CompressionZSTD,
	})
	require.NoError(b, err)
	require.NoError(b, w.WriteHeader(&mcap.Header{Profile: "bench"}))
	require.NoError(b, w.WriteSchema(&mcap.Schema{ID: 1, Name: "point", Encoding: "raw", Data: []byte("x:f64,y:f64,z:f64")}))
	require.NoError(b, w.WriteChannel(&mcap.Channel{ID: 1, SchemaID: 1, Topic: "/lidar", MessageEncoding: "raw"}))

	payload := make([]byte, msgSize)
	for i := range payload {
		payload[i] = byte(i)
	}
	for i := 0; i < msgCount; i++ {
		ts := uint64(time.Now().UnixNano()) + uint64(i)*1_000_000
		require.NoError(b, w.WriteMessage(&mcap.Message{
			ChannelID:   1,
			Sequence:    uint32(i),
			LogTime:     ts,
			PublishTime: ts,
			Data:        payload,
		}))
	}
	require.NoError(b, w.Close())

	info, err := os.Stat(path)
	require.NoError(b, err)
	return path, info.Size()
}

func benchmarkEncrypt(b *testing.B, msgCount, msgSize int) {
	b.Helper()
	dir := b.TempDir()
	inputPath, fileBytes := buildBenchMCAP(b, dir, msgCount, msgSize)
	outputPath := filepath.Join(dir, "enc.mcap")

	keyBase := filepath.Join(dir, "key")
	require.NoError(b, mcapencrypt.GenerateKeyPair(keyBase))
	pubKey := keyBase + ".pub.pem"

	b.SetBytes(fileBytes)
	b.ResetTimer()
	for range b.N {
		os.Remove(outputPath)
		if err := mcapencrypt.Encrypt(inputPath, outputPath, pubKey); err != nil {
			b.Fatal(err)
		}
	}
}

func benchmarkDecrypt(b *testing.B, msgCount, msgSize int) {
	b.Helper()
	dir := b.TempDir()
	inputPath, _ := buildBenchMCAP(b, dir, msgCount, msgSize)
	encPath := filepath.Join(dir, "enc.mcap")
	decPath := filepath.Join(dir, "dec.mcap")

	keyBase := filepath.Join(dir, "key")
	require.NoError(b, mcapencrypt.GenerateKeyPair(keyBase))
	require.NoError(b, mcapencrypt.Encrypt(inputPath, encPath, keyBase+".pub.pem"))

	encInfo, err := os.Stat(encPath)
	require.NoError(b, err)
	privKey := keyBase + ".priv.pem"

	b.SetBytes(encInfo.Size())
	b.ResetTimer()
	for range b.N {
		os.Remove(decPath)
		if err := mcapencrypt.Decrypt(encPath, decPath, privKey); err != nil {
			b.Fatal(err)
		}
	}
}

// Small: 100 messages × 1 KB  (~100 KB file)
func BenchmarkEncryptSmall(b *testing.B) { benchmarkEncrypt(b, 100, 1024) }
func BenchmarkDecryptSmall(b *testing.B) { benchmarkDecrypt(b, 100, 1024) }

// Medium: 1 000 messages × 4 KB  (~4 MB file)
func BenchmarkEncryptMedium(b *testing.B) { benchmarkEncrypt(b, 1000, 4096) }
func BenchmarkDecryptMedium(b *testing.B) { benchmarkDecrypt(b, 1000, 4096) }

// Large: 5 000 messages × 64 KB  (~320 MB file)
func BenchmarkEncryptLarge(b *testing.B) { benchmarkEncrypt(b, 5000, 65536) }
func BenchmarkDecryptLarge(b *testing.B) { benchmarkDecrypt(b, 5000, 65536) }
