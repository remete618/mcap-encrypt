package mcapencrypt

import (
	"bytes"
	"fmt"
	"io"
	"sync"

	"github.com/klauspost/compress/zstd"
	"github.com/pierrec/lz4/v4"
)

// zstdDecoderPool reuses decoders across calls. zstd.Decoder is not goroutine-safe,
// but sync.Pool gives each caller its own instance, so this is safe.
var zstdDecoderPool = sync.Pool{
	New: func() any {
		d, err := zstd.NewReader(nil)
		if err != nil {
			// NewReader only fails on option errors; nil options never fail.
			panic("zstd.NewReader: " + err.Error())
		}
		return d
	},
}

// zstdEncoderPool reuses encoders across calls. Used only for the LZ4→zstd
// normalization path; the hot encrypt path uses mcap.Writer's built-in encoder.
var zstdEncoderPool = sync.Pool{
	New: func() any {
		e, err := zstd.NewWriter(nil)
		if err != nil {
			panic("zstd.NewWriter: " + err.Error())
		}
		return e
	},
}

func decompressZstd(data []byte) ([]byte, error) {
	d := zstdDecoderPool.Get().(*zstd.Decoder)
	defer zstdDecoderPool.Put(d)
	if err := d.Reset(bytes.NewReader(data)); err != nil {
		return nil, fmt.Errorf("zstd reset: %w", err)
	}
	out, err := io.ReadAll(d)
	if err != nil {
		return nil, fmt.Errorf("zstd decompress: %w", err)
	}
	return out, nil
}

func decompressLz4(data []byte) ([]byte, error) {
	r := lz4.NewReader(bytes.NewReader(data))
	return io.ReadAll(r)
}

func compressZstd(data []byte) ([]byte, error) {
	e := zstdEncoderPool.Get().(*zstd.Encoder)
	var buf bytes.Buffer
	e.Reset(&buf)
	_, writeErr := e.Write(data)
	closeErr := e.Close()
	// Always return to pool; Reset() on next use reinitialises state regardless.
	zstdEncoderPool.Put(e)
	if writeErr != nil {
		return nil, fmt.Errorf("zstd write: %w", writeErr)
	}
	if closeErr != nil {
		return nil, fmt.Errorf("zstd close: %w", closeErr)
	}
	return buf.Bytes(), nil
}
