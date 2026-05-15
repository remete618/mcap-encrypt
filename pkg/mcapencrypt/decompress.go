package mcapencrypt

import (
	"bytes"
	"fmt"
	"io"

	"github.com/klauspost/compress/zstd"
	"github.com/pierrec/lz4/v4"
)

func decompressZstd(data []byte) ([]byte, error) {
	r, err := zstd.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("zstd reader: %w", err)
	}
	defer r.Close()
	return io.ReadAll(r)
}

func decompressLz4(data []byte) ([]byte, error) {
	r := lz4.NewReader(bytes.NewReader(data))
	return io.ReadAll(r)
}

func compressZstd(data []byte) ([]byte, error) {
	var buf bytes.Buffer
	w, err := zstd.NewWriter(&buf)
	if err != nil {
		return nil, fmt.Errorf("zstd writer: %w", err)
	}
	if _, err := w.Write(data); err != nil {
		return nil, fmt.Errorf("zstd write: %w", err)
	}
	if err := w.Close(); err != nil {
		return nil, fmt.Errorf("zstd close: %w", err)
	}
	return buf.Bytes(), nil
}
