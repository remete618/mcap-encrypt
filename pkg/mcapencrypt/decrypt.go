package mcapencrypt

import (
	"bytes"
	"crypto/rsa"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"path/filepath"

	"golang.org/x/crypto/chacha20poly1305"

	"github.com/foxglove/mcap/go/mcap"
)

// Decrypt reads an encrypted MCAP file and writes a standard, indexed MCAP file.
// Decryption is single-pass: the wrapped key attachment appears before the first
// encrypted chunk so each chunk is decrypted immediately as it is read.
// inputPath and outputPath must differ.
func Decrypt(inputPath, outputPath, privKeyPath string) (retErr error) {
	absIn, err := filepath.Abs(inputPath)
	if err != nil {
		return fmt.Errorf("resolve input path: %w", err)
	}
	absOut, err := filepath.Abs(outputPath)
	if err != nil {
		return fmt.Errorf("resolve output path: %w", err)
	}
	if absIn == absOut {
		return fmt.Errorf("inputPath and outputPath must differ")
	}

	priv, err := LoadPrivateKey(privKeyPath)
	if err != nil {
		return fmt.Errorf("load private key: %w", err)
	}

	inFile, err := os.Open(inputPath)
	if err != nil {
		return fmt.Errorf("open input: %w", err)
	}
	defer inFile.Close()

	outFile, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("create output: %w", err)
	}
	defer func() {
		if err := outFile.Close(); err != nil && retErr == nil {
			retErr = fmt.Errorf("close output: %w", err)
		}
		if retErr != nil {
			os.Remove(outputPath)
		}
	}()

	return streamDecrypt(inFile, outFile, priv)
}

// streamDecrypt performs a single-pass decrypt: schemas and channels are
// buffered (they are small and appear before the first chunk), the wrapped key
// is parsed when its attachment is encountered, and each EncryptedChunk is
// decrypted and written immediately without buffering all chunks.
func streamDecrypt(r io.Reader, w io.Writer, priv *rsa.PrivateKey) error {
	if err := ReadMagic(r); err != nil {
		return fmt.Errorf("read magic: %w", err)
	}

	var (
		symKey   []byte
		wkaCount int // number of wrapped-key attachments found
		schemas  []*mcap.Schema
		channels []*mcap.Channel
		writer   *mcap.Writer
	)

	// ensureWriter initialises the McapWriter on first EncryptedChunk, writing
	// all buffered schemas and channels before any messages.
	ensureWriter := func() error {
		if writer != nil {
			return nil
		}
		var err error
		writer, err = mcap.NewWriter(w, &mcap.WriterOptions{
			Chunked:     true,
			ChunkSize:   4 * 1024 * 1024,
			Compression: mcap.CompressionZSTD,
			IncludeCRC:  true,
		})
		if err != nil {
			return fmt.Errorf("create writer: %w", err)
		}
		if err := writer.WriteHeader(&mcap.Header{Profile: ""}); err != nil {
			return err
		}
		for _, s := range schemas {
			if err := writer.WriteSchema(s); err != nil {
				return err
			}
		}
		for _, c := range channels {
			if err := writer.WriteChannel(c); err != nil {
				return err
			}
		}
		return nil
	}

scan:
	for {
		var opcode byte
		var data []byte
		var err error
		opcode, data, err = ReadRecord(r)
		if err != nil {
			if errors.Is(err, io.EOF) {
				err = nil
				break
			}
			return err
		}

		switch opcode {
		case opcodeSchema:
			s, parseErr := mcap.ParseSchema(data)
			if parseErr != nil {
				return fmt.Errorf("parse schema: %w", parseErr)
			}
			schemas = append(schemas, s)

		case opcodeChannel:
			c, parseErr := mcap.ParseChannel(data)
			if parseErr != nil {
				return fmt.Errorf("parse channel: %w", parseErr)
			}
			channels = append(channels, c)

		case opcodeAttach:
			name, mediaType, attData, parseErr := parseAttachmentRecord(data)
			if parseErr != nil {
				return fmt.Errorf("parse attachment: %w", parseErr)
			}
			if name != AttachmentName || mediaType != AttachmentMediaType {
				continue
			}
			wkaCount++
			if symKey != nil {
				continue // already found a valid key
			}
			wkd, decErr := DecodeWrappedKeyData(attData)
			if decErr != nil {
				continue // malformed attachment; try the next one
			}
			candidate, unwrapErr := UnwrapSymmetricKey(wkd.WrappedKey, priv)
			if unwrapErr != nil {
				continue // wrong recipient; try the next attachment
			}
			if len(candidate) != 32 {
				continue // unexpected sym key length; skip
			}
			symKey = candidate

		case OpcodeEncryptedChunk:
			if symKey == nil {
				return fmt.Errorf("encountered encrypted chunk before wrapped key attachment")
			}
			if err := ensureWriter(); err != nil {
				return err
			}
			ec, decErr := DecodeEncryptedChunk(data)
			if decErr != nil {
				return fmt.Errorf("decode encrypted chunk: %w", decErr)
			}
			if len(ec.Nonce) != chacha20poly1305.NonceSizeX {
				return fmt.Errorf("chunk [%d–%d]: nonce length %d invalid (want %d)",
					ec.MessageStartTime, ec.MessageEndTime, len(ec.Nonce), chacha20poly1305.NonceSizeX)
			}
			if len(ec.EncryptedData) < 16 {
				return fmt.Errorf("chunk [%d–%d]: ciphertext too short (%d bytes, minimum 16)",
					ec.MessageStartTime, ec.MessageEndTime, len(ec.EncryptedData))
			}
			aead, cipherErr := chacha20poly1305.NewX(symKey)
			if cipherErr != nil {
				return fmt.Errorf("create cipher: %w", cipherErr)
			}
			aad := chunkAAD(ec.MessageStartTime, ec.MessageEndTime)
			plaintext, openErr := aead.Open(nil, ec.Nonce, ec.EncryptedData, aad)
			if openErr != nil {
				return fmt.Errorf("decrypt chunk [%d–%d]: %w", ec.MessageStartTime, ec.MessageEndTime, openErr)
			}
			msgs, parseErr := parseChunkRecords(plaintext, ec.Compression, ec.UncompressedCRC)
			if parseErr != nil {
				return fmt.Errorf("parse decrypted chunk: %w", parseErr)
			}
			for _, msg := range msgs {
				if writeErr := writer.WriteMessage(msg); writeErr != nil {
					return fmt.Errorf("write message: %w", writeErr)
				}
			}

		case opcodeFooter:
			break scan

		// Ignore header, data-end, and any index records.
		}
	}

	if symKey == nil {
		if wkaCount == 0 {
			return fmt.Errorf("no wrapped key attachment found: is this an encrypted MCAP file?")
		}
		return fmt.Errorf("private key does not match any of the %d recipient key(s) in this file", wkaCount)
	}
	if err := ensureWriter(); err != nil {
		return err
	}
	return writer.Close()
}

// parseAttachmentRecord extracts name, mediaType, and data from raw Attachment record bytes.
func parseAttachmentRecord(data []byte) (name, mediaType string, attData []byte, err error) {
	if len(data) < 20 {
		return "", "", nil, fmt.Errorf("attachment record too short")
	}
	o := 16 // skip log_time (8) + create_time (8)

	readStr := func() (string, error) {
		if o+4 > len(data) {
			return "", fmt.Errorf("truncated reading string length")
		}
		n := int(binary.LittleEndian.Uint32(data[o:]))
		o += 4
		if o+n > len(data) {
			return "", fmt.Errorf("truncated reading string data")
		}
		s := string(data[o : o+n])
		o += n
		return s, nil
	}

	name, err = readStr()
	if err != nil {
		return
	}
	mediaType, err = readStr()
	if err != nil {
		return
	}
	if o+8 > len(data) {
		return "", "", nil, fmt.Errorf("truncated before data_size")
	}
	dataSize := int(binary.LittleEndian.Uint64(data[o:]))
	o += 8
	if o+dataSize > len(data) {
		return "", "", nil, fmt.Errorf("truncated in data field")
	}
	attData = data[o : o+dataSize]
	return
}

// parseChunkRecords decompresses chunk data and extracts Message records.
func parseChunkRecords(compressed []byte, compression string, expectedCRC uint32) ([]*mcap.Message, error) {
	decompressed, err := decompressChunkData(compressed, compression)
	if err != nil {
		return nil, fmt.Errorf("decompress: %w", err)
	}

	if expectedCRC != 0 {
		if got := crc32.ChecksumIEEE(decompressed); got != expectedCRC {
			return nil, fmt.Errorf("CRC mismatch: got %#08x, want %#08x", got, expectedCRC)
		}
	}

	var msgs []*mcap.Message
	r := bytes.NewReader(decompressed)
	for r.Len() > 0 {
		var hdr [9]byte
		if _, err := io.ReadFull(r, hdr[:]); err != nil {
			return nil, fmt.Errorf("read inner record header: %w", err)
		}
		innerOpcode := hdr[0]
		length := binary.LittleEndian.Uint64(hdr[1:])

		innerData := make([]byte, length)
		if _, err := io.ReadFull(r, innerData); err != nil {
			return nil, fmt.Errorf("read inner record data: %w", err)
		}

		if innerOpcode != 0x05 {
			continue
		}
		msg, parseErr := mcap.ParseMessage(innerData)
		if parseErr != nil {
			return nil, fmt.Errorf("parse message: %w", parseErr)
		}
		msgs = append(msgs, msg)
	}
	return msgs, nil
}

func decompressChunkData(data []byte, compression string) ([]byte, error) {
	switch compression {
	case "", "none":
		return data, nil
	case "zstd":
		return decompressZstd(data)
	case "lz4":
		return decompressLz4(data)
	default:
		return nil, fmt.Errorf("unsupported compression %q", compression)
	}
}
