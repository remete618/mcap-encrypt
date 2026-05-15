package mcapencrypt

import (
	"bytes"
	"crypto/rsa"
	"encoding/binary"
	"fmt"
	"io"
	"os"

	"golang.org/x/crypto/chacha20poly1305"

	"github.com/foxglove/mcap/go/mcap"
)

// Decrypt reads an encrypted MCAP file and writes a standard MCAP file.
func Decrypt(inputPath, outputPath, privKeyPath string) error {
	priv, err := LoadPrivateKey(privKeyPath)
	if err != nil {
		return fmt.Errorf("load private key: %w", err)
	}

	inFile, err := os.Open(inputPath)
	if err != nil {
		return fmt.Errorf("open input: %w", err)
	}
	defer inFile.Close()

	symKey, schemas, channels, encChunks, scanErr := scanEncryptedFile(inFile, priv)
	if scanErr != nil {
		return fmt.Errorf("scan: %w", scanErr)
	}

	outFile, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("create output: %w", err)
	}
	defer outFile.Close()

	writer, err := mcap.NewWriter(outFile, &mcap.WriterOptions{
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

	aead, err := chacha20poly1305.NewX(symKey)
	if err != nil {
		return fmt.Errorf("create cipher: %w", err)
	}

	for _, ec := range encChunks {
		plaintext, decErr := aead.Open(nil, ec.Nonce, ec.EncryptedData, nil)
		if decErr != nil {
			return fmt.Errorf("decrypt chunk: %w", decErr)
		}

		msgs, parseErr := parseChunkRecords(plaintext, ec.Compression)
		if parseErr != nil {
			return fmt.Errorf("parse decrypted chunk: %w", parseErr)
		}
		for _, msg := range msgs {
			if writeErr := writer.WriteMessage(msg); writeErr != nil {
				return fmt.Errorf("write message: %w", writeErr)
			}
		}
	}

	return writer.Close()
}

// scanEncryptedFile does a single linear pass over an encrypted MCAP file.
// It returns the unwrapped symmetric key, plaintext schemas/channels, and all
// EncryptedChunk records. The file must not require random access.
func scanEncryptedFile(r io.Reader, priv *rsa.PrivateKey) (
	symKey []byte,
	schemas []*mcap.Schema,
	channels []*mcap.Channel,
	encChunks []*EncryptedChunk,
	err error,
) {
	if err = ReadMagic(r); err != nil {
		return
	}

scan:
	for {
		var opcode byte
		var data []byte
		opcode, data, err = ReadRecord(r)
		if err != nil {
			if err == io.EOF {
				err = nil
				break
			}
			return
		}

		switch opcode {
		case opcodeSchema:
			s, parseErr := mcap.ParseSchema(data)
			if parseErr != nil {
				err = fmt.Errorf("parse schema: %w", parseErr)
				return
			}
			schemas = append(schemas, s)

		case opcodeChannel:
			c, parseErr := mcap.ParseChannel(data)
			if parseErr != nil {
				err = fmt.Errorf("parse channel: %w", parseErr)
				return
			}
			channels = append(channels, c)

		case opcodeAttach:
			name, mediaType, attData, parseErr := parseAttachmentRecord(data)
			if parseErr != nil {
				err = fmt.Errorf("parse attachment: %w", parseErr)
				return
			}
			if name != AttachmentName || mediaType != AttachmentMediaType {
				continue
			}
			wkd, decErr := DecodeWrappedKeyData(attData)
			if decErr != nil {
				err = fmt.Errorf("decode wrapped key: %w", decErr)
				return
			}
			symKey, err = UnwrapSymmetricKey(wkd.WrappedKey, priv)
			if err != nil {
				err = fmt.Errorf("unwrap symmetric key: %w", err)
				return
			}

		case OpcodeEncryptedChunk:
			ec, decErr := DecodeEncryptedChunk(data)
			if decErr != nil {
				err = fmt.Errorf("decode encrypted chunk: %w", decErr)
				return
			}
			encChunks = append(encChunks, ec)

		case opcodeFooter:
			break scan
		}
	}

	if symKey == nil {
		err = fmt.Errorf("no wrapped key attachment found in file")
	}
	return
}

// parseAttachmentRecord extracts name, mediaType, and data from raw Attachment record bytes.
func parseAttachmentRecord(data []byte) (name, mediaType string, attData []byte, err error) {
	if len(data) < 20 {
		return "", "", nil, fmt.Errorf("attachment record too short")
	}
	o := 0
	o += 8 // log_time
	o += 8 // create_time

	readStr := func() (string, error) {
		if o+4 > len(data) {
			return "", fmt.Errorf("truncated")
		}
		n := int(binary.LittleEndian.Uint32(data[o:]))
		o += 4
		if o+n > len(data) {
			return "", fmt.Errorf("truncated")
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

// parseChunkRecords decompresses chunk data and parses the Message records within.
func parseChunkRecords(compressed []byte, compression string) ([]*mcap.Message, error) {
	decompressed, err := decompressChunkData(compressed, compression)
	if err != nil {
		return nil, fmt.Errorf("decompress: %w", err)
	}

	// The decompressed bytes are a sequence of raw MCAP records.
	// We only extract Message records (opcode 0x05); Schema/Channel inside chunks
	// are already handled from the plaintext section of the file.
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
		// Use the zstd reader from the MCAP library's transitive dependency.
		// We import it directly since it's already in go.sum.
		return decompressZstd(data)
	case "lz4":
		return decompressLz4(data)
	default:
		return nil, fmt.Errorf("unsupported compression: %s", compression)
	}
}
