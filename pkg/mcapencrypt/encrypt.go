package mcapencrypt

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/crypto/chacha20poly1305"

	"github.com/foxglove/mcap/go/mcap"
)

// Encrypt reads a standard MCAP file and writes an encrypted MCAP file.
// Each chunk is encrypted with XChaCha20Poly1305. The symmetric key is
// wrapped with the RSA-2048 public key and stored as an Attachment named
// "mcap_encryption_key", placed before the first encrypted chunk to enable
// single-pass streaming decryption.
//
// Constraints:
//   - Input must be a chunked MCAP. Non-chunked files are rejected.
//   - inputPath and outputPath must differ.
func Encrypt(inputPath, outputPath, pubKeyPath string) (retErr error) {
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

	pub, err := LoadPublicKey(pubKeyPath)
	if err != nil {
		return fmt.Errorf("load public key: %w", err)
	}

	symKey := make([]byte, chacha20poly1305.KeySize)
	if _, err := rand.Read(symKey); err != nil {
		return fmt.Errorf("generate symmetric key: %w", err)
	}

	wrapped, err := WrapSymmetricKey(symKey, pub)
	if err != nil {
		return fmt.Errorf("wrap symmetric key: %w", err)
	}

	const keyID = "key-1"
	wkd := &WrappedKeyData{
		KeyID:      keyID,
		Algorithm:  "xchacha20poly1305",
		KEKAlg:     "rsa-oaep-sha256",
		WrappedKey: wrapped,
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

	if err := WriteMagic(outFile); err != nil {
		return err
	}

	// First pass: collect schema and channel records to write as plaintext.
	// mcap.Writer places schemas/channels inside the first chunk; with
	// EmitChunks=true the lexer only exposes summary-section copies (after
	// DataEnd), which is too late to place before the first encrypted chunk.
	// A quick default-mode scan captures them from the chunk contents.
	type pendingRecord struct{ opcode byte; data []byte }
	var pending []pendingRecord

	{
		scanFile, scanErr := os.Open(inputPath)
		if scanErr != nil {
			return fmt.Errorf("open input for schema scan: %w", scanErr)
		}
		defer scanFile.Close()
		scanLexer, scanErr := mcap.NewLexer(scanFile)
		if scanErr != nil {
			return fmt.Errorf("create schema scan lexer: %w", scanErr)
		}
		seenSchemas := make(map[uint16]bool)
		seenChannels := make(map[uint16]bool)
		var scanBuf []byte
		for {
			tok, scanData, lexErr := scanLexer.Next(scanBuf)
			if lexErr != nil {
				break
			}
			scanBuf = scanData
			switch tok {
			case mcap.TokenSchema:
				s, parseErr := mcap.ParseSchema(scanData)
				if parseErr != nil || seenSchemas[s.ID] {
					continue
				}
				seenSchemas[s.ID] = true
				cp := make([]byte, len(scanData))
				copy(cp, scanData)
				pending = append(pending, pendingRecord{passthroughOpcode[mcap.TokenSchema], cp})
			case mcap.TokenChannel:
				c, parseErr := mcap.ParseChannel(scanData)
				if parseErr != nil || seenChannels[c.ID] {
					continue
				}
				seenChannels[c.ID] = true
				cp := make([]byte, len(scanData))
				copy(cp, scanData)
				pending = append(pending, pendingRecord{passthroughOpcode[mcap.TokenChannel], cp})
			}
		}
	}

	flushed := false
	flushPending := func() error {
		if flushed {
			return nil
		}
		flushed = true
		for _, r := range pending {
			if err := WriteRecord(outFile, r.opcode, r.data); err != nil {
				return err
			}
		}
		// Write the wrapped key attachment before the first encrypted chunk.
		return writeAttachmentRecord(
			outFile,
			uint64(time.Now().UnixNano()), 0,
			AttachmentName, AttachmentMediaType,
			wkd.Encode(),
		)
	}

	lexer, err := mcap.NewLexer(inFile, &mcap.LexerOptions{
		EmitChunks: true,
		AttachmentCallback: func(ar *mcap.AttachmentReader) error {
			data, readErr := io.ReadAll(ar.Data())
			if readErr != nil {
				return readErr
			}
			return writeAttachmentRecord(outFile, ar.LogTime, ar.CreateTime, ar.Name, ar.MediaType, data)
		},
	})
	if err != nil {
		return fmt.Errorf("create lexer: %w", err)
	}

	var tokenBuf []byte
	for {
		tok, data, lexErr := lexer.Next(tokenBuf)
		if lexErr != nil {
			if errors.Is(lexErr, io.EOF) {
				break
			}
			return fmt.Errorf("lexer: %w", lexErr)
		}
		tokenBuf = data

		switch tok {

		case mcap.TokenMessage:
			return fmt.Errorf("input MCAP is not chunked: raw Message records found outside chunks; " +
				"re-encode with chunking enabled before encrypting")

		case mcap.TokenHeader:
			op, ok := passthroughOpcode[tok]
			if !ok {
				return fmt.Errorf("unhandled token type %v", tok)
			}
			if writeErr := WriteRecord(outFile, op, data); writeErr != nil {
				return writeErr
			}

		case mcap.TokenSchema, mcap.TokenChannel:
			// Already collected in the first pass; skip summary-section duplicates.

		case mcap.TokenMetadata:
			if flushErr := flushPending(); flushErr != nil {
				return flushErr
			}
			op, ok := passthroughOpcode[tok]
			if !ok {
				return fmt.Errorf("unhandled token type %v", tok)
			}
			if writeErr := WriteRecord(outFile, op, data); writeErr != nil {
				return writeErr
			}

		case mcap.TokenChunk:
			if flushErr := flushPending(); flushErr != nil {
				return flushErr
			}
			chunk, parseErr := mcap.ParseChunk(data)
			if parseErr != nil {
				return fmt.Errorf("parse chunk: %w", parseErr)
			}
			enc, encErr := encryptChunk(chunk, symKey, keyID)
			if encErr != nil {
				return fmt.Errorf("encrypt chunk: %w", encErr)
			}
			if writeErr := WriteRecord(outFile, OpcodeEncryptedChunk, enc.Encode()); writeErr != nil {
				return writeErr
			}

		case mcap.TokenDataEnd:
			// Flush in case there were no chunks (schema/channel-only file).
			if flushErr := flushPending(); flushErr != nil {
				return flushErr
			}
			if writeErr := WriteRecord(outFile, opcodeDataEnd, data); writeErr != nil {
				return writeErr
			}

		case mcap.TokenFooter:
			if writeErr := WriteRecord(outFile, opcodeFooter, emptyFooter); writeErr != nil {
				return writeErr
			}

		case mcap.TokenMessageIndex, mcap.TokenChunkIndex,
			mcap.TokenStatistics, mcap.TokenSummaryOffset,
			mcap.TokenAttachmentIndex, mcap.TokenMetadataIndex:
			// Drop: all index/offset records reference byte positions in the
			// original file that are invalid after chunk replacement.

		default:
			return fmt.Errorf("unhandled token type %v", tok)
		}
	}

	return WriteMagic(outFile)
}

// passthroughOpcode maps token types that are written verbatim to their opcodes.
var passthroughOpcode = map[mcap.TokenType]byte{
	mcap.TokenHeader:   0x01,
	mcap.TokenSchema:   0x03,
	mcap.TokenChannel:  0x04,
	mcap.TokenMetadata: 0x0C,
}

// chunkAAD encodes chunk time bounds as AEAD additional data (16 bytes).
// Binding this prevents ciphertext chunks from being swapped between files.
func chunkAAD(startTime, endTime uint64) []byte {
	aad := make([]byte, 16)
	binary.LittleEndian.PutUint64(aad[0:], startTime)
	binary.LittleEndian.PutUint64(aad[8:], endTime)
	return aad
}

func encryptChunk(chunk *mcap.Chunk, symKey []byte, keyID string) (*EncryptedChunk, error) {
	records := chunk.Records
	compression := string(chunk.Compression)

	// Normalize LZ4 to zstd: no pure-JS LZ4 exists, so all encrypted files
	// must use a compression format that both Go and TypeScript can decode.
	if compression == "lz4" {
		decompressed, err := decompressLz4(records)
		if err != nil {
			return nil, fmt.Errorf("decompress lz4 for normalization: %w", err)
		}
		recompressed, err := compressZstd(decompressed)
		if err != nil {
			return nil, fmt.Errorf("recompress as zstd: %w", err)
		}
		records = recompressed
		compression = "zstd"
	}

	aead, err := chacha20poly1305.NewX(symKey)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, chacha20poly1305.NonceSizeX)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	aad := chunkAAD(chunk.MessageStartTime, chunk.MessageEndTime)
	ciphertext := aead.Seal(nil, nonce, records, aad)

	return &EncryptedChunk{
		MessageStartTime: chunk.MessageStartTime,
		MessageEndTime:   chunk.MessageEndTime,
		UncompressedSize: chunk.UncompressedSize,
		UncompressedCRC:  chunk.UncompressedCRC,
		Compression:      compression,
		KeyID:            keyID,
		Nonce:            nonce,
		EncryptedData:    ciphertext,
	}, nil
}

// writeAttachmentRecord serializes a full MCAP Attachment record (opcode 0x09).
// CRC field is written as 0 (validation skipped).
func writeAttachmentRecord(w io.Writer, logTime, createTime uint64, name, mediaType string, data []byte) error {
	nb := []byte(name)
	mb := []byte(mediaType)
	size := 8 + 8 + 4 + len(nb) + 4 + len(mb) + 8 + len(data) + 4
	buf := make([]byte, size)
	o := 0
	put64 := func(v uint64) { binary.LittleEndian.PutUint64(buf[o:], v); o += 8 }
	put32 := func(v uint32) { binary.LittleEndian.PutUint32(buf[o:], v); o += 4 }
	putStr := func(b []byte) { put32(uint32(len(b))); copy(buf[o:], b); o += len(b) }

	put64(logTime)
	put64(createTime)
	putStr(nb)
	putStr(mb)
	put64(uint64(len(data)))
	copy(buf[o:], data)
	o += len(data)
	put32(0) // CRC = 0
	_ = o

	return WriteRecord(w, opcodeAttach, buf)
}
