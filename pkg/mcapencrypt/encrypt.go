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

// Encrypt encrypts a standard MCAP file using a single RSA public key.
func Encrypt(inputPath, outputPath, pubKeyPath string) error {
	return EncryptMulti(inputPath, outputPath, []string{pubKeyPath})
}

// EncryptMulti encrypts a standard MCAP file. The symmetric key is wrapped
// separately with each public key in pubKeyPaths and stored as individual
// attachments; any of the corresponding private keys can decrypt the file.
//
// Constraints:
//   - Input must be a chunked MCAP. Non-chunked files are rejected.
//   - inputPath and outputPath must differ.
//   - At least one public key must be provided.
//
// The encryption is single-pass over the input after an initial schema/channel
// scan: each chunk is encrypted and written to the output immediately without
// buffering the full file in memory.
func EncryptMulti(inputPath, outputPath string, pubKeyPaths []string) (retErr error) {
	if len(pubKeyPaths) == 0 {
		return fmt.Errorf("at least one public key is required")
	}

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
	if _, statErr := os.Stat(absOut); statErr == nil {
		return fmt.Errorf("output file already exists: %q (delete it first)", outputPath)
	}

	symKey := make([]byte, chacha20poly1305.KeySize)
	if _, err := rand.Read(symKey); err != nil {
		return fmt.Errorf("generate symmetric key: %w", err)
	}
	defer clear(symKey)
	fileID := make([]byte, fileIDSize)
	if _, err := rand.Read(fileID); err != nil {
		return fmt.Errorf("generate file ID: %w", err)
	}

	// Wrap the symmetric key for each recipient.
	wkds := make([]*WrappedKeyData, len(pubKeyPaths))
	for i, path := range pubKeyPaths {
		pub, loadErr := LoadPublicKey(path)
		if loadErr != nil {
			return fmt.Errorf("load public key %d: %w", i+1, loadErr)
		}
		fingerprint, fpErr := SPKIFingerprint(pub)
		if fpErr != nil {
			return fmt.Errorf("fingerprint key %d: %w", i+1, fpErr)
		}
		wrapped, wrapErr := WrapSymmetricKey(symKey, pub)
		if wrapErr != nil {
			return fmt.Errorf("wrap key for recipient %d: %w", i+1, wrapErr)
		}
		wkds[i] = &WrappedKeyData{
			FileID:     fileID,
			KeyID:      fingerprint,
			Algorithm:  "xchacha20poly1305",
			KEKAlg:     "rsa-oaep-sha256",
			WrappedKey: wrapped,
		}
	}

	// --- Pass 1: collect schemas and channels from inside chunk records. ---
	// mcap.Lexer with EmitChunks=true only yields Schema/Channel from the
	// summary section (after DataEnd). A default-mode scan reads them from
	// inside decompressed chunk contents.
	type pendingRecord struct {
		opcode byte
		data   []byte
	}
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

	// --- Pass 2: open output and stream-encrypt. ---
	// Each chunk is encrypted and written immediately; no chunk buffering.
	inFile, err := os.Open(inputPath)
	if err != nil {
		return fmt.Errorf("open input: %w", err)
	}
	defer inFile.Close()

	tmpFile, err := os.CreateTemp(filepath.Dir(outputPath), ".mcap-encrypt-tmp-*")
	if err != nil {
		return fmt.Errorf("create temp output: %w", err)
	}
	tmpPath := tmpFile.Name()
	var tmpClosed bool
	defer func() {
		if !tmpClosed {
			if closeErr := tmpFile.Close(); closeErr != nil && retErr == nil {
				retErr = fmt.Errorf("close temp output: %w", closeErr)
			}
		}
		if retErr != nil {
			os.Remove(tmpPath)
		}
	}()

	if err := WriteMagic(tmpFile); err != nil {
		return err
	}

	const keyID = "key-1"
	now := uint64(time.Now().UnixNano())

	// flushed tracks whether schemas, channels, and key attachments have been
	// written. They must appear before the first EncryptedChunk record.
	var flushed bool
	flushPending := func() error {
		if flushed {
			return nil
		}
		flushed = true
		for _, r := range pending {
			if err := WriteRecord(tmpFile, r.opcode, r.data); err != nil {
				return err
			}
		}
		for _, wkd := range wkds {
			attBytes := buildAttachmentBytes(now, 0, AttachmentName, AttachmentMediaType, wkd.Encode())
			if err := WriteRecord(tmpFile, opcodeAttach, attBytes); err != nil {
				return err
			}
		}
		return nil
	}

	lexer, err := mcap.NewLexer(inFile, &mcap.LexerOptions{
		EmitChunks: true,
		AttachmentCallback: func(ar *mcap.AttachmentReader) error {
			data, readErr := io.ReadAll(ar.Data())
			if readErr != nil {
				return readErr
			}
			// Skip wrapped-key attachments from previously encrypted inputs.
			if ar.Name == AttachmentName {
				return nil
			}
			if err := flushPending(); err != nil {
				return err
			}
			return WriteRecord(tmpFile, opcodeAttach, buildAttachmentBytes(ar.LogTime, ar.CreateTime, ar.Name, ar.MediaType, data))
		},
	})
	if err != nil {
		return fmt.Errorf("create lexer: %w", err)
	}

	var chunkIdx int
	var tokenBuf []byte

outer:
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
			if err := WriteRecord(tmpFile, passthroughOpcode[tok], data); err != nil {
				return err
			}

		case mcap.TokenSchema, mcap.TokenChannel:
			// Already collected in pass 1 and written via flushPending.

		case mcap.TokenMetadata:
			if err := flushPending(); err != nil {
				return err
			}
			if err := WriteRecord(tmpFile, passthroughOpcode[tok], data); err != nil {
				return err
			}

		case mcap.TokenChunk:
			if err := flushPending(); err != nil {
				return err
			}
			chunk, parseErr := mcap.ParseChunk(data)
			if parseErr != nil {
				return fmt.Errorf("parse chunk: %w", parseErr)
			}
			// encryptChunk is called synchronously before the next lexer.Next(),
			// so chunk.Records (which aliases tokenBuf) is still valid here.
			ec, encErr := encryptChunk(chunk, symKey, keyID, fileID, chunkIdx)
			if encErr != nil {
				return fmt.Errorf("encrypt chunk %d: %w", chunkIdx, encErr)
			}
			chunkIdx++
			if err := WriteRecord(tmpFile, OpcodeEncryptedChunk, ec.Encode()); err != nil {
				return err
			}

		case mcap.TokenDataEnd:
			// Flush in case there were no chunks (schema/channel-only files).
			if err := flushPending(); err != nil {
				return err
			}
			if err := WriteRecord(tmpFile, opcodeDataEnd, data); err != nil {
				return err
			}

		case mcap.TokenFooter:
			if err := WriteRecord(tmpFile, opcodeFooter, emptyFooter); err != nil {
				return err
			}
			break outer

		case mcap.TokenMessageIndex, mcap.TokenChunkIndex,
			mcap.TokenStatistics, mcap.TokenSummaryOffset,
			mcap.TokenAttachmentIndex, mcap.TokenMetadataIndex:
			// Drop: all index records reference byte positions in the
			// original file that are invalid after chunk replacement.

		default:
			return fmt.Errorf("unhandled token type %v", tok)
		}
	}

	if err := WriteMagic(tmpFile); err != nil {
		return err
	}
	if err := tmpFile.Close(); err != nil {
		return fmt.Errorf("flush temp output: %w", err)
	}
	tmpClosed = true
	return os.Rename(tmpPath, outputPath)
}

// passthroughOpcode maps token types that are written verbatim to their opcodes.
var passthroughOpcode = map[mcap.TokenType]byte{
	mcap.TokenHeader:   0x01,
	mcap.TokenSchema:   0x03,
	mcap.TokenChannel:  0x04,
	mcap.TokenMetadata: 0x0C,
}

// chunkAAD builds the AEAD additional data for one encrypted chunk.
// It binds: file identity, chunk position, key identity, compression
// parameters, and time bounds. Any modification to these plaintext fields
// or the ciphertext will cause authentication to fail.
func chunkAAD(fileID []byte, chunkIdx uint64, keyID, compression string, uncompressedSize uint64, uncompressedCRC uint32, startTime, endTime uint64) []byte {
	putStr := func(buf []byte, s string) []byte {
		var n [4]byte
		binary.LittleEndian.PutUint32(n[:], uint32(len(s)))
		buf = append(buf, n[:]...)
		return append(buf, s...)
	}
	buf := make([]byte, 0, fileIDSize+8+4+len(keyID)+4+len(compression)+8+4+8+8)
	buf = append(buf, fileID...)
	buf = binary.LittleEndian.AppendUint64(buf, chunkIdx)
	buf = putStr(buf, keyID)
	buf = putStr(buf, compression)
	buf = binary.LittleEndian.AppendUint64(buf, uncompressedSize)
	buf = binary.LittleEndian.AppendUint32(buf, uncompressedCRC)
	buf = binary.LittleEndian.AppendUint64(buf, startTime)
	buf = binary.LittleEndian.AppendUint64(buf, endTime)
	return buf
}

func encryptChunk(chunk *mcap.Chunk, symKey []byte, keyID string, fileID []byte, chunkIdx int) (*EncryptedChunk, error) {
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
	aad := chunkAAD(fileID, uint64(chunkIdx), keyID, compression, chunk.UncompressedSize, chunk.UncompressedCRC, chunk.MessageStartTime, chunk.MessageEndTime)
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

// buildAttachmentBytes serializes an MCAP Attachment record payload.
// CRC field is written as 0 (validation skipped).
func buildAttachmentBytes(logTime, createTime uint64, name, mediaType string, data []byte) []byte {
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
	return buf
}
