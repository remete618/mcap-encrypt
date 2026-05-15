package mcapencrypt

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"time"

	"golang.org/x/crypto/chacha20poly1305"

	"github.com/foxglove/mcap/go/mcap"
)

// tokenOpcode maps Lexer token types to their MCAP opcodes for raw passthrough.
var tokenOpcode = map[mcap.TokenType]byte{
	mcap.TokenHeader:        0x01,
	mcap.TokenFooter:        0x02,
	mcap.TokenSchema:        0x03,
	mcap.TokenChannel:       0x04,
	mcap.TokenMessage:       0x05,
	mcap.TokenChunk:         0x06,
	mcap.TokenMessageIndex:  0x07,
	mcap.TokenChunkIndex:    0x08,
	mcap.TokenStatistics:    0x0B,
	mcap.TokenMetadata:      0x0C,
	mcap.TokenMetadataIndex: 0x0D,
	mcap.TokenSummaryOffset: 0x0E,
	mcap.TokenDataEnd:       0x0F,
}

// Encrypt reads a standard MCAP file and writes an encrypted MCAP file.
// Each chunk is encrypted with XChaCha20Poly1305. The symmetric key is
// wrapped with the RSA-2048 public key and stored as an Attachment named
// "mcap_encryption_key". Schemas and channels remain plaintext.
func Encrypt(inputPath, outputPath, pubKeyPath string) error {
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
	defer outFile.Close()

	if err := WriteMagic(outFile); err != nil {
		return err
	}

	wroteKey := false

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
			if lexErr == io.EOF {
				break
			}
			return fmt.Errorf("lexer: %w", lexErr)
		}
		tokenBuf = data

		switch tok {
		case mcap.TokenChunk:
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
			if !wroteKey {
				if writeErr := writeAttachmentRecord(
					outFile,
					uint64(time.Now().UnixNano()), 0,
					AttachmentName, AttachmentMediaType,
					wkd.Encode(),
				); writeErr != nil {
					return fmt.Errorf("write wrapped key: %w", writeErr)
				}
				wroteKey = true
			}
			if writeErr := WriteRecord(outFile, opcodeDataEnd, data); writeErr != nil {
				return writeErr
			}

		case mcap.TokenFooter:
			// Write our own footer: SummaryStart=0 means no summary section.
			if writeErr := WriteRecord(outFile, opcodeFooter, emptyFooter); writeErr != nil {
				return writeErr
			}

		case mcap.TokenMessageIndex, mcap.TokenChunkIndex,
			mcap.TokenStatistics, mcap.TokenSummaryOffset:
			// Drop: byte offsets are invalid after chunk replacement.

		default:
			op, ok := tokenOpcode[tok]
			if !ok {
				return fmt.Errorf("unhandled token type %v", tok)
			}
			if writeErr := WriteRecord(outFile, op, data); writeErr != nil {
				return writeErr
			}
		}
	}

	return WriteMagic(outFile)
}

func encryptChunk(chunk *mcap.Chunk, symKey []byte, keyID string) (*EncryptedChunk, error) {
	aead, err := chacha20poly1305.NewX(symKey)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, chacha20poly1305.NonceSizeX)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	ciphertext := aead.Seal(nil, nonce, chunk.Records, nil)

	return &EncryptedChunk{
		MessageStartTime: chunk.MessageStartTime,
		MessageEndTime:   chunk.MessageEndTime,
		UncompressedSize: chunk.UncompressedSize,
		UncompressedCRC:  chunk.UncompressedCRC,
		Compression:      chunk.Compression,
		KeyID:            keyID,
		Nonce:            nonce,
		EncryptedData:    ciphertext,
	}, nil
}

// writeAttachmentRecord serializes a full MCAP Attachment record (opcode 0x09).
// CRC is written as 0 (not validated).
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
