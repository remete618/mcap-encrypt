package mcapencrypt

import (
	"crypto/ecdh"
	"crypto/rand"
	"crypto/rsa"
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

// Encrypt encrypts a standard MCAP file using a single RSA or X25519 public key.
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
// Public keys may be RSA (any size) or X25519. Mixed-algorithm recipient lists
// are supported.
// EncryptMulti encrypts a standard MCAP file for one or more recipients.
// The optional progress callback receives cumulative bytes written to the output.
func EncryptMulti(inputPath, outputPath string, pubKeyPaths []string, progress ...func(int64)) (retErr error) {
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
		pub, loadErr := LoadPublicKeyAny(path)
		if loadErr != nil {
			return fmt.Errorf("load public key %d: %w", i+1, loadErr)
		}
		fingerprint, fpErr := SPKIFingerprint(pub)
		if fpErr != nil {
			return fmt.Errorf("fingerprint key %d: %w", i+1, fpErr)
		}
		var wrapped []byte
		var kekAlg string
		var wrapErr error
		switch k := pub.(type) {
		case *rsa.PublicKey:
			kekAlg = "rsa-oaep-sha256"
			wrapped, wrapErr = WrapSymmetricKey(symKey, k)
		case *ecdh.PublicKey:
			kekAlg = "x25519-hkdf-xchacha20poly1305"
			wrapped, wrapErr = WrapSymmetricKeyX25519(symKey, k)
		default:
			return fmt.Errorf("unsupported public key type %T for recipient %d", pub, i+1)
		}
		if wrapErr != nil {
			return fmt.Errorf("wrap key for recipient %d: %w", i+1, wrapErr)
		}
		wkds[i] = &WrappedKeyData{
			FileID:     fileID,
			KeyID:      fingerprint,
			Algorithm:  "xchacha20poly1305",
			KEKAlg:     kekAlg,
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

	const slotID = "key-1"
	now := uint64(time.Now().UnixNano())

	// manifestDataFileOffset tracks where in tmpFile the manifest payload lives
	// so we can patch the chunk count and HMAC after all chunks are written.
	var manifestDataFileOffset int64

	// flushed tracks whether schemas, channels, key attachments, and the manifest
	// placeholder have been written. They must appear before the first EncryptedChunk.
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
		// Write a manifest placeholder so we can patch it with the real chunk count
		// and HMAC after all chunks have been encrypted.
		curOffset, seekErr := tmpFile.Seek(0, io.SeekCurrent)
		if seekErr != nil {
			return fmt.Errorf("seek for manifest offset: %w", seekErr)
		}
		// The manifest data field is at: record header (9) + payload offset (83)
		// after the start of this record.
		manifestDataFileOffset = curOffset + 9 + int64(manifestDataOffsetInPayload)
		placeholder := make([]byte, manifestPayloadSize)
		attBytes := buildAttachmentBytes(now, 0, ManifestAttachmentName, ManifestAttachmentMediaType, placeholder)
		if err := WriteRecord(tmpFile, opcodeAttach, attBytes); err != nil {
			return err
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
			// Check both name AND media type so a legitimate user attachment that
			// happens to share the name is not silently dropped.
			if ar.Name == AttachmentName && ar.MediaType == AttachmentMediaType {
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

	// encChunkMeta captures the file position and key metadata of each
	// EncryptedChunk record so we can populate ChunkIndex in the summary.
	type encChunkMeta struct {
		fileOffset     int64  // byte position of the record's opcode byte
		recordLen      int64  // 9 (header) + len(encoded data)
		msgStart       uint64
		msgEnd         uint64
		compression    string
		compressedSize uint64 // len(ciphertext), for ChunkIndex.compressed_size
		uncompSize     uint64
	}
	var encChunkMetas []encChunkMeta

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
			ec, encErr := encryptChunk(chunk, symKey, slotID, fileID, chunkIdx)
			if encErr != nil {
				return fmt.Errorf("encrypt chunk %d: %w", chunkIdx, encErr)
			}
			chunkIdx++
			ecData := ec.Encode()
			startOff, seekErr := tmpFile.Seek(0, io.SeekCurrent)
			if seekErr != nil {
				return fmt.Errorf("seek before chunk %d: %w", chunkIdx-1, seekErr)
			}
			if err := WriteRecord(tmpFile, OpcodeEncryptedChunk, ecData); err != nil {
				return err
			}
			endOff, seekErr := tmpFile.Seek(0, io.SeekCurrent)
			if seekErr != nil {
				return fmt.Errorf("seek after chunk %d: %w", chunkIdx-1, seekErr)
			}
			if len(progress) > 0 && progress[0] != nil {
				progress[0](endOff)
			}
			encChunkMetas = append(encChunkMetas, encChunkMeta{
				fileOffset:     startOff,
				recordLen:      endOff - startOff,
				msgStart:       ec.MessageStartTime,
				msgEnd:         ec.MessageEndTime,
				compression:    ec.Compression,
				compressedSize: uint64(len(ec.EncryptedData)),
				uncompSize:     ec.UncompressedSize,
			})

		case mcap.TokenDataEnd:
			// Flush in case there were no chunks (schema/channel-only files).
			if err := flushPending(); err != nil {
				return err
			}
			// Patch the manifest placeholder with the real chunk count and HMAC.
			var manifestPayload [manifestPayloadSize]byte
			binary.LittleEndian.PutUint64(manifestPayload[:8], uint64(chunkIdx))
			mac := ComputeManifestHMAC(symKey, uint64(chunkIdx), fileID)
			copy(manifestPayload[8:], mac)
			if _, err := tmpFile.WriteAt(manifestPayload[:], manifestDataFileOffset); err != nil {
				return fmt.Errorf("patch manifest: %w", err)
			}
			if err := WriteRecord(tmpFile, opcodeDataEnd, data); err != nil {
				return err
			}

		case mcap.TokenFooter:
			// Build a real summary section so seekable MCAP readers (and
			// Foxglove Studio) can navigate the file by time range without
			// decrypting. Schemas and channels are already plaintext; ChunkIndex
			// records carry the EncryptedChunk offsets and time bounds.
			summaryStart, seekErr := tmpFile.Seek(0, io.SeekCurrent)
			if seekErr != nil {
				return fmt.Errorf("seek for summary: %w", seekErr)
			}

			type group struct {
				opcode    byte
				absStart  int64
				absLength int64
			}
			var groups []group

			// Build summary in a byte buffer; track absolute file offsets by
			// adding summaryStart + written-so-far.
			var sumBuf []byte
			written := int64(0)
			emitRec := func(opcode byte, data []byte) {
				hdr := [9]byte{opcode}
				binary.LittleEndian.PutUint64(hdr[1:], uint64(len(data)))
				sumBuf = append(sumBuf, hdr[:]...)
				sumBuf = append(sumBuf, data...)
				written += int64(9 + len(data))
			}
			put16 := func(b []byte, v uint16) { binary.LittleEndian.PutUint16(b, v) }
			put32 := func(b []byte, v uint32) { binary.LittleEndian.PutUint32(b, v) }
			put64 := func(b []byte, v uint64) { binary.LittleEndian.PutUint64(b, v) }
			putStr := func(s string) []byte {
				b := make([]byte, 4+len(s))
				binary.LittleEndian.PutUint32(b, uint32(len(s)))
				copy(b[4:], s)
				return b
			}

			// Schema group
			schemaStart := summaryStart + written
			for _, r := range pending {
				if r.opcode == opcodeSchema {
					emitRec(opcodeSchema, r.data)
				}
			}
			if l := summaryStart + written - schemaStart; l > 0 {
				groups = append(groups, group{opcodeSchema, schemaStart, l})
			}

			// Channel group
			channelStart := summaryStart + written
			for _, r := range pending {
				if r.opcode == opcodeChannel {
					emitRec(opcodeChannel, r.data)
				}
			}
			if l := summaryStart + written - channelStart; l > 0 {
				groups = append(groups, group{opcodeChannel, channelStart, l})
			}

			// Statistics (message_count unknown for encrypted files = 0)
			statsStart := summaryStart + written
			var globalMsgStart, globalMsgEnd uint64
			schemaCount, channelCount := 0, 0
			for _, r := range pending {
				switch r.opcode {
				case opcodeSchema:
					schemaCount++
				case opcodeChannel:
					channelCount++
				}
			}
			if len(encChunkMetas) > 0 {
				globalMsgStart = encChunkMetas[0].msgStart
				globalMsgEnd = encChunkMetas[0].msgEnd
				for _, m := range encChunkMetas[1:] {
					if m.msgStart < globalMsgStart {
						globalMsgStart = m.msgStart
					}
					if m.msgEnd > globalMsgEnd {
						globalMsgEnd = m.msgEnd
					}
				}
			}
			statsBuf := make([]byte, 8+2+4+4+4+4+8+8+4)
			o := 0
			put64(statsBuf[o:], 0); o += 8                          // message_count (unknown)
			put16(statsBuf[o:], uint16(schemaCount)); o += 2         // schema_count
			put32(statsBuf[o:], uint32(channelCount)); o += 4        // channel_count
			put32(statsBuf[o:], 0); o += 4                          // attachment_count
			put32(statsBuf[o:], 0); o += 4                          // metadata_count
			put32(statsBuf[o:], uint32(len(encChunkMetas))); o += 4 // chunk_count
			put64(statsBuf[o:], globalMsgStart); o += 8             // message_start_time
			put64(statsBuf[o:], globalMsgEnd); o += 8               // message_end_time
			put32(statsBuf[o:], 0); o += 4                          // channel_message_counts: empty
			emitRec(opcodeStatistics, statsBuf)
			groups = append(groups, group{opcodeStatistics, statsStart, summaryStart + written - statsStart})

			// ChunkIndex: one per EncryptedChunk, pointing at its file offset.
			// Readers seek to chunk_start_offset and find opcode 0x81; tools
			// that understand the encrypted format use this for O(log n) seeking.
			chunkIdxStart := summaryStart + written
			for _, m := range encChunkMetas {
				comp := m.compression
				ci := make([]byte, 8+8+8+8+4+8+4+len(comp)+8+8)
				o := 0
				put64(ci[o:], m.msgStart); o += 8
				put64(ci[o:], m.msgEnd); o += 8
				put64(ci[o:], uint64(m.fileOffset)); o += 8
				put64(ci[o:], uint64(m.recordLen)); o += 8
				put32(ci[o:], 0); o += 4           // message_index_offsets: empty
				put64(ci[o:], 0); o += 8           // message_index_length: 0
				copy(ci[o:], putStr(comp)); o += 4 + len(comp)
				put64(ci[o:], m.compressedSize); o += 8
				put64(ci[o:], m.uncompSize); o += 8
				emitRec(opcodeChunkIndex, ci[:o])
			}
			if l := summaryStart + written - chunkIdxStart; l > 0 {
				groups = append(groups, group{opcodeChunkIndex, chunkIdxStart, l})
			}

			// SummaryOffset records
			summaryOffsetStart := summaryStart + written
			for _, g := range groups {
				so := make([]byte, 1+8+8)
				so[0] = g.opcode
				put64(so[1:], uint64(g.absStart))
				put64(so[9:], uint64(g.absLength))
				emitRec(opcodeSummaryOffset, so)
			}

			if _, err := tmpFile.Write(sumBuf); err != nil {
				return fmt.Errorf("write summary: %w", err)
			}

			// Footer with real summary offsets.
			footerBuf := make([]byte, 20)
			put64(footerBuf[0:], uint64(summaryStart))
			put64(footerBuf[8:], uint64(summaryOffsetStart))
			// summary_crc = 0 (bytes 16-19 remain zero)
			if err := WriteRecord(tmpFile, opcodeFooter, footerBuf); err != nil {
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
// It binds: file identity, chunk position, slot identity, compression
// parameters, and time bounds. Any modification to these plaintext fields
// or the ciphertext will cause authentication to fail.
func chunkAAD(fileID []byte, chunkIdx uint64, slotID, compression string, uncompressedSize uint64, uncompressedCRC uint32, startTime, endTime uint64) []byte {
	putStr := func(buf []byte, s string) []byte {
		var n [4]byte
		binary.LittleEndian.PutUint32(n[:], uint32(len(s)))
		buf = append(buf, n[:]...)
		return append(buf, s...)
	}
	buf := make([]byte, 0, fileIDSize+8+4+len(slotID)+4+len(compression)+8+4+8+8)
	buf = append(buf, fileID...)
	buf = binary.LittleEndian.AppendUint64(buf, chunkIdx)
	buf = putStr(buf, slotID)
	buf = putStr(buf, compression)
	buf = binary.LittleEndian.AppendUint64(buf, uncompressedSize)
	buf = binary.LittleEndian.AppendUint32(buf, uncompressedCRC)
	buf = binary.LittleEndian.AppendUint64(buf, startTime)
	buf = binary.LittleEndian.AppendUint64(buf, endTime)
	return buf
}

func encryptChunk(chunk *mcap.Chunk, symKey []byte, slotID string, fileID []byte, chunkIdx int) (*EncryptedChunk, error) {
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
	aad := chunkAAD(fileID, uint64(chunkIdx), slotID, compression, chunk.UncompressedSize, chunk.UncompressedCRC, chunk.MessageStartTime, chunk.MessageEndTime)
	ciphertext := aead.Seal(nil, nonce, records, aad)

	return &EncryptedChunk{
		MessageStartTime: chunk.MessageStartTime,
		MessageEndTime:   chunk.MessageEndTime,
		UncompressedSize: chunk.UncompressedSize,
		UncompressedCRC:  chunk.UncompressedCRC,
		Compression:      compression,
		SlotID:           slotID,
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
