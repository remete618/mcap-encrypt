package mcapencrypt

import (
	"bytes"
	"crypto/ecdh"
	"crypto/hmac"
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
// progressReader wraps an io.Reader and calls a progress callback with the
// cumulative byte count after each Read.
type progressReader struct {
	r        io.Reader
	progress func(int64)
	count    int64
}

func (p *progressReader) Read(b []byte) (int, error) {
	n, err := p.r.Read(b)
	if n > 0 {
		p.count += int64(n)
		p.progress(p.count)
	}
	return n, err
}

// Decrypt reads an encrypted MCAP file and writes a standard, indexed MCAP file.
// The optional progress callback receives cumulative bytes read from the input.
func Decrypt(inputPath, outputPath, privKeyPath string, progress ...func(int64)) (retErr error) {
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

	privKey, err := LoadPrivateKeyAny(privKeyPath)
	if err != nil {
		return fmt.Errorf("load private key: %w", err)
	}

	// Build an unwrap function that dispatches based on KEKAlg in each attachment.
	var unwrap func(kekAlg string, wrappedKey []byte) ([]byte, error)
	switch k := privKey.(type) {
	case *rsa.PrivateKey:
		unwrap = func(kekAlg string, wrappedKey []byte) ([]byte, error) {
			if kekAlg != "rsa-oaep-sha256" {
				return nil, fmt.Errorf("private key is RSA but slot uses %q", kekAlg)
			}
			return UnwrapSymmetricKey(wrappedKey, k)
		}
	case *ecdh.PrivateKey:
		unwrap = func(kekAlg string, wrappedKey []byte) ([]byte, error) {
			if kekAlg != "x25519-hkdf-xchacha20poly1305" {
				return nil, fmt.Errorf("private key is X25519 but slot uses %q", kekAlg)
			}
			return UnwrapSymmetricKeyX25519(wrappedKey, k)
		}
	default:
		return fmt.Errorf("unsupported private key type %T", privKey)
	}

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
			if err := tmpFile.Close(); err != nil && retErr == nil {
				retErr = fmt.Errorf("close temp output: %w", err)
			}
		}
		if retErr != nil {
			os.Remove(tmpPath)
		}
	}()

	var src io.Reader = inFile
	if len(progress) > 0 && progress[0] != nil {
		src = &progressReader{r: inFile, progress: progress[0]}
	}
	if err := streamDecrypt(src, tmpFile, unwrap); err != nil {
		return err
	}
	if err := tmpFile.Close(); err != nil {
		return fmt.Errorf("flush temp output: %w", err)
	}
	tmpClosed = true
	return os.Rename(tmpPath, outputPath)
}

// streamDecrypt performs a single-pass decrypt: schemas and channels are
// buffered (they are small and appear before the first chunk), the wrapped key
// is parsed when its attachment is encountered, and each EncryptedChunk is
// decrypted and written immediately without buffering all chunks.
//
// unwrap receives the kek_algorithm name and wrapped key bytes from each
// wrapped-key attachment and returns the symmetric key or an error (e.g. wrong
// key type or failed RSA/X25519 unwrap).
func streamDecrypt(r io.Reader, w io.Writer, unwrap func(kekAlg string, wrappedKey []byte) ([]byte, error)) error {
	if err := ReadMagic(r); err != nil {
		return fmt.Errorf("read magic: %w", err)
	}

	var (
		symKey           []byte
		fileID           []byte
		chunkIdx         uint64
		wkaCount         int  // number of wrapped-key attachments found
		manifestRequired bool // true when a v3+ key attachment is seen
		inputHdr         *mcap.Header
		schemas          []*mcap.Schema
		channels         []*mcap.Channel
		attachments      []*mcap.Attachment // non-key plaintext attachments to pass through
		metadataRecs     []*mcap.Metadata   // metadata records to pass through
		manifestPayload  []byte             // raw bytes from the manifest attachment
		writer           *mcap.Writer
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
		outHdr := &mcap.Header{Profile: "", Library: "mcap-encrypt"}
		if inputHdr != nil {
			outHdr.Profile = inputHdr.Profile
			outHdr.Library = inputHdr.Library
		}
		if err := writer.WriteHeader(outHdr); err != nil {
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
		case opcodeHeader:
			if h, parseErr := mcap.ParseHeader(data); parseErr == nil {
				inputHdr = h
			}

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

		case opcodeMetadata:
			m, parseErr := mcap.ParseMetadata(data)
			if parseErr != nil {
				return fmt.Errorf("parse metadata: %w", parseErr)
			}
			metadataRecs = append(metadataRecs, m)

		case opcodeAttach:
			name, mediaType, attData, parseErr := parseAttachmentRecord(data)
			if parseErr != nil {
				return fmt.Errorf("parse attachment: %w", parseErr)
			}

			// Manifest attachment: buffer for post-scan verification.
			if name == ManifestAttachmentName && mediaType == ManifestAttachmentMediaType {
				manifestPayload = make([]byte, len(attData))
				copy(manifestPayload, attData)
				continue
			}

			if name != AttachmentName || mediaType != AttachmentMediaType {
				// Non-key attachment: buffer for plaintext passthrough.
				logT, createT := parseAttachmentTimes(data)
				dataCopy := make([]byte, len(attData))
				copy(dataCopy, attData)
				attachments = append(attachments, &mcap.Attachment{
					LogTime:    logT,
					CreateTime: createT,
					Name:       name,
					MediaType:  mediaType,
					DataSize:   uint64(len(dataCopy)),
					Data:       bytes.NewReader(dataCopy),
				})
				continue
			}

			wkaCount++
			wkd, decErr := DecodeWrappedKeyData(attData)
			if decErr != nil {
				continue // malformed attachment; try the next one
			}
			// v3+ files always write a manifest; require it on decrypt.
			if wkd.Version >= wrappedKeyVersion {
				manifestRequired = true
			}
			if symKey != nil {
				continue // already found a valid key
			}
			candidate, unwrapErr := unwrap(wkd.KEKAlg, wkd.WrappedKey)
			if unwrapErr != nil {
				continue // wrong recipient or key type mismatch; try the next attachment
			}
			if len(candidate) != 32 {
				continue // unexpected sym key length; skip
			}
			symKey = candidate
			defer clear(symKey)
			fileID = wkd.FileID

		case OpcodeEncryptedAttachment:
			if symKey == nil {
				// Key attachment must precede encrypted attachments; skip until key is found.
				// This mirrors the encrypted-chunk-before-key error path.
				continue
			}
			ea, decErr := DecodeEncryptedAttachment(data)
			if decErr != nil {
				return fmt.Errorf("decode encrypted attachment: %w", decErr)
			}
			plain, decErr := decryptAttachmentData(ea, symKey, fileID)
			if decErr != nil {
				return fmt.Errorf("decrypt attachment %q: %w", ea.Name, decErr)
			}
			plainData := make([]byte, len(plain))
			copy(plainData, plain)
			attachments = append(attachments, &mcap.Attachment{
				LogTime:    ea.LogTime,
				CreateTime: ea.CreateTime,
				Name:       ea.Name,
				MediaType:  ea.MediaType,
				DataSize:   uint64(len(plainData)),
				Data:       bytes.NewReader(plainData),
			})

		case OpcodeEncryptedChunk:
			if symKey == nil {
				if wkaCount == 0 {
					return fmt.Errorf("encountered encrypted chunk before wrapped key attachment")
				}
				return fmt.Errorf("private key does not match any of the %d recipient key(s) in this file", wkaCount)
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
			aad := chunkAAD(fileID, chunkIdx, ec.SlotID, ec.Compression, ec.UncompressedSize, ec.UncompressedCRC, ec.MessageStartTime, ec.MessageEndTime)
			plaintext, openErr := aead.Open(nil, ec.Nonce, ec.EncryptedData, aad)
			if openErr != nil {
				return fmt.Errorf("decrypt chunk [%d–%d]: %w", ec.MessageStartTime, ec.MessageEndTime, openErr)
			}
			chunkIdx++
			if parseErr := writeChunkMessages(plaintext, ec.Compression, ec.UncompressedSize, ec.UncompressedCRC, writer); parseErr != nil {
				return fmt.Errorf("parse decrypted chunk: %w", parseErr)
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

	// v3+ files always write a manifest. Reject if it was stripped.
	if manifestRequired && manifestPayload == nil {
		return fmt.Errorf("manifest attachment missing: file may have been tampered with (strip attack)")
	}

	// Verify the manifest when present. v2 legacy files may lack one.
	if manifestPayload != nil {
		if len(manifestPayload) < manifestPayloadSize {
			return fmt.Errorf("manifest payload too short (%d bytes, need %d)", len(manifestPayload), manifestPayloadSize)
		}
		storedCount := binary.LittleEndian.Uint64(manifestPayload[:8])
		storedHMAC := manifestPayload[8 : 8+32]
		// HMAC covers storedCount, not chunkIdx, so any modification to the
		// count field is caught here rather than by the count comparison below.
		expectedHMAC := ComputeManifestHMAC(symKey, storedCount, fileID)
		if !hmac.Equal(storedHMAC, expectedHMAC) {
			return fmt.Errorf("manifest HMAC verification failed: file may be corrupted or tampered")
		}
		if storedCount != chunkIdx {
			if storedCount < chunkIdx {
				return fmt.Errorf("manifest chunk count mismatch: declared %d chunk(s), found %d (file may have been padded with extra chunks)", storedCount, chunkIdx)
			}
			return fmt.Errorf("manifest chunk count mismatch: declared %d chunk(s), found %d (file appears truncated)", storedCount, chunkIdx)
		}
	}

	if err := ensureWriter(); err != nil {
		return err
	}
	for _, att := range attachments {
		if err := writer.WriteAttachment(att); err != nil {
			return fmt.Errorf("write attachment %q: %w", att.Name, err)
		}
	}
	for _, m := range metadataRecs {
		if err := writer.WriteMetadata(m); err != nil {
			return fmt.Errorf("write metadata %q: %w", m.Name, err)
		}
	}
	return writer.Close()
}

// parseAttachmentTimes extracts log_time and create_time from raw Attachment bytes.
func parseAttachmentTimes(data []byte) (logTime, createTime uint64) {
	if len(data) < 16 {
		return 0, 0
	}
	return binary.LittleEndian.Uint64(data[0:8]),
		binary.LittleEndian.Uint64(data[8:16])
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
	// Keep data_size as uint64: an int() cast can turn a hostile high-bit
	// value negative, defeating the bounds check and panicking the slice.
	dataSize := binary.LittleEndian.Uint64(data[o:])
	o += 8
	if dataSize > uint64(len(data)-o) {
		return "", "", nil, fmt.Errorf("truncated in data field")
	}
	attData = data[o : o+int(dataSize)]
	return
}

// writeChunkMessages decompresses chunk data and writes each Message record
// directly to w, avoiding an intermediate []*mcap.Message slice.
// innerData slices point into the decompressed buffer; mcap.Writer copies them
// into its chunk buffer on WriteMessage so there is no aliasing hazard.
func writeChunkMessages(compressed []byte, compression string, expectedSize uint64, expectedCRC uint32, w *mcap.Writer) error {
	decompressed, err := decompressChunkData(compressed, compression)
	if err != nil {
		return fmt.Errorf("decompress: %w", err)
	}
	if expectedSize != 0 && uint64(len(decompressed)) != expectedSize {
		return fmt.Errorf("uncompressed size mismatch: got %d, want %d", len(decompressed), expectedSize)
	}
	if expectedCRC != 0 {
		if got := crc32.ChecksumIEEE(decompressed); got != expectedCRC {
			return fmt.Errorf("CRC mismatch: got %#08x, want %#08x", got, expectedCRC)
		}
	}

	o := 0
	for o < len(decompressed) {
		if o+9 > len(decompressed) {
			return fmt.Errorf("truncated inner record header at offset %d", o)
		}
		innerOpcode := decompressed[o]
		length := binary.LittleEndian.Uint64(decompressed[o+1 : o+9])
		o += 9
		if length > uint64(len(decompressed)-o) {
			return fmt.Errorf("truncated inner record data at offset %d (need %d bytes)", o, length)
		}
		end := o + int(length)
		if innerOpcode == 0x05 {
			msg, parseErr := mcap.ParseMessage(decompressed[o:end])
			if parseErr != nil {
				return fmt.Errorf("parse message: %w", parseErr)
			}
			if writeErr := w.WriteMessage(msg); writeErr != nil {
				return fmt.Errorf("write message: %w", writeErr)
			}
		}
		o = end
	}
	return nil
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
