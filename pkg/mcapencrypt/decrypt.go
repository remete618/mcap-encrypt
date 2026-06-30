package mcapencrypt

import (
	"bytes"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rsa"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"path/filepath"
	"strings"

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

// DecryptOptions carries optional parameters for DecryptWithOptions.
type DecryptOptions struct {
	// WarnFunc is called with a human-readable message whenever a non-fatal
	// issue is encountered during decryption (e.g. a wrapped-key attachment
	// that cannot be parsed). If nil, such issues are silently skipped.
	WarnFunc func(string)
}

// DecryptWithOptions decrypts an encrypted MCAP stream and writes a standard,
// indexed MCAP to w. It behaves identically to the file-based Decrypt function
// but operates on arbitrary io.Reader / io.Writer pairs and accepts DecryptOptions.
func DecryptWithOptions(r io.Reader, w io.Writer, privateKeyPem string, opts DecryptOptions) error {
	privKey, err := parsePrivateKeyPEM(privateKeyPem)
	if err != nil {
		return fmt.Errorf("parse private key: %w", err)
	}
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
	return streamDecrypt(r, w, unwrap, opts.WarnFunc)
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
	if err := streamDecrypt(src, tmpFile, unwrap, nil); err != nil {
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
//
// warnFunc, if non-nil, is called with a human-readable message whenever a
// non-fatal issue is encountered (e.g. a malformed wrapped-key attachment).
func streamDecrypt(r io.Reader, w io.Writer, unwrap func(kekAlg string, wrappedKey []byte) ([]byte, error), warnFunc func(string)) error {
	if err := ReadMagic(r); err != nil {
		return fmt.Errorf("read magic: %w", err)
	}

	var (
		// symKey and fileID accumulate via constant-time selection across all
		// wrapped-key slots: see the opcodeAttach branch below. They are
		// pre-allocated to fixed length so a constant-time select can populate
		// them without revealing which slot matched. symKeyFound tracks whether
		// any slot produced a 32-byte unwrap; it is set in constant time too.
		symKey           = make([]byte, symKeyLen)
		fileID           = make([]byte, fileIDSize)
		symKeyFound      int // 1 once a valid slot has been seen, else 0
		slotErrs         []string
		chunkIdx         uint64
		wkaCount         int  // number of wrapped-key attachments found
		manifestRequired bool // true when a v3+ key attachment is seen
		inputHdr         *mcap.Header
		schemas          []*mcap.Schema
		channels         []*mcap.Channel
		attachments      []*mcap.Attachment   // non-key plaintext attachments to pass through
		metadataRecs     []*mcap.Metadata     // plaintext metadata records
		encMetadataRecs  []*EncryptedMetadata // encrypted metadata records (decrypted in finalize)
		manifestPayload  []byte               // raw bytes from the manifest attachment
		writer           *mcap.Writer
	)
	defer clear(symKey)

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
				if warnFunc != nil {
					warnFunc(fmt.Sprintf("wrapped-key attachment #%d could not be parsed: %v", wkaCount, decErr))
				}
				continue // malformed framing: cannot be tried; record nothing.
			}
			// v3+ files always write a manifest; require it on decrypt.
			if wkd.Version >= wrappedKeyVersion {
				manifestRequired = true
			}

			// Constant-time slot trial. Every well-formed slot is unwrapped,
			// even after a match has been found, so wall-clock timing of the
			// decrypt does not depend on slot position. Selection of the
			// matching key uses crypto/subtle to avoid a secret-dependent
			// branch. See issue #21.
			//lint:ignore SA4006 slotErr is read in the if statement below;
			// staticcheck 2025.1.1 false-positives on this pattern inside a
			// switch case inside a for loop.
			candidate, slotErr := unwrap(wkd.KEKAlg, wkd.WrappedKey)
			ok := subtle.ConstantTimeEq(int32(len(candidate)), int32(symKeyLen))
			if slotErr != nil {
				ok = 0
				slotErrs = append(slotErrs, fmt.Sprintf("slot #%d: %v", wkaCount, slotErr))
			}
			// Stage candidate and fileID into fixed-size buffers so the
			// constant-time copy below has length-invariant inputs even when
			// unwrap returned a nil or short slice. copy() into a fixed-size
			// array is safe for any source length: it copies min(len) bytes
			// and leaves the rest at its prior (zero) value.
			var (
				candidateBuf [symKeyLen]byte
				fileIDBuf    [fileIDSize]byte
			)
			copy(candidateBuf[:], candidate)
			// wkd.FileID is parsed from plaintext attachment bytes and is
			// always 16 bytes on a well-formed slot (DecodeWrappedKeyData
			// enforces this), but copy is bounded for safety.
			copy(fileIDBuf[:], wkd.FileID)
			// Take the first valid slot only: if symKeyFound is already 1,
			// keep the existing symKey/fileID; else copy the staged buffers
			// if this slot is ok.
			take := subtle.ConstantTimeSelect(symKeyFound, 0, ok)
			ctSelectInto(symKey, candidateBuf[:], take)
			ctSelectInto(fileID, fileIDBuf[:], take)
			symKeyFound |= take

		case OpcodeEncryptedAttachment:
			if symKeyFound == 0 {
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

		case OpcodeEncryptedMetadata:
			em, decErr := DecodeEncryptedMetadata(data)
			if decErr != nil {
				return fmt.Errorf("decode encrypted metadata: %w", decErr)
			}
			encMetadataRecs = append(encMetadataRecs, em)

		case OpcodeEncryptedChunk:
			if symKeyFound == 0 {
				if wkaCount == 0 {
					return fmt.Errorf("encountered encrypted chunk before wrapped key attachment")
				}
				if len(slotErrs) > 0 {
					return fmt.Errorf("private key does not match any of the %d recipient key(s) in this file: %s",
						wkaCount, strings.Join(slotErrs, "; "))
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
			plaintext, decErr := decryptSingleChunk(ec, symKey, fileID, chunkIdx)
			if decErr != nil {
				return decErr
			}
			chunkIdx++
			// Skip chunks that claim to carry no data — AEAD has already
			// authenticated the zero UncompressedSize, so this is legitimate
			// and avoids a no-op decompression call.
			if ec.UncompressedSize == 0 {
				continue
			}
			if parseErr := writeChunkMessages(plaintext, ec.Compression, ec.UncompressedSize, ec.UncompressedCRC, writer); parseErr != nil {
				return fmt.Errorf("parse decrypted chunk: %w", parseErr)
			}

		case opcodeFooter:
			break scan

			// Ignore header, data-end, and any index records.
		}
	}

	if symKeyFound == 0 {
		if wkaCount == 0 {
			return fmt.Errorf("input is not an encrypted MCAP file (no wrapped key attachment present); only files produced by 'mcap-encrypt encrypt' can be decrypted")
		}
		if len(slotErrs) > 0 {
			return fmt.Errorf("private key does not match any of the %d recipient key(s) in this file: %s",
				wkaCount, strings.Join(slotErrs, "; "))
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
	for _, em := range encMetadataRecs {
		plain, decErr := decryptMetadataRecord(em, symKey, fileID)
		if decErr != nil {
			return fmt.Errorf("decrypt metadata record: %w", decErr)
		}
		m, parseErr := mcap.ParseMetadata(plain)
		if parseErr != nil {
			return fmt.Errorf("parse decrypted metadata: %w", parseErr)
		}
		if err := writer.WriteMetadata(m); err != nil {
			return fmt.Errorf("write decrypted metadata %q: %w", m.Name, err)
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

// decryptSingleChunk validates one EncryptedChunk and returns its plaintext
// (still compressed). The chunkIdx must match the chunk's position in the
// file's encryption sequence: it is bound into the AEAD additional data, so a
// wrong index causes Open to fail. Callers that already hold a decoded
// EncryptedChunk (e.g. the streaming bridge) reuse this helper to avoid
// duplicating the AEAD wiring from streamDecrypt.
func decryptSingleChunk(ec *EncryptedChunk, symKey, fileID []byte, chunkIdx uint64) ([]byte, error) {
	if len(ec.Nonce) != chacha20poly1305.NonceSizeX {
		return nil, fmt.Errorf("chunk [%d–%d]: nonce length %d invalid (want %d)",
			ec.MessageStartTime, ec.MessageEndTime, len(ec.Nonce), chacha20poly1305.NonceSizeX)
	}
	if len(ec.EncryptedData) < 16 {
		return nil, fmt.Errorf("chunk [%d–%d]: ciphertext too short (%d bytes, minimum 16)",
			ec.MessageStartTime, ec.MessageEndTime, len(ec.EncryptedData))
	}
	aead, cipherErr := chacha20poly1305.NewX(symKey)
	if cipherErr != nil {
		return nil, fmt.Errorf("create cipher: %w", cipherErr)
	}
	aad := chunkAAD(fileID, chunkIdx, ec.SlotID, ec.Compression, ec.UncompressedSize, ec.UncompressedCRC, ec.MessageStartTime, ec.MessageEndTime)
	plaintext, openErr := aead.Open(nil, ec.Nonce, ec.EncryptedData, aad)
	if openErr != nil {
		return nil, fmt.Errorf("decrypt chunk [%d–%d]: %w", ec.MessageStartTime, ec.MessageEndTime, openErr)
	}
	return plaintext, nil
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

// ctSelectInto overwrites dst with src when take == 1, and leaves dst
// unchanged when take == 0, using a bitmask so the work and memory access
// pattern do not depend on take. src must be exactly len(dst) bytes (callers
// pre-pad short or nil unwrap results into a fixed-size buffer before
// invoking this helper).
func ctSelectInto(dst, src []byte, take int) {
	if len(src) != len(dst) {
		panic("ctSelectInto: src and dst must have equal length")
	}
	mask := byte(-take & 0xFF) // 0xFF when take==1, 0x00 when take==0
	for i := 0; i < len(dst); i++ {
		dst[i] = (dst[i] &^ mask) | (src[i] & mask)
	}
}
