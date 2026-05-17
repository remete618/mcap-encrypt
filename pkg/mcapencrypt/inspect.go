package mcapencrypt

import (
	"encoding/binary"
	"fmt"
	"io"
	"os"
)

// RecipientInfo describes one wrapped-key slot in an encrypted MCAP.
type RecipientInfo struct {
	KeyID     string // hex SHA-256 of the recipient's SPKI public key
	KEKAlg    string // "rsa-oaep-sha256" | "x25519-hkdf-xchacha20poly1305"
	Algorithm string // symmetric cipher, always "xchacha20poly1305"
}

// InspectResult holds the metadata extracted by Inspect without decrypting.
type InspectResult struct {
	IsEncrypted              bool
	FormatVersion            byte   // from WrappedKeyData.Version (2 or 3)
	FileID                   []byte // 16-byte random file identifier
	ChunkCount               uint64 // declared in manifest attachment
	EncryptedChunkCount      uint64 // actual 0x81 records scanned
	EncryptedAttachmentCount uint64 // actual 0x82 records scanned
	Compression              string // from first EncryptedChunk header
	Recipients               []RecipientInfo
}

// Inspect scans an MCAP (encrypted or plain) and returns its metadata without
// decrypting any chunk data. Large EncryptedChunk payloads are skipped via
// io.Discard; only a small header prefix of each chunk is read.
func Inspect(r io.Reader) (*InspectResult, error) {
	if err := ReadMagic(r); err != nil {
		return nil, fmt.Errorf("not a valid MCAP file: %w", err)
	}

	res := &InspectResult{}
	compressionSet := false

	for {
		var hdr [9]byte
		if _, err := io.ReadFull(r, hdr[:]); err != nil {
			if err == io.EOF || err == io.ErrUnexpectedEOF {
				break
			}
			return nil, fmt.Errorf("read record header: %w", err)
		}
		opcode := hdr[0]
		length := binary.LittleEndian.Uint64(hdr[1:])
		if length > maxRecordDataSize {
			return nil, fmt.Errorf("record length %d exceeds maximum allowed size", length)
		}

		switch opcode {
		case opcodeAttach:
			data, err := io.ReadAll(io.LimitReader(r, int64(length)))
			if err != nil {
				return nil, fmt.Errorf("read attachment: %w", err)
			}
			if uint64(len(data)) != length {
				return nil, fmt.Errorf("attachment record truncated")
			}
			name, mediaType, attData, pErr := parseAttachmentRecord(data)
			if pErr != nil {
				continue
			}
			switch {
			case name == AttachmentName && mediaType == AttachmentMediaType:
				wk, dErr := DecodeWrappedKeyData(attData)
				if dErr != nil {
					continue
				}
				res.IsEncrypted = true
				if res.FileID == nil {
					res.FileID = wk.FileID
					res.FormatVersion = wk.Version
				}
				res.Recipients = append(res.Recipients, RecipientInfo{
					KeyID:     wk.KeyID,
					KEKAlg:    wk.KEKAlg,
					Algorithm: wk.Algorithm,
				})
			case name == ManifestAttachmentName && mediaType == ManifestAttachmentMediaType:
				if len(attData) >= 8 {
					res.ChunkCount = binary.LittleEndian.Uint64(attData[:8])
				}
			}

		case OpcodeEncryptedChunk:
			res.IsEncrypted = true
			res.EncryptedChunkCount++
			if !compressionSet {
				// EncryptedChunk layout: 3×uint64 (24) + uint32 (4) = 28 fixed bytes,
				// then string compression = uint32 length (4) + bytes.
				// Peek at most 28+4+64 bytes to capture any reasonable compression name.
				const fixedOffset = 28
				peekLen := uint64(fixedOffset + 4 + 64)
				if peekLen > length {
					peekLen = length
				}
				peek := make([]byte, peekLen)
				n, _ := io.ReadFull(r, peek)
				peek = peek[:n]
				if n >= fixedOffset+4 {
					strLen := int(binary.LittleEndian.Uint32(peek[fixedOffset:]))
					end := fixedOffset + 4 + strLen
					if end <= n && strLen <= 64 {
						res.Compression = string(peek[fixedOffset+4 : end])
						compressionSet = true
					}
				}
				remaining := int64(length) - int64(n)
				if remaining > 0 {
					if _, err := io.CopyN(io.Discard, r, remaining); err != nil {
						return nil, fmt.Errorf("skip EncryptedChunk: %w", err)
					}
				}
			} else {
				if _, err := io.CopyN(io.Discard, r, int64(length)); err != nil {
					return nil, fmt.Errorf("skip EncryptedChunk: %w", err)
				}
			}

		case OpcodeEncryptedAttachment:
			res.IsEncrypted = true
			res.EncryptedAttachmentCount++
			if _, err := io.CopyN(io.Discard, r, int64(length)); err != nil {
				return nil, fmt.Errorf("skip EncryptedAttachment: %w", err)
			}

		default:
			if _, err := io.CopyN(io.Discard, r, int64(length)); err != nil {
				return nil, fmt.Errorf("skip record 0x%02x: %w", opcode, err)
			}
		}
	}

	return res, nil
}

// InspectFile opens the file at path and calls Inspect.
func InspectFile(path string) (*InspectResult, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open: %w", err)
	}
	defer f.Close()
	return Inspect(f)
}
