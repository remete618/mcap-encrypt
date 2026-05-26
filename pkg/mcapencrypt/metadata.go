package mcapencrypt

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
)

// MetadataMode controls how Metadata records are handled during encryption.
type MetadataMode string

const (
	// MetadataPlaintext passes Metadata records through unchanged (default).
	// Compatible with all MCAP readers.
	MetadataPlaintext MetadataMode = "plaintext"

	// MetadataEncrypt encrypts the metadata map while keeping the record name
	// readable without a key. Stored as EncryptedMetadata (opcode 0x83).
	MetadataEncrypt MetadataMode = "encrypt"

	// MetadataEncryptAll encrypts both the name and the map.
	// No information is visible without the private key.
	// Stored as EncryptedMetadata (opcode 0x83) with an empty plaintext name.
	MetadataEncryptAll MetadataMode = "encrypt-all"
)

// metadataFlag values written into the EncryptedMetadata flags byte.
const (
	metadataFlagEncrypt    = byte(0x00) // name plaintext, map encrypted
	metadataFlagEncryptAll = byte(0x01) // name + map both encrypted
)

// EncryptedMetadata is the on-disk format for an encrypted MCAP metadata
// record (opcode 0x83).
//
// Layout:
//
//	flags          uint8   — 0x00: name plaintext / 0x01: name+map encrypted
//	name           string  — plaintext name (4-byte LE length + utf8; empty when flags=0x01)
//	nonce          bytes   — 24-byte XChaCha20Poly1305 nonce (4-byte LE length prefix)
//	encrypted_data bytes   — ciphertext (4-byte LE length prefix)
//
// flags=0x00: encrypted_data covers only the map bytes; AAD = file_id + uint32(len(name)) + name.
// flags=0x01: encrypted_data covers the full metadata payload (name+map); AAD = file_id.
type EncryptedMetadata struct {
	Flags         byte
	Name          string
	Nonce         []byte
	EncryptedData []byte
}

func (m *EncryptedMetadata) Encode() []byte {
	name := []byte(m.Name)

	n := 1 +
		4 + len(name) +
		4 + len(m.Nonce) +
		4 + len(m.EncryptedData)

	buf := make([]byte, n)
	o := 0

	buf[o] = m.Flags
	o++
	put32 := func(v uint32) { binary.LittleEndian.PutUint32(buf[o:], v); o += 4 }
	putBytes := func(b []byte) { put32(uint32(len(b))); copy(buf[o:], b); o += len(b) }

	putBytes(name)
	putBytes(m.Nonce)
	putBytes(m.EncryptedData)

	return buf
}

// DecodeEncryptedMetadata parses a raw EncryptedMetadata record payload.
func DecodeEncryptedMetadata(data []byte) (*EncryptedMetadata, error) {
	if len(data) < 1 {
		return nil, fmt.Errorf("encrypted metadata record too short (%d bytes)", len(data))
	}
	m := &EncryptedMetadata{}
	o := 0

	m.Flags = data[o]
	o++

	if m.Flags != metadataFlagEncrypt && m.Flags != metadataFlagEncryptAll {
		return nil, fmt.Errorf("unknown encrypted metadata flags 0x%02x", m.Flags)
	}

	getBytes := func() ([]byte, error) {
		if o+4 > len(data) {
			return nil, fmt.Errorf("truncated at offset %d reading length", o)
		}
		n := int(binary.LittleEndian.Uint32(data[o:]))
		o += 4
		if o+n > len(data) {
			return nil, fmt.Errorf("truncated at offset %d reading %d bytes", o, n)
		}
		v := make([]byte, n)
		copy(v, data[o:o+n])
		o += n
		return v, nil
	}
	getString := func() (string, error) {
		b, err := getBytes()
		return string(b), err
	}

	var err error
	if m.Name, err = getString(); err != nil {
		return nil, fmt.Errorf("read name: %w", err)
	}
	if m.Nonce, err = getBytes(); err != nil {
		return nil, fmt.Errorf("read nonce: %w", err)
	}
	if m.EncryptedData, err = getBytes(); err != nil {
		return nil, fmt.Errorf("read encrypted_data: %w", err)
	}
	return m, nil
}

// metadataAAD builds AEAD additional data for one encrypted metadata record.
//
// flags=0x00: AAD = file_id + uint32(len(name)) + name
// flags=0x01: AAD = file_id only
func metadataAAD(fileID []byte, flags byte, name string) []byte {
	if flags == metadataFlagEncryptAll {
		buf := make([]byte, fileIDSize)
		copy(buf, fileID)
		return buf
	}
	// flags == metadataFlagEncrypt: bind plaintext name to ciphertext
	nb := []byte(name)
	buf := make([]byte, 0, fileIDSize+4+len(nb))
	buf = append(buf, fileID...)
	var n [4]byte
	binary.LittleEndian.PutUint32(n[:], uint32(len(nb)))
	buf = append(buf, n[:]...)
	buf = append(buf, nb...)
	return buf
}

// splitMetadataPayload splits a raw MCAP Metadata payload into the name string
// and the remaining map bytes (everything after the name field).
func splitMetadataPayload(data []byte) (name string, mapBytes []byte, err error) {
	if len(data) < 4 {
		return "", nil, fmt.Errorf("metadata payload too short (%d bytes)", len(data))
	}
	n := int(binary.LittleEndian.Uint32(data))
	if 4+n > len(data) {
		return "", nil, fmt.Errorf("truncated metadata name (need %d bytes, have %d)", 4+n, len(data))
	}
	return string(data[4 : 4+n]), data[4+n:], nil
}

// reassembleMetadataPayload rebuilds a full MCAP Metadata payload from a
// plaintext name and decrypted map bytes.
func reassembleMetadataPayload(name string, mapBytes []byte) []byte {
	nb := []byte(name)
	buf := make([]byte, 4+len(nb)+len(mapBytes))
	binary.LittleEndian.PutUint32(buf, uint32(len(nb)))
	copy(buf[4:], nb)
	copy(buf[4+len(nb):], mapBytes)
	return buf
}

// encryptMetadataRecord encrypts one raw MCAP Metadata payload according to mode.
// It returns an EncryptedMetadata ready to encode, or an error.
func encryptMetadataRecord(payload, symKey, fileID []byte, mode MetadataMode) (*EncryptedMetadata, error) {
	aead, err := chacha20poly1305.NewX(symKey)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, chacha20poly1305.NonceSizeX)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	switch mode {
	case MetadataEncrypt:
		name, mapBytes, err := splitMetadataPayload(payload)
		if err != nil {
			return nil, fmt.Errorf("split metadata payload: %w", err)
		}
		aad := metadataAAD(fileID, metadataFlagEncrypt, name)
		return &EncryptedMetadata{
			Flags:         metadataFlagEncrypt,
			Name:          name,
			Nonce:         nonce,
			EncryptedData: aead.Seal(nil, nonce, mapBytes, aad),
		}, nil

	case MetadataEncryptAll:
		aad := metadataAAD(fileID, metadataFlagEncryptAll, "")
		return &EncryptedMetadata{
			Flags:         metadataFlagEncryptAll,
			Name:          "",
			Nonce:         nonce,
			EncryptedData: aead.Seal(nil, nonce, payload, aad),
		}, nil

	default:
		return nil, fmt.Errorf("unsupported metadata mode %q", mode)
	}
}

// decryptMetadataRecord decrypts one EncryptedMetadata and returns the
// plaintext MCAP Metadata payload (name + map bytes).
func decryptMetadataRecord(em *EncryptedMetadata, symKey, fileID []byte) ([]byte, error) {
	if len(em.Nonce) != chacha20poly1305.NonceSizeX {
		return nil, fmt.Errorf("nonce length %d invalid (want %d)", len(em.Nonce), chacha20poly1305.NonceSizeX)
	}
	if len(em.EncryptedData) < 16 {
		return nil, fmt.Errorf("ciphertext too short (%d bytes, minimum 16)", len(em.EncryptedData))
	}
	aead, err := chacha20poly1305.NewX(symKey)
	if err != nil {
		return nil, err
	}
	aad := metadataAAD(fileID, em.Flags, em.Name)
	plain, err := aead.Open(nil, em.Nonce, em.EncryptedData, aad)
	if err != nil {
		return nil, fmt.Errorf("AEAD authentication failed")
	}

	switch em.Flags {
	case metadataFlagEncryptAll:
		// plain is the full metadata payload
		return plain, nil
	case metadataFlagEncrypt:
		// plain is map bytes only; prepend the plaintext name
		return reassembleMetadataPayload(em.Name, plain), nil
	default:
		return nil, fmt.Errorf("unknown flags 0x%02x", em.Flags)
	}
}
