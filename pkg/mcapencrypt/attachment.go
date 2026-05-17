package mcapencrypt

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
)

// EncryptedAttachment is the on-disk format for an encrypted MCAP attachment (opcode 0x82).
//
// Layout:
//
//	string name            — plaintext: attachment name, preserved for seekable access
//	string media_type      — plaintext: MIME type
//	uint64 log_time        — plaintext: nanosecond timestamp from source file
//	uint64 create_time     — plaintext: nanosecond timestamp from source file
//	bytes  nonce           — 24-byte XChaCha20Poly1305 nonce (4-byte LE length prefix)
//	bytes  encrypted_data  — ciphertext of the raw attachment data (4-byte LE length prefix)
//
// AAD binds file_id + name + media_type + log_time + create_time so that
// transplanting an attachment from another file, renaming it, or altering
// its timestamps causes AEAD authentication to fail.
type EncryptedAttachment struct {
	Name          string
	MediaType     string
	LogTime       uint64
	CreateTime    uint64
	Nonce         []byte
	EncryptedData []byte
}

func (a *EncryptedAttachment) Encode() []byte {
	name := []byte(a.Name)
	mt := []byte(a.MediaType)

	n := 4 + len(name) +
		4 + len(mt) +
		8 + 8 +
		4 + len(a.Nonce) +
		4 + len(a.EncryptedData)

	buf := make([]byte, n)
	o := 0

	put64 := func(v uint64) { binary.LittleEndian.PutUint64(buf[o:], v); o += 8 }
	put32 := func(v uint32) { binary.LittleEndian.PutUint32(buf[o:], v); o += 4 }
	putBytes := func(b []byte) { put32(uint32(len(b))); copy(buf[o:], b); o += len(b) }

	putBytes(name)
	putBytes(mt)
	put64(a.LogTime)
	put64(a.CreateTime)
	putBytes(a.Nonce)
	putBytes(a.EncryptedData)

	return buf
}

// DecodeEncryptedAttachment parses a raw EncryptedAttachment record payload.
func DecodeEncryptedAttachment(data []byte) (*EncryptedAttachment, error) {
	if len(data) < 4 {
		return nil, fmt.Errorf("encrypted attachment record too short (%d bytes)", len(data))
	}
	a := &EncryptedAttachment{}
	o := 0

	get64 := func() (uint64, error) {
		if o+8 > len(data) {
			return 0, fmt.Errorf("truncated at offset %d reading uint64", o)
		}
		v := binary.LittleEndian.Uint64(data[o:])
		o += 8
		return v, nil
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
	if a.Name, err = getString(); err != nil {
		return nil, fmt.Errorf("read name: %w", err)
	}
	if a.MediaType, err = getString(); err != nil {
		return nil, fmt.Errorf("read media_type: %w", err)
	}
	if a.LogTime, err = get64(); err != nil {
		return nil, fmt.Errorf("read log_time: %w", err)
	}
	if a.CreateTime, err = get64(); err != nil {
		return nil, fmt.Errorf("read create_time: %w", err)
	}
	if a.Nonce, err = getBytes(); err != nil {
		return nil, fmt.Errorf("read nonce: %w", err)
	}
	if a.EncryptedData, err = getBytes(); err != nil {
		return nil, fmt.Errorf("read encrypted_data: %w", err)
	}
	return a, nil
}

// attachmentAAD builds the AEAD additional data for one encrypted attachment.
// It binds file identity, attachment name, media type, and both timestamps.
// Any modification to these plaintext fields or the ciphertext causes AEAD
// authentication to fail.
func attachmentAAD(fileID []byte, name, mediaType string, logTime, createTime uint64) []byte {
	putStr := func(buf []byte, s string) []byte {
		var n [4]byte
		binary.LittleEndian.PutUint32(n[:], uint32(len(s)))
		buf = append(buf, n[:]...)
		return append(buf, s...)
	}
	buf := make([]byte, 0, fileIDSize+4+len(name)+4+len(mediaType)+8+8)
	buf = append(buf, fileID...)
	buf = putStr(buf, name)
	buf = putStr(buf, mediaType)
	buf = binary.LittleEndian.AppendUint64(buf, logTime)
	buf = binary.LittleEndian.AppendUint64(buf, createTime)
	return buf
}

// encryptAttachmentData encrypts one attachment's raw data with the file symmetric key.
func encryptAttachmentData(data, symKey, fileID []byte, name, mediaType string, logTime, createTime uint64) (*EncryptedAttachment, error) {
	aead, err := chacha20poly1305.NewX(symKey)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, chacha20poly1305.NonceSizeX)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	aad := attachmentAAD(fileID, name, mediaType, logTime, createTime)
	return &EncryptedAttachment{
		Name:          name,
		MediaType:     mediaType,
		LogTime:       logTime,
		CreateTime:    createTime,
		Nonce:         nonce,
		EncryptedData: aead.Seal(nil, nonce, data, aad),
	}, nil
}

// decryptAttachmentData decrypts one EncryptedAttachment and returns the plaintext data.
func decryptAttachmentData(ea *EncryptedAttachment, symKey, fileID []byte) ([]byte, error) {
	if len(ea.Nonce) != chacha20poly1305.NonceSizeX {
		return nil, fmt.Errorf("nonce length %d invalid (want %d)", len(ea.Nonce), chacha20poly1305.NonceSizeX)
	}
	if len(ea.EncryptedData) < 16 {
		return nil, fmt.Errorf("ciphertext too short (%d bytes, minimum 16)", len(ea.EncryptedData))
	}
	aead, err := chacha20poly1305.NewX(symKey)
	if err != nil {
		return nil, err
	}
	aad := attachmentAAD(fileID, ea.Name, ea.MediaType, ea.LogTime, ea.CreateTime)
	plain, err := aead.Open(nil, ea.Nonce, ea.EncryptedData, aad)
	if err != nil {
		return nil, fmt.Errorf("AEAD authentication failed")
	}
	return plain, nil
}
