package mcapencrypt

import (
	"encoding/binary"
	"fmt"
)

// EncryptedChunk is the on-disk format for an encrypted MCAP chunk (opcode 0x81).
//
// Layout:
//
//	uint64 message_start_time  — plaintext, preserved for indexing
//	uint64 message_end_time    — plaintext
//	uint64 uncompressed_size   — plaintext, for post-decrypt verification
//	uint32 uncompressed_crc    — plaintext, CRC32 of decompressed records
//	string compression         — plaintext ("zstd", "lz4", or "")
//	string key_id              — plaintext, identifies the wrapped key
//	bytes  nonce               — 24 bytes (XChaCha20Poly1305 nonce)
//	bytes  encrypted_data      — ciphertext of the original compressed records
type EncryptedChunk struct {
	MessageStartTime uint64
	MessageEndTime   uint64
	UncompressedSize uint64
	UncompressedCRC  uint32
	Compression      string
	KeyID            string
	Nonce            []byte
	EncryptedData    []byte
}

func (c *EncryptedChunk) Encode() []byte {
	comp := []byte(c.Compression)
	keyID := []byte(c.KeyID)

	n := 8 + 8 + 8 + 4 +
		4 + len(comp) +
		4 + len(keyID) +
		4 + len(c.Nonce) +
		4 + len(c.EncryptedData)

	buf := make([]byte, n)
	o := 0

	put64 := func(v uint64) { binary.LittleEndian.PutUint64(buf[o:], v); o += 8 }
	put32 := func(v uint32) { binary.LittleEndian.PutUint32(buf[o:], v); o += 4 }
	putBytes := func(b []byte) { put32(uint32(len(b))); copy(buf[o:], b); o += len(b) }

	put64(c.MessageStartTime)
	put64(c.MessageEndTime)
	put64(c.UncompressedSize)
	put32(c.UncompressedCRC)
	putBytes(comp)
	putBytes(keyID)
	putBytes(c.Nonce)
	putBytes(c.EncryptedData)

	return buf
}

func DecodeEncryptedChunk(data []byte) (*EncryptedChunk, error) {
	if len(data) < 28 {
		return nil, fmt.Errorf("encrypted chunk record too short (%d bytes)", len(data))
	}
	c := &EncryptedChunk{}
	o := 0

	get64 := func() uint64 { v := binary.LittleEndian.Uint64(data[o:]); o += 8; return v }
	get32 := func() uint32 { v := binary.LittleEndian.Uint32(data[o:]); o += 4; return v }
	getBytes := func() ([]byte, error) {
		if o+4 > len(data) {
			return nil, fmt.Errorf("truncated at offset %d reading length", o)
		}
		n := int(get32())
		if o+n > len(data) {
			return nil, fmt.Errorf("truncated at offset %d reading %d bytes", o, n)
		}
		v := make([]byte, n)
		copy(v, data[o:o+n])
		o += n
		return v, nil
	}
	getString := func() (string, error) { b, err := getBytes(); return string(b), err }

	c.MessageStartTime = get64()
	c.MessageEndTime = get64()
	c.UncompressedSize = get64()
	c.UncompressedCRC = get32()

	var err error
	if c.Compression, err = getString(); err != nil {
		return nil, fmt.Errorf("read compression: %w", err)
	}
	if c.KeyID, err = getString(); err != nil {
		return nil, fmt.Errorf("read key_id: %w", err)
	}
	if c.Nonce, err = getBytes(); err != nil {
		return nil, fmt.Errorf("read nonce: %w", err)
	}
	if c.EncryptedData, err = getBytes(); err != nil {
		return nil, fmt.Errorf("read encrypted_data: %w", err)
	}
	return c, nil
}
