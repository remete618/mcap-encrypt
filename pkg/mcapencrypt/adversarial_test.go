package mcapencrypt_test

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"

	"github.com/foxglove/mcap/go/mcap"
	"github.com/stretchr/testify/require"

	"github.com/remete618/mcap-encrypt/pkg/mcapencrypt"
)

func findFirstEncryptedChunk(t *testing.T, data []byte) (recStart, recLen int) {
	t.Helper()
	pos := 8
	for pos+9 <= len(data) {
		opcode := data[pos]
		n := int(binary.LittleEndian.Uint64(data[pos+1:]))
		if opcode == 0x81 {
			return pos + 9, n
		}
		pos += 9 + n
	}
	t.Fatal("no encrypted chunk (0x81) found")
	return 0, 0
}

func TestTamperedNonce(t *testing.T) {
	dir := t.TempDir()
	plainPath := filepath.Join(dir, "plain.mcap")
	encPath := filepath.Join(dir, "enc.mcap")
	decPath := filepath.Join(dir, "dec.mcap")
	keyBase := filepath.Join(dir, "key")

	buildTestMCAP(t, plainPath)
	require.NoError(t, mcapencrypt.GenerateKeyPair(keyBase))
	require.NoError(t, mcapencrypt.Encrypt(plainPath, encPath, keyBase+".pub.pem"))

	data, err := os.ReadFile(encPath)
	require.NoError(t, err)
	recStart, recLen := findFirstEncryptedChunk(t, data)

	// Decode the chunk to find the nonce offset structurally rather than with a
	// hardcoded constant, so the test survives changes to slot_id or compression.
	ec, parseErr := mcapencrypt.DecodeEncryptedChunk(data[recStart : recStart+recLen])
	require.NoError(t, parseErr)

	// nonce is at: fixed fields(28) + compression string(4+len) + slot_id string(4+len) + nonce len prefix(4)
	nonceOffset := 28 + 4 + len(ec.Compression) + 4 + len(ec.SlotID) + 4

	tampered := make([]byte, len(data))
	copy(tampered, data)
	tampered[recStart+nonceOffset] ^= 0xFF

	require.NoError(t, os.WriteFile(encPath, tampered, 0o644))
	err = mcapencrypt.Decrypt(encPath, decPath, keyBase+".priv.pem")
	require.Error(t, err)
	require.Contains(t, err.Error(), "authentication failed")
}

func TestTamperedAAD(t *testing.T) {
	dir := t.TempDir()
	plainPath := filepath.Join(dir, "plain.mcap")
	encPath := filepath.Join(dir, "enc.mcap")
	decPath := filepath.Join(dir, "dec.mcap")
	keyBase := filepath.Join(dir, "key")

	buildTestMCAP(t, plainPath)
	require.NoError(t, mcapencrypt.GenerateKeyPair(keyBase))
	require.NoError(t, mcapencrypt.Encrypt(plainPath, encPath, keyBase+".pub.pem"))

	data, err := os.ReadFile(encPath)
	require.NoError(t, err)
	recStart, _ := findFirstEncryptedChunk(t, data)

	// Flip the first byte of message_start_time (offset 0 in record data).
	// The decrypt side computes AAD from message_start_time and message_end_time,
	// so changing this field changes the AAD, causing AEAD authentication failure.
	tampered := make([]byte, len(data))
	copy(tampered, data)
	tampered[recStart] ^= 0xFF

	require.NoError(t, os.WriteFile(encPath, tampered, 0o644))
	err = mcapencrypt.Decrypt(encPath, decPath, keyBase+".priv.pem")
	require.Error(t, err)
	require.Contains(t, err.Error(), "authentication failed")
}

func TestTamperedCiphertext(t *testing.T) {
	dir := t.TempDir()
	plainPath := filepath.Join(dir, "plain.mcap")
	encPath := filepath.Join(dir, "enc.mcap")
	decPath := filepath.Join(dir, "dec.mcap")
	keyBase := filepath.Join(dir, "key")

	buildTestMCAP(t, plainPath)
	require.NoError(t, mcapencrypt.GenerateKeyPair(keyBase))
	require.NoError(t, mcapencrypt.Encrypt(plainPath, encPath, keyBase+".pub.pem"))

	data, err := os.ReadFile(encPath)
	require.NoError(t, err)
	recStart, recLen := findFirstEncryptedChunk(t, data)

	// Flip a byte near the middle of the encrypted data (well past headers).
	tampered := make([]byte, len(data))
	copy(tampered, data)
	tampered[recStart+recLen/2] ^= 0xFF

	require.NoError(t, os.WriteFile(encPath, tampered, 0o644))
	err = mcapencrypt.Decrypt(encPath, decPath, keyBase+".priv.pem")
	require.Error(t, err)
	require.Contains(t, err.Error(), "authentication failed")
}

func TestWrongKeyError(t *testing.T) {
	dir := t.TempDir()
	plainPath := filepath.Join(dir, "plain.mcap")
	encPath := filepath.Join(dir, "enc.mcap")
	decPath := filepath.Join(dir, "dec.mcap")
	encKey := filepath.Join(dir, "enc-key")
	decKey := filepath.Join(dir, "dec-key")

	buildTestMCAP(t, plainPath)
	require.NoError(t, mcapencrypt.GenerateKeyPair(encKey))
	require.NoError(t, mcapencrypt.GenerateKeyPair(decKey))
	require.NoError(t, mcapencrypt.Encrypt(plainPath, encPath, encKey+".pub.pem"))

	err := mcapencrypt.Decrypt(encPath, decPath, decKey+".priv.pem")
	require.Error(t, err)
	require.Contains(t, err.Error(), "private key does not match")
}

// stripManifestAttachment returns a copy of data with the manifest attachment
// record removed, simulating a strip attack on a v3 file.
func stripManifestAttachment(t *testing.T, data []byte) []byte {
	t.Helper()
	var out []byte
	out = append(out, data[:8]...) // magic
	pos := 8
	for pos+9 <= len(data) {
		opcode := data[pos]
		n := int(binary.LittleEndian.Uint64(data[pos+1:]))
		rec := data[pos : pos+9+n]
		if opcode == 0x09 { // opcodeAttach = 0x09
			// Parse name from attachment: logTime(8)+createTime(8)+nameLen(4)+name
			payload := data[pos+9 : pos+9+n]
			if len(payload) >= 28 {
				nameLen := int(binary.LittleEndian.Uint32(payload[16:20]))
				if 20+nameLen <= len(payload) {
					name := string(payload[20 : 20+nameLen])
					if name == mcapencrypt.ManifestAttachmentName {
						pos += 9 + n
						continue // drop this record
					}
				}
			}
		}
		out = append(out, rec...)
		pos += 9 + n
	}
	return out
}

// TestManifestStrippedV3Rejected verifies that stripping the manifest from a
// v3 file (the current format version) causes decryption to fail.
func TestManifestStrippedV3Rejected(t *testing.T) {
	dir := t.TempDir()
	plainPath := filepath.Join(dir, "plain.mcap")
	encPath := filepath.Join(dir, "enc.mcap")
	strippedPath := filepath.Join(dir, "stripped.mcap")
	decPath := filepath.Join(dir, "dec.mcap")
	keyBase := filepath.Join(dir, "key")

	buildTestMCAP(t, plainPath)
	require.NoError(t, mcapencrypt.GenerateKeyPair(keyBase))
	require.NoError(t, mcapencrypt.Encrypt(plainPath, encPath, keyBase+".pub.pem"))

	data, err := os.ReadFile(encPath)
	require.NoError(t, err)
	stripped := stripManifestAttachment(t, data)
	require.Less(t, len(stripped), len(data), "stripped file should be smaller")
	require.NoError(t, os.WriteFile(strippedPath, stripped, 0o644))

	err = mcapencrypt.Decrypt(strippedPath, decPath, keyBase+".priv.pem")
	require.Error(t, err)
	require.Contains(t, err.Error(), "manifest attachment missing")
}

// TestNonceUniquenessAcrossChunks verifies that each EncryptedChunk in a file
// receives a distinct random nonce. Nonce reuse under XChaCha20-Poly1305 with the
// same key leaks the XOR of plaintexts and breaks authentication.
func TestNonceUniquenessAcrossChunks(t *testing.T) {
	dir := t.TempDir()
	plainPath := filepath.Join(dir, "plain.mcap")
	encPath := filepath.Join(dir, "enc.mcap")
	keyBase := filepath.Join(dir, "key")

	buildTestMCAP(t, plainPath)
	require.NoError(t, mcapencrypt.GenerateKeyPair(keyBase))
	require.NoError(t, mcapencrypt.Encrypt(plainPath, encPath, keyBase+".pub.pem"))

	data, err := os.ReadFile(encPath)
	require.NoError(t, err)

	nonces := map[string]struct{}{}
	pos := 8
	for pos+9 <= len(data) {
		opcode := data[pos]
		n := int(binary.LittleEndian.Uint64(data[pos+1:]))
		if opcode == mcapencrypt.OpcodeEncryptedChunk {
			ec, parseErr := mcapencrypt.DecodeEncryptedChunk(data[pos+9 : pos+9+n])
			require.NoError(t, parseErr)
			key := string(ec.Nonce)
			_, duplicate := nonces[key]
			require.False(t, duplicate, "nonce reused between chunks: %x", ec.Nonce)
			nonces[key] = struct{}{}
		}
		pos += 9 + n
	}
	require.Greater(t, len(nonces), 1, "test requires at least 2 encrypted chunks; verify ChunkSize in buildTestMCAP")
}

// TestAADFieldsTampering verifies that each field included in the AEAD additional
// data is actually bound to the authentication tag. Modifying any AAD field in the
// plaintext header of an EncryptedChunk must cause decryption to fail, proving no
// field can be silently altered after encryption.
//
// AAD covers: fileID, chunkIdx, slot_id, compression, uncompressed_size,
// uncompressed_crc, message_start_time, and message_end_time.
// message_start_time is already tested in TestTamperedAAD.
func TestAADFieldsTampering(t *testing.T) {
	dir := t.TempDir()
	plainPath := filepath.Join(dir, "plain.mcap")
	encPath := filepath.Join(dir, "enc.mcap")
	keyBase := filepath.Join(dir, "key")

	buildTestMCAP(t, plainPath)
	require.NoError(t, mcapencrypt.GenerateKeyPair(keyBase))
	require.NoError(t, mcapencrypt.Encrypt(plainPath, encPath, keyBase+".pub.pem"))

	data, err := os.ReadFile(encPath)
	require.NoError(t, err)
	recStart, recLen := findFirstEncryptedChunk(t, data)

	ec, parseErr := mcapencrypt.DecodeEncryptedChunk(data[recStart : recStart+recLen])
	require.NoError(t, parseErr)

	// tamperField re-encodes a modified EncryptedChunk, splices it back into the
	// file in-place (same byte length), and asserts that decryption fails with an
	// authentication error.
	tamperField := func(t *testing.T, mod *mcapencrypt.EncryptedChunk) {
		t.Helper()
		newData := mod.Encode()
		require.Equal(t, recLen, len(newData), "re-encoded chunk must have same byte length for in-place splice")
		tampered := make([]byte, len(data))
		copy(tampered, data)
		copy(tampered[recStart:], newData)

		tmpDir := t.TempDir()
		tamperedPath := filepath.Join(tmpDir, "tampered.mcap")
		decPath := filepath.Join(tmpDir, "out.mcap")
		require.NoError(t, os.WriteFile(tamperedPath, tampered, 0o644))
		decErr := mcapencrypt.Decrypt(tamperedPath, decPath, keyBase+".priv.pem")
		require.Error(t, decErr)
		require.Contains(t, decErr.Error(), "authentication failed")
	}

	t.Run("MessageEndTime", func(t *testing.T) {
		mod := *ec
		mod.MessageEndTime ^= 1
		tamperField(t, &mod)
	})
	t.Run("UncompressedSize", func(t *testing.T) {
		mod := *ec
		mod.UncompressedSize ^= 1
		tamperField(t, &mod)
	})
	t.Run("UncompressedCRC", func(t *testing.T) {
		mod := *ec
		mod.UncompressedCRC ^= 1
		tamperField(t, &mod)
	})
	t.Run("SlotID", func(t *testing.T) {
		mod := *ec
		b := []byte(ec.SlotID)
		b[len(b)-1] ^= 0xFF
		mod.SlotID = string(b)
		tamperField(t, &mod)
	})
	t.Run("Compression", func(t *testing.T) {
		mod := *ec
		b := []byte(ec.Compression)
		b[0] ^= 0xFF
		mod.Compression = string(b)
		tamperField(t, &mod)
	})
}

// tamperWrappedKeyFileID locates the wrapped-key attachment in data and flips a
// byte in the FileID field of its WrappedKeyData payload. The FileID is the first
// 16 bytes after the version byte; it is included in the AAD of every encrypted
// chunk, so any modification must cause authentication to fail.
func tamperWrappedKeyFileID(t *testing.T, data []byte) []byte {
	t.Helper()
	tampered := make([]byte, len(data))
	copy(tampered, data)

	pos := 8
	for pos+9 <= len(data) {
		opcode := data[pos]
		n := int(binary.LittleEndian.Uint64(data[pos+1:]))
		if opcode == 0x09 && pos+9+n <= len(data) {
			payload := data[pos+9 : pos+9+n]
			if len(payload) <= 20 {
				pos += 9 + n
				continue
			}
			nameLen := int(binary.LittleEndian.Uint32(payload[16:20]))
			if 20+nameLen > len(payload) || string(payload[20:20+nameLen]) != mcapencrypt.AttachmentName {
				pos += 9 + n
				continue
			}
			// Advance past name to mediaType length prefix.
			o := 20 + nameLen
			if o+4 > len(payload) {
				t.Fatal("attachment too short to read mediaType length")
			}
			mediaTypeLen := int(binary.LittleEndian.Uint32(payload[o:]))
			o += 4 + mediaTypeLen + 8 // skip mediaType bytes and dataSize field
			// WrappedKeyData layout: version(1) + fileID(16) + ...
			// fileID starts at o+1.
			if o+1+16 > len(payload) {
				t.Fatal("attachment too short to contain WrappedKeyData fileID")
			}
			tampered[pos+9+o+1] ^= 0xFF
			return tampered
		}
		pos += 9 + n
	}
	t.Fatal("wrapped-key attachment not found in encrypted file")
	return nil
}

// TestWrappedKeyFileIDTamperRejected verifies that the FileID stored in the
// wrapped-key attachment is bound to chunk authentication. The FileID is
// included in the AAD of every EncryptedChunk; tampering it causes aead.Open to
// fail with an authentication error on the first chunk, before the manifest check.
func TestWrappedKeyFileIDTamperRejected(t *testing.T) {
	dir := t.TempDir()
	plainPath := filepath.Join(dir, "plain.mcap")
	encPath := filepath.Join(dir, "enc.mcap")
	keyBase := filepath.Join(dir, "key")

	buildTestMCAP(t, plainPath)
	require.NoError(t, mcapencrypt.GenerateKeyPair(keyBase))
	require.NoError(t, mcapencrypt.Encrypt(plainPath, encPath, keyBase+".pub.pem"))

	data, err := os.ReadFile(encPath)
	require.NoError(t, err)
	tampered := tamperWrappedKeyFileID(t, data)

	tamperedPath := filepath.Join(dir, "tampered.mcap")
	require.NoError(t, os.WriteFile(tamperedPath, tampered, 0o644))

	decErr := mcapencrypt.Decrypt(tamperedPath, filepath.Join(dir, "out.mcap"), keyBase+".priv.pem")
	require.Error(t, decErr)
	require.Contains(t, decErr.Error(), "authentication failed")
}

// TestReadRecordOversizedLengthRejected verifies that ReadRecord rejects a record
// whose length field exceeds maxRecordDataSize (1 << 32). This is the boundary
// condition fixed by INT-2025-001; values above the limit previously caused a
// runtime panic in make([]byte, length).
func TestReadRecordOversizedLengthRejected(t *testing.T) {
	var buf bytes.Buffer
	buf.WriteByte(0x01)
	var lenBuf [8]byte
	binary.LittleEndian.PutUint64(lenBuf[:], (1<<32)+1) // one above the limit
	buf.Write(lenBuf[:])

	_, _, err := mcapencrypt.ReadRecord(&buf)
	require.Error(t, err)
	require.Contains(t, err.Error(), "exceeds maximum allowed size")
}

// TestReadRecordAtLimit verifies that a record with length exactly equal to
// maxRecordDataSize is rejected. The guard uses strict greater-than, so the
// limit itself is the first accepted value only up to the constant boundary.
func TestReadRecordAtLimit(t *testing.T) {
	var buf bytes.Buffer
	buf.WriteByte(0x01)
	var lenBuf [8]byte
	binary.LittleEndian.PutUint64(lenBuf[:], 1<<32) // exactly at the limit
	buf.Write(lenBuf[:])
	// The header is valid; the record body (4 GiB) cannot be read from the buffer.
	// ReadRecord will fail on io.ReadFull, not on the size guard.
	_, _, err := mcapencrypt.ReadRecord(&buf)
	require.Error(t, err)
	require.NotContains(t, err.Error(), "exceeds maximum allowed size",
		"the limit itself should not be rejected by the size guard; failure must be io.ReadFull")
}

// findEncryptedAttachment locates the first 0x82 record in raw MCAP bytes.
// Returns the byte offset of the record's data field and the data length.
func findEncryptedAttachment(t *testing.T, data []byte) (dataStart, dataLen int) {
	t.Helper()
	pos := 8
	for pos+9 <= len(data) {
		opcode := data[pos]
		n := int(binary.LittleEndian.Uint64(data[pos+1:]))
		if opcode == mcapencrypt.OpcodeEncryptedAttachment {
			return pos + 9, n
		}
		pos += 9 + n
	}
	t.Fatal("no EncryptedAttachment (0x82) found")
	return 0, 0
}

// TestEncryptedAttachmentCiphertextTamperRejected flips a byte in the
// EncryptedData field; AEAD must reject decryption.
func TestEncryptedAttachmentCiphertextTamperRejected(t *testing.T) {
	dir := t.TempDir()
	plainPath := filepath.Join(dir, "plain.mcap")
	encPath := filepath.Join(dir, "enc.mcap")
	decPath := filepath.Join(dir, "dec.mcap")
	keyBase := filepath.Join(dir, "key")

	buildTestMCAPWithAttachment(t, plainPath)
	require.NoError(t, mcapencrypt.GenerateKeyPair(keyBase))
	require.NoError(t, mcapencrypt.Encrypt(plainPath, encPath, keyBase+".pub.pem"))

	raw, err := os.ReadFile(encPath)
	require.NoError(t, err)
	dataStart, dataLen := findEncryptedAttachment(t, raw)

	// Decode the record to find the EncryptedData bytes offset.
	ea, err := mcapencrypt.DecodeEncryptedAttachment(raw[dataStart : dataStart+dataLen])
	require.NoError(t, err)

	// Calculate byte offset of encrypted_data payload within the record:
	// name(4+len) + media_type(4+len) + log_time(8) + create_time(8) + nonce(4+24) + encrypted_data_len(4)
	encDataOffset := dataStart + 4 + len(ea.Name) + 4 + len(ea.MediaType) + 8 + 8 + 4 + len(ea.Nonce) + 4

	tampered := make([]byte, len(raw))
	copy(tampered, raw)
	tampered[encDataOffset] ^= 0xFF

	require.NoError(t, os.WriteFile(encPath, tampered, 0o644))
	err = mcapencrypt.Decrypt(encPath, decPath, keyBase+".priv.pem")
	require.Error(t, err)
	require.Contains(t, err.Error(), "authentication failed")
}

// TestEncryptedAttachmentNameTamperRejected changes the plaintext name field;
// since name is part of the AAD, decryption must fail.
func TestEncryptedAttachmentNameTamperRejected(t *testing.T) {
	dir := t.TempDir()
	plainPath := filepath.Join(dir, "plain.mcap")
	encPath := filepath.Join(dir, "enc.mcap")
	decPath := filepath.Join(dir, "dec.mcap")
	keyBase := filepath.Join(dir, "key")

	buildTestMCAPWithAttachment(t, plainPath)
	require.NoError(t, mcapencrypt.GenerateKeyPair(keyBase))
	require.NoError(t, mcapencrypt.Encrypt(plainPath, encPath, keyBase+".pub.pem"))

	raw, err := os.ReadFile(encPath)
	require.NoError(t, err)
	dataStart, dataLen := findEncryptedAttachment(t, raw)
	ea, err := mcapencrypt.DecodeEncryptedAttachment(raw[dataStart : dataStart+dataLen])
	require.NoError(t, err)
	require.Equal(t, "config.json", ea.Name, "test fixture must produce attachment named config.json")

	// Flip one byte inside the name string (name length prefix is 4 bytes).
	// "config.json" → flip 'c' → the AAD name will differ from the one used at encrypt time.
	nameOffset := dataStart + 4
	tampered := make([]byte, len(raw))
	copy(tampered, raw)
	tampered[nameOffset] ^= 0x01

	require.NoError(t, os.WriteFile(encPath, tampered, 0o644))
	err = mcapencrypt.Decrypt(encPath, decPath, keyBase+".priv.pem")
	require.Error(t, err)
	require.Contains(t, err.Error(), "authentication failed")
}

func TestNonChunkedInputRejected(t *testing.T) {
	dir := t.TempDir()
	flatPath := filepath.Join(dir, "flat.mcap")
	encPath := filepath.Join(dir, "enc.mcap")
	keyBase := filepath.Join(dir, "key")

	f, createErr := os.Create(flatPath)
	require.NoError(t, createErr)
	w, err := mcap.NewWriter(f, &mcap.WriterOptions{Chunked: false})
	require.NoError(t, err)
	require.NoError(t, w.WriteHeader(&mcap.Header{Profile: "test"}))
	require.NoError(t, w.WriteSchema(&mcap.Schema{ID: 1, Name: "s", Encoding: "json", Data: []byte(`{}`)}))
	require.NoError(t, w.WriteChannel(&mcap.Channel{ID: 1, SchemaID: 1, Topic: "/t", MessageEncoding: "json"}))
	require.NoError(t, w.WriteMessage(&mcap.Message{ChannelID: 1, Data: []byte(`{}`)}))
	require.NoError(t, w.Close())
	f.Close()

	require.NoError(t, mcapencrypt.GenerateKeyPair(keyBase))
	err = mcapencrypt.Encrypt(flatPath, encPath, keyBase+".pub.pem")
	require.Error(t, err)
	require.Contains(t, err.Error(), "not chunked")
}
