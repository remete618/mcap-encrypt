package mcapencrypt_test

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/remete618/mcap-encrypt/pkg/mcapencrypt"
)

// TestRSA4096RoundTrip verifies encrypt/decrypt with RSA-4096 keys.
func TestRSA4096RoundTrip(t *testing.T) {
	dir := t.TempDir()
	plainPath := filepath.Join(dir, "plain.mcap")
	encPath := filepath.Join(dir, "enc.mcap")
	decPath := filepath.Join(dir, "dec.mcap")
	keyBase := filepath.Join(dir, "key")

	buildTestMCAP(t, plainPath)
	require.NoError(t, mcapencrypt.GenerateKeyPair(keyBase))

	require.NoError(t, mcapencrypt.Encrypt(plainPath, encPath, keyBase+".pub.pem"))
	require.NoError(t, mcapencrypt.Decrypt(encPath, decPath, keyBase+".priv.pem"))

	origMsgs := readAllMessages(t, plainPath)
	decMsgs := readAllMessages(t, decPath)
	require.Equal(t, len(origMsgs), len(decMsgs))
	for i, om := range origMsgs {
		require.Equal(t, om.Data, decMsgs[i].Data, "message %d data mismatch", i)
	}
}

// TestX25519RoundTrip verifies encrypt/decrypt with X25519 keys.
func TestX25519RoundTrip(t *testing.T) {
	dir := t.TempDir()
	plainPath := filepath.Join(dir, "plain.mcap")
	encPath := filepath.Join(dir, "enc.mcap")
	decPath := filepath.Join(dir, "dec.mcap")
	keyBase := filepath.Join(dir, "key")

	buildTestMCAP(t, plainPath)
	require.NoError(t, mcapencrypt.GenerateX25519KeyPair(keyBase))

	require.NoError(t, mcapencrypt.Encrypt(plainPath, encPath, keyBase+".pub.pem"))
	require.NoError(t, mcapencrypt.Decrypt(encPath, decPath, keyBase+".priv.pem"))

	origMsgs := readAllMessages(t, plainPath)
	decMsgs := readAllMessages(t, decPath)
	require.Equal(t, len(origMsgs), len(decMsgs))
	for i, om := range origMsgs {
		require.Equal(t, om.Data, decMsgs[i].Data, "message %d data mismatch", i)
	}
}

// TestX25519WrongKeyRejected verifies an X25519 private key that was not a recipient cannot decrypt.
func TestX25519WrongKeyRejected(t *testing.T) {
	dir := t.TempDir()
	plainPath := filepath.Join(dir, "plain.mcap")
	encPath := filepath.Join(dir, "enc.mcap")
	keyA := filepath.Join(dir, "keyA")
	keyB := filepath.Join(dir, "keyB")

	buildTestMCAP(t, plainPath)
	require.NoError(t, mcapencrypt.GenerateX25519KeyPair(keyA))
	require.NoError(t, mcapencrypt.GenerateX25519KeyPair(keyB))
	require.NoError(t, mcapencrypt.Encrypt(plainPath, encPath, keyA+".pub.pem"))

	err := mcapencrypt.Decrypt(encPath, filepath.Join(dir, "out.mcap"), keyB+".priv.pem")
	require.Error(t, err)
	require.Contains(t, err.Error(), "private key does not match")
}

// TestMixedAlgorithmRecipients verifies a file can be encrypted for both RSA and X25519 recipients.
func TestMixedAlgorithmRecipients(t *testing.T) {
	dir := t.TempDir()
	plainPath := filepath.Join(dir, "plain.mcap")
	encPath := filepath.Join(dir, "enc.mcap")
	rsaKey := filepath.Join(dir, "rsa")
	x25519Key := filepath.Join(dir, "x25519")

	buildTestMCAP(t, plainPath)
	require.NoError(t, mcapencrypt.GenerateKeyPair(rsaKey))
	require.NoError(t, mcapencrypt.GenerateX25519KeyPair(x25519Key))

	require.NoError(t, mcapencrypt.EncryptMulti(plainPath, encPath, []string{
		rsaKey + ".pub.pem",
		x25519Key + ".pub.pem",
	}))

	origMsgs := readAllMessages(t, plainPath)

	for _, priv := range []string{rsaKey + ".priv.pem", x25519Key + ".priv.pem"} {
		decPath := filepath.Join(dir, filepath.Base(priv)+".dec.mcap")
		require.NoError(t, mcapencrypt.Decrypt(encPath, decPath, priv), "decrypt with %s", priv)
		decMsgs := readAllMessages(t, decPath)
		require.Equal(t, len(origMsgs), len(decMsgs))
	}
}

// TestMultiRecipientOutputConsistency verifies that all recipients of a
// multi-recipient file recover byte-identical plaintext. A bug in key wrapping
// that produced different symmetric keys per recipient would pass round-trip tests
// but fail here.
func TestMultiRecipientOutputConsistency(t *testing.T) {
	dir := t.TempDir()
	plainPath := filepath.Join(dir, "plain.mcap")
	encPath := filepath.Join(dir, "enc.mcap")
	rsaKey := filepath.Join(dir, "rsa")
	x25519Key := filepath.Join(dir, "x25519")

	buildTestMCAP(t, plainPath)
	require.NoError(t, mcapencrypt.GenerateKeyPair(rsaKey))
	require.NoError(t, mcapencrypt.GenerateX25519KeyPair(x25519Key))

	require.NoError(t, mcapencrypt.EncryptMulti(plainPath, encPath, []string{
		rsaKey + ".pub.pem",
		x25519Key + ".pub.pem",
	}))

	decRSA := filepath.Join(dir, "dec-rsa.mcap")
	decX25519 := filepath.Join(dir, "dec-x25519.mcap")
	require.NoError(t, mcapencrypt.Decrypt(encPath, decRSA, rsaKey+".priv.pem"))
	require.NoError(t, mcapencrypt.Decrypt(encPath, decX25519, x25519Key+".priv.pem"))

	rsaMsgs := readAllMessages(t, decRSA)
	x25519Msgs := readAllMessages(t, decX25519)
	require.Equal(t, len(rsaMsgs), len(x25519Msgs), "recipient decryptions must yield the same message count")
	for i := range rsaMsgs {
		require.Equal(t, rsaMsgs[i].Data, x25519Msgs[i].Data,
			"message %d payload differs between RSA and X25519 decryption; both must recover identical plaintext", i)
	}
}

// TestRSAKeyCannotDecryptX25519File verifies RSA private key fails on X25519-encrypted file.
func TestRSAKeyCannotDecryptX25519File(t *testing.T) {
	dir := t.TempDir()
	plainPath := filepath.Join(dir, "plain.mcap")
	encPath := filepath.Join(dir, "enc.mcap")
	x25519Key := filepath.Join(dir, "x25519")
	rsaKey := filepath.Join(dir, "rsa")

	buildTestMCAP(t, plainPath)
	require.NoError(t, mcapencrypt.GenerateX25519KeyPair(x25519Key))
	require.NoError(t, mcapencrypt.GenerateKeyPair(rsaKey))
	require.NoError(t, mcapencrypt.Encrypt(plainPath, encPath, x25519Key+".pub.pem"))

	err := mcapencrypt.Decrypt(encPath, filepath.Join(dir, "out.mcap"), rsaKey+".priv.pem")
	require.Error(t, err)
	require.Contains(t, err.Error(), "private key does not match")
}

// TestManifestDetectsTailTruncation verifies that removing the last chunk causes a manifest error.
func TestManifestDetectsTailTruncation(t *testing.T) {
	dir := t.TempDir()
	plainPath := filepath.Join(dir, "plain.mcap")
	encPath := filepath.Join(dir, "enc.mcap")
	keyBase := filepath.Join(dir, "key")

	buildTestMCAP(t, plainPath)
	require.NoError(t, mcapencrypt.GenerateKeyPair(keyBase))
	require.NoError(t, mcapencrypt.Encrypt(plainPath, encPath, keyBase+".pub.pem"))

	data, err := os.ReadFile(encPath)
	require.NoError(t, err)

	// Find the last EncryptedChunk (0x81) record and truncate just before it
	// to simulate tail truncation of a chunk.
	lastChunkPos := -1
	pos := 8
	for pos+9 <= len(data) {
		if data[pos] == 0x81 {
			lastChunkPos = pos
		}
		n := int(binary.LittleEndian.Uint64(data[pos+1:]))
		pos += 9 + n
	}
	require.Greater(t, lastChunkPos, -1, "test file must have at least one EncryptedChunk")

	// Write a truncated file that is missing the last chunk and everything after it.
	truncData := data[:lastChunkPos]
	truncPath := filepath.Join(dir, "trunc.mcap")
	require.NoError(t, os.WriteFile(truncPath, truncData, 0o644))

	err = mcapencrypt.Decrypt(truncPath, filepath.Join(dir, "out.mcap"), keyBase+".priv.pem")
	require.Error(t, err)
	// Error could be manifest mismatch OR missing chunks depending on truncation point;
	// either is acceptable — the key check is that no silent success occurs.
	t.Logf("tail truncation error: %v", err)
}

// TestManifestTamperedCountRejected verifies a forged chunk count is caught.
func TestManifestTamperedCountRejected(t *testing.T) {
	dir := t.TempDir()
	plainPath := filepath.Join(dir, "plain.mcap")
	encPath := filepath.Join(dir, "enc.mcap")
	keyBase := filepath.Join(dir, "key")

	buildTestMCAP(t, plainPath)
	require.NoError(t, mcapencrypt.GenerateKeyPair(keyBase))
	require.NoError(t, mcapencrypt.Encrypt(plainPath, encPath, keyBase+".pub.pem"))

	data, err := os.ReadFile(encPath)
	require.NoError(t, err)
	tampered := tamperManifestCount(t, data, 999)

	tamperedPath := filepath.Join(dir, "tampered.mcap")
	require.NoError(t, os.WriteFile(tamperedPath, tampered, 0o644))

	err = mcapencrypt.Decrypt(tamperedPath, filepath.Join(dir, "out.mcap"), keyBase+".priv.pem")
	require.Error(t, err)
	require.Contains(t, err.Error(), "manifest HMAC verification failed")
}

// TestSlotIDWireFormat verifies the slot_id wire value stays "key-1".
func TestSlotIDWireFormat(t *testing.T) {
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
	require.Equal(t, "key-1", ec.SlotID, "slot_id wire value must remain \"key-1\"")
}

// TestWrapUnwrapX25519 unit-tests X25519 key wrapping through a full encrypt/decrypt round-trip.
func TestWrapUnwrapX25519(t *testing.T) {
	dir := t.TempDir()
	keyBase := filepath.Join(dir, "key")
	require.NoError(t, mcapencrypt.GenerateX25519KeyPair(keyBase))

	pub, err := mcapencrypt.LoadPublicKeyAny(keyBase + ".pub.pem")
	require.NoError(t, err)
	require.NotNil(t, pub)

	priv, err := mcapencrypt.LoadPrivateKeyAny(keyBase + ".priv.pem")
	require.NoError(t, err)
	require.NotNil(t, priv)

	// Verify type round-trip via a second key pair.
	keyBase2 := filepath.Join(dir, "key2")
	require.NoError(t, mcapencrypt.GenerateX25519KeyPair(keyBase2))

	// Full round-trip: encrypt with key, decrypt fails with key2, decrypt succeeds with key.
	plainPath := filepath.Join(dir, "plain.mcap")
	buildTestMCAP(t, plainPath)

	encPath := filepath.Join(dir, "enc.mcap")
	require.NoError(t, mcapencrypt.Encrypt(plainPath, encPath, keyBase+".pub.pem"))

	err = mcapencrypt.Decrypt(encPath, filepath.Join(dir, "wrong.mcap"), keyBase2+".priv.pem")
	require.Error(t, err)

	decPath := filepath.Join(dir, "dec.mcap")
	require.NoError(t, mcapencrypt.Decrypt(encPath, decPath, keyBase+".priv.pem"))

	orig := readAllMessages(t, plainPath)
	dec := readAllMessages(t, decPath)
	require.Equal(t, len(orig), len(dec))
}

// TestManifestHMACConsistency unit-tests ComputeManifestHMAC determinism.
func TestManifestHMACConsistency(t *testing.T) {
	symKey := bytes.Repeat([]byte{0xAB}, 32)
	fileID := bytes.Repeat([]byte{0xCD}, 16)
	mac1 := mcapencrypt.ComputeManifestHMAC(symKey, 7, fileID)
	mac2 := mcapencrypt.ComputeManifestHMAC(symKey, 7, fileID)
	require.True(t, hmac.Equal(mac1, mac2), "HMAC must be deterministic")
	require.Len(t, mac1, sha256.Size)

	macDiff := mcapencrypt.ComputeManifestHMAC(symKey, 8, fileID)
	require.False(t, hmac.Equal(mac1, macDiff), "different count must produce different HMAC")
}

// tamperManifestCount finds the manifest attachment and replaces its first 8 bytes
// (the chunk count uint64) with a new value. The HMAC is left unchanged, so
// the decoder will detect the mismatch.
func tamperManifestCount(t *testing.T, data []byte, newCount uint64) []byte {
	t.Helper()
	tampered := make([]byte, len(data))
	copy(tampered, data)

	const manifestName = "mcap_encryption_manifest"
	pos := 8
	for pos+9 <= len(data) {
		opcode := data[pos]
		n := int(binary.LittleEndian.Uint64(data[pos+1:]))
		if opcode == 0x09 && pos+9+n <= len(data) {
			payload := data[pos+9 : pos+9+n]
			// Extract name from attachment payload: skip logTime(8)+createTime(8), then read len-prefixed string.
			if len(payload) > 20 {
				nameLen := int(binary.LittleEndian.Uint32(payload[16:]))
				if len(payload) >= 20+nameLen && string(payload[20:20+nameLen]) == manifestName {
					// Data field offset: 8+8+4+nameLen+4+mediaTypeLen+8
					o := 20 + nameLen
					if len(payload) > o+4 {
						mediaTypeLen := int(binary.LittleEndian.Uint32(payload[o:]))
						o += 4 + mediaTypeLen + 8
						if len(payload) >= o+8 {
							binary.LittleEndian.PutUint64(tampered[pos+9+o:], newCount)
							return tampered
						}
					}
				}
			}
		}
		pos += 9 + n
	}
	t.Fatal("manifest attachment not found in encrypted file")
	return nil
}
