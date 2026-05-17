package mcapencrypt_test

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/remete618/mcap-encrypt/pkg/mcapencrypt"
)

// corruptWrappedKeyAttachmentData finds the first wrapped-key attachment record
// in data and overwrites the data field bytes with zeros, breaking the
// WrappedKeyData binary encoding while leaving the outer MCAP record framing
// (opcode, length, name, mediaType, dataSize) intact.
func corruptWrappedKeyAttachmentData(t *testing.T, data []byte) []byte {
	t.Helper()
	pos := 8
	for pos+9 <= len(data) {
		opcode := data[pos]
		recLen := int(binary.LittleEndian.Uint64(data[pos+1:]))
		if opcode == 0x09 {
			payload := data[pos+9 : pos+9+recLen]
			// Parse name to find the right record.
			if len(payload) >= 20 {
				o := 16 // skip log_time + create_time
				nameLen := int(binary.LittleEndian.Uint32(payload[o:]))
				o += 4
				if o+nameLen <= len(payload) {
					name := string(payload[o : o+nameLen])
					o += nameLen
					if name == mcapencrypt.AttachmentName {
						// Skip mediaType.
						if o+4 <= len(payload) {
							mediaTypeLen := int(binary.LittleEndian.Uint32(payload[o:]))
							o += 4 + mediaTypeLen
						}
						// Skip dataSize (8 bytes); data bytes start at o+8.
						dataStart := o + 8
						if dataStart < len(payload) {
							out := make([]byte, len(data))
							copy(out, data)
							// Zero out the inner data field to break WrappedKeyData parsing.
							for i := pos + 9 + dataStart; i < pos+9+recLen; i++ {
								out[i] = 0x00
							}
							return out
						}
					}
				}
			}
		}
		pos += 9 + recLen
	}
	t.Fatal("no wrapped-key attachment (0x09) found to corrupt")
	return nil
}

// TestWarnFuncCalledOnMalformedKeyAttachment encrypts a file for two
// recipients, corrupts the first wrapped-key attachment data field so that
// DecodeWrappedKeyData fails, then decrypts with the second (uncorrupted)
// recipient key. WarnFunc must be called for the malformed slot, and decryption
// must still succeed.
func TestWarnFuncCalledOnMalformedKeyAttachment(t *testing.T) {
	dir := t.TempDir()
	plainPath := filepath.Join(dir, "plain.mcap")
	encPath := filepath.Join(dir, "enc.mcap")
	keyA := filepath.Join(dir, "keyA")
	keyB := filepath.Join(dir, "keyB")

	buildTestMCAP(t, plainPath)
	require.NoError(t, mcapencrypt.GenerateKeyPair(keyA))
	require.NoError(t, mcapencrypt.GenerateKeyPair(keyB))

	// Encrypt for two recipients so keyB can still decrypt after keyA slot is corrupted.
	require.NoError(t, mcapencrypt.EncryptMulti(
		plainPath, encPath,
		[]string{keyA + ".pub.pem", keyB + ".pub.pem"},
	))

	data, err := os.ReadFile(encPath)
	require.NoError(t, err)

	tampered := corruptWrappedKeyAttachmentData(t, data)

	privPEM, err := os.ReadFile(keyB + ".priv.pem")
	require.NoError(t, err)

	var warnings []string
	out := &bytes.Buffer{}
	decErr := mcapencrypt.DecryptWithOptions(
		bytes.NewReader(tampered),
		out,
		string(privPEM),
		mcapencrypt.DecryptOptions{
			WarnFunc: func(msg string) {
				warnings = append(warnings, msg)
			},
		},
	)
	require.NoError(t, decErr, "decryption must succeed using the uncorrupted keyB slot")
	require.NotEmpty(t, warnings, "WarnFunc must be called at least once for the malformed slot")
}

// TestWarnFuncNotCalledOnCleanDecrypt verifies that a normal round-trip with
// WarnFunc set does not trigger any warnings.
func TestWarnFuncNotCalledOnCleanDecrypt(t *testing.T) {
	dir := t.TempDir()
	plainPath := filepath.Join(dir, "plain.mcap")
	encPath := filepath.Join(dir, "enc.mcap")
	keyBase := filepath.Join(dir, "key")

	buildTestMCAP(t, plainPath)
	require.NoError(t, mcapencrypt.GenerateKeyPair(keyBase))
	require.NoError(t, mcapencrypt.Encrypt(plainPath, encPath, keyBase+".pub.pem"))

	encData, err := os.ReadFile(encPath)
	require.NoError(t, err)

	privPEM, err := os.ReadFile(keyBase + ".priv.pem")
	require.NoError(t, err)

	var warnings []string
	out := &bytes.Buffer{}
	decErr := mcapencrypt.DecryptWithOptions(
		bytes.NewReader(encData),
		out,
		string(privPEM),
		mcapencrypt.DecryptOptions{
			WarnFunc: func(msg string) {
				warnings = append(warnings, msg)
			},
		},
	)
	require.NoError(t, decErr)
	require.Empty(t, warnings, "WarnFunc must not be called on a clean, well-formed decrypt")
}
