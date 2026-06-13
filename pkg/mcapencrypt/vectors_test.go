package mcapencrypt

// Conformance test vectors live in ../../testdata/vectors/*.json. They are the
// canonical interop reference for non-Go implementations. This test reads each
// vector and re-verifies it against the live (in-package) crypto code. Any
// drift between the JSON outputs and the live code is a wire-format change
// and the test fails. Vectors must never be regenerated to silence a failure;
// instead, decide whether the change is intentional and, if so, bump the spec
// version and update the JSON files explicitly.

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/crypto/chacha20poly1305"

	"github.com/stretchr/testify/require"
)

const vectorsDir = "../../testdata/vectors"

type vectorEntry struct {
	Description string                 `json:"description"`
	Inputs      map[string]interface{} `json:"inputs"`
	Output      string                 `json:"output"`
	Notes       map[string]interface{} `json:"notes,omitempty"`
}

type vectorFile struct {
	Operation string        `json:"operation"`
	Spec      string        `json:"spec_section"`
	Algorithm string        `json:"algorithm,omitempty"`
	Encoding  string        `json:"encoding"`
	Vectors   []vectorEntry `json:"vectors"`
}

func loadVectorFile(t *testing.T, name string) vectorFile {
	t.Helper()
	path := filepath.Join(vectorsDir, name)
	data, err := os.ReadFile(path)
	require.NoError(t, err, "read %s", path)
	var vf vectorFile
	require.NoError(t, json.Unmarshal(data, &vf), "parse %s", path)
	require.NotEmpty(t, vf.Vectors, "no vectors in %s", path)
	return vf
}

func hexInput(t *testing.T, e vectorEntry, key string) []byte {
	t.Helper()
	v, ok := e.Inputs[key].(string)
	require.True(t, ok, "missing input %q", key)
	b, err := hex.DecodeString(v)
	require.NoError(t, err, "decode hex input %q", key)
	return b
}

func uint64Input(t *testing.T, e vectorEntry, key string) uint64 {
	t.Helper()
	v, ok := e.Inputs[key]
	require.True(t, ok, "missing input %q", key)
	switch n := v.(type) {
	case float64:
		// JSON numbers may exceed float64 safe-integer range; for our largest
		// values (uint64 max) JSON.Unmarshal still round-trips correctly because
		// 0xFFFFFFFFFFFFFFFF is representable as a float64 (with rounding to
		// the same bit pattern via uint64(float64(...))). We accept that.
		return uint64(n)
	case json.Number:
		u, err := n.Int64()
		require.NoError(t, err)
		return uint64(u)
	case string:
		var u uint64
		_, err := fmt.Sscanf(n, "%d", &u)
		require.NoError(t, err)
		return u
	default:
		t.Fatalf("uint64 input %q has unexpected type %T", key, v)
		return 0
	}
}

func uint32Input(t *testing.T, e vectorEntry, key string) uint32 {
	return uint32(uint64Input(t, e, key))
}

func stringInput(t *testing.T, e vectorEntry, key string) string {
	t.Helper()
	v, ok := e.Inputs[key].(string)
	require.True(t, ok, "missing string input %q", key)
	return v
}

// TestVectors is the umbrella test: one subtest per JSON file. Each subtest
// loads the file and verifies every entry against the live code path.
func TestVectors(t *testing.T) {
	t.Run("hkdf_x25519", testVectorsHKDFX25519)
	t.Run("chunk_aad", testVectorsChunkAAD)
	t.Run("attachment_aad", testVectorsAttachmentAAD)
	t.Run("metadata_aad", testVectorsMetadataAAD)
	t.Run("manifest_hmac", testVectorsManifestHMAC)
	t.Run("chunk_aead", testVectorsChunkAEAD)
	t.Run("attachment_aead", testVectorsAttachmentAEAD)
	t.Run("metadata_aead", testVectorsMetadataAEAD)
}

func testVectorsHKDFX25519(t *testing.T) {
	vf := loadVectorFile(t, "hkdf_x25519.json")
	for i, e := range vf.Vectors {
		t.Run(fmt.Sprintf("vec%d", i), func(t *testing.T) {
			shared := hexInput(t, e, "shared_secret")
			expected, err := hex.DecodeString(e.Output)
			require.NoError(t, err)
			got, err := deriveX25519KEK(shared)
			require.NoError(t, err)
			require.Equal(t, expected, got, e.Description)
		})
	}
}

func testVectorsChunkAAD(t *testing.T) {
	vf := loadVectorFile(t, "chunk_aad.json")
	for i, e := range vf.Vectors {
		t.Run(fmt.Sprintf("vec%d", i), func(t *testing.T) {
			fileID := hexInput(t, e, "file_id_hex")
			got := chunkAAD(
				fileID,
				uint64Input(t, e, "chunk_index"),
				stringInput(t, e, "slot_id"),
				stringInput(t, e, "compression"),
				uint64Input(t, e, "uncompressed_size"),
				uint32Input(t, e, "uncompressed_crc"),
				uint64Input(t, e, "message_start_ns"),
				uint64Input(t, e, "message_end_ns"),
			)
			expected, err := hex.DecodeString(e.Output)
			require.NoError(t, err)
			require.Equal(t, expected, got, e.Description)
		})
	}
}

func testVectorsAttachmentAAD(t *testing.T) {
	vf := loadVectorFile(t, "attachment_aad.json")
	for i, e := range vf.Vectors {
		t.Run(fmt.Sprintf("vec%d", i), func(t *testing.T) {
			fileID := hexInput(t, e, "file_id_hex")
			got := attachmentAAD(
				fileID,
				stringInput(t, e, "name"),
				stringInput(t, e, "media_type"),
				uint64Input(t, e, "log_time_ns"),
				uint64Input(t, e, "create_time_ns"),
			)
			expected, err := hex.DecodeString(e.Output)
			require.NoError(t, err)
			require.Equal(t, expected, got, e.Description)
		})
	}
}

func testVectorsMetadataAAD(t *testing.T) {
	vf := loadVectorFile(t, "metadata_aad.json")
	for i, e := range vf.Vectors {
		t.Run(fmt.Sprintf("vec%d", i), func(t *testing.T) {
			fileID := hexInput(t, e, "file_id_hex")
			flags := byte(uint32Input(t, e, "flags"))
			got := metadataAAD(fileID, flags, stringInput(t, e, "name"))
			expected, err := hex.DecodeString(e.Output)
			require.NoError(t, err)
			require.Equal(t, expected, got, e.Description)
		})
	}
}

func testVectorsManifestHMAC(t *testing.T) {
	vf := loadVectorFile(t, "manifest_hmac.json")
	for i, e := range vf.Vectors {
		t.Run(fmt.Sprintf("vec%d", i), func(t *testing.T) {
			symKey := hexInput(t, e, "sym_key_hex")
			fileID := hexInput(t, e, "file_id_hex")
			chunkCount := uint64Input(t, e, "chunk_count")
			got := ComputeManifestHMAC(symKey, chunkCount, fileID)
			expected, err := hex.DecodeString(e.Output)
			require.NoError(t, err)
			require.Equal(t, expected, got, e.Description)
		})
	}
}

func testVectorsChunkAEAD(t *testing.T) {
	vf := loadVectorFile(t, "chunk_aead.json")
	for i, e := range vf.Vectors {
		t.Run(fmt.Sprintf("vec%d", i), func(t *testing.T) {
			symKey := hexInput(t, e, "sym_key_hex")
			nonce := hexInput(t, e, "nonce_hex")
			aadFromFile := hexInput(t, e, "aad_hex")
			plaintext := hexInput(t, e, "plaintext_hex")
			expected, err := hex.DecodeString(e.Output)
			require.NoError(t, err)

			// Cross-check: the AAD recorded in the vector must equal the AAD
			// the live constructor produces from the same field-level inputs.
			fields, ok := e.Inputs["aad_fields"].(map[string]interface{})
			require.True(t, ok, "missing aad_fields")
			fileID, err := hex.DecodeString(fields["file_id_hex"].(string))
			require.NoError(t, err)
			liveAAD := chunkAAD(
				fileID,
				uint64(fields["chunk_index"].(float64)),
				fields["slot_id"].(string),
				fields["compression"].(string),
				uint64(fields["uncompressed_size"].(float64)),
				uint32(fields["uncompressed_crc"].(float64)),
				uint64(fields["message_start_ns"].(float64)),
				uint64(fields["message_end_ns"].(float64)),
			)
			require.Equal(t, aadFromFile, liveAAD, "live chunkAAD must match aad_hex in vector")

			aead, err := chacha20poly1305.NewX(symKey)
			require.NoError(t, err)
			got := aead.Seal(nil, nonce, plaintext, liveAAD)
			require.Equal(t, expected, got, e.Description)

			// Roundtrip: Open recovers the plaintext.
			rt, err := aead.Open(nil, nonce, got, liveAAD)
			require.NoError(t, err)
			require.Equal(t, plaintext, rt)
		})
	}
}

func testVectorsAttachmentAEAD(t *testing.T) {
	vf := loadVectorFile(t, "attachment_aead.json")
	for i, e := range vf.Vectors {
		t.Run(fmt.Sprintf("vec%d", i), func(t *testing.T) {
			symKey := hexInput(t, e, "sym_key_hex")
			nonce := hexInput(t, e, "nonce_hex")
			aadFromFile := hexInput(t, e, "aad_hex")
			plaintext := hexInput(t, e, "plaintext_hex")
			expected, err := hex.DecodeString(e.Output)
			require.NoError(t, err)

			fields, ok := e.Inputs["aad_fields"].(map[string]interface{})
			require.True(t, ok, "missing aad_fields")
			fileID, err := hex.DecodeString(fields["file_id_hex"].(string))
			require.NoError(t, err)
			liveAAD := attachmentAAD(
				fileID,
				fields["name"].(string),
				fields["media_type"].(string),
				uint64(fields["log_time_ns"].(float64)),
				uint64(fields["create_time_ns"].(float64)),
			)
			require.Equal(t, aadFromFile, liveAAD, "live attachmentAAD must match aad_hex in vector")

			aead, err := chacha20poly1305.NewX(symKey)
			require.NoError(t, err)
			got := aead.Seal(nil, nonce, plaintext, liveAAD)
			require.Equal(t, expected, got, e.Description)

			rt, err := aead.Open(nil, nonce, got, liveAAD)
			require.NoError(t, err)
			require.Equal(t, plaintext, rt)
		})
	}
}

func testVectorsMetadataAEAD(t *testing.T) {
	vf := loadVectorFile(t, "metadata_aead.json")
	for i, e := range vf.Vectors {
		t.Run(fmt.Sprintf("vec%d", i), func(t *testing.T) {
			symKey := hexInput(t, e, "sym_key_hex")
			nonce := hexInput(t, e, "nonce_hex")
			aadFromFile := hexInput(t, e, "aad_hex")
			plaintext := hexInput(t, e, "plaintext_hex")
			flags := byte(uint32Input(t, e, "flags"))
			name := stringInput(t, e, "name")
			expected, err := hex.DecodeString(e.Output)
			require.NoError(t, err)

			// Cross-check AAD against live constructor.
			// file_id is taken from the recorded AAD (first 16 bytes).
			require.GreaterOrEqual(t, len(aadFromFile), 16)
			fileID := aadFromFile[:16]
			liveAAD := metadataAAD(fileID, flags, name)
			require.Equal(t, aadFromFile, liveAAD, "live metadataAAD must match aad_hex in vector")

			aead, err := chacha20poly1305.NewX(symKey)
			require.NoError(t, err)
			got := aead.Seal(nil, nonce, plaintext, liveAAD)
			require.Equal(t, expected, got, e.Description)

			rt, err := aead.Open(nil, nonce, got, liveAAD)
			require.NoError(t, err)
			require.Equal(t, plaintext, rt)
		})
	}
}

// Compile-time use of binary to keep imports stable if future vectors add
// additional helpers; remove if the linter complains.
var _ = binary.LittleEndian
