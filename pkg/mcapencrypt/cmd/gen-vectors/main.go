// Command gen-vectors generates the JSON conformance test vectors in
// testdata/vectors/. The generated files are committed and are the canonical
// interop reference for non-Go implementations. Re-run only when adding new
// operations or intentionally changing wire-format-affecting algorithm
// parameters; both events are breaking changes that require a version bump.
//
//	go run ./pkg/mcapencrypt/cmd/gen-vectors -out testdata/vectors
package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

type entry struct {
	Description string         `json:"description"`
	Inputs      map[string]any `json:"inputs"`
	Output      string         `json:"output"`
	Notes       map[string]any `json:"notes,omitempty"`
}

type vectorFile struct {
	Operation string  `json:"operation"`
	Spec      string  `json:"spec_section"`
	Algorithm string  `json:"algorithm,omitempty"`
	Encoding  string  `json:"encoding"`
	Vectors   []entry `json:"vectors"`
}

func main() {
	outDir := flag.String("out", "testdata/vectors", "directory to write JSON vector files into")
	flag.Parse()

	if err := os.MkdirAll(*outDir, 0o755); err != nil {
		log.Fatalf("mkdir: %v", err)
	}

	writers := []func(string) error{
		writeHKDFX25519,
		writeChunkAAD,
		writeAttachmentAAD,
		writeMetadataAAD,
		writeManifestHMAC,
		writeChunkAEAD,
		writeAttachmentAEAD,
		writeMetadataAEAD,
	}
	for _, w := range writers {
		if err := w(*outDir); err != nil {
			log.Fatalf("write vector: %v", err)
		}
	}
	fmt.Println("wrote", len(writers), "vector files to", *outDir)
}

func writeJSON(outDir, name string, vf vectorFile) error {
	path := filepath.Join(outDir, name)
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	if err := enc.Encode(vf); err != nil {
		return err
	}
	return nil
}

// repeatByte returns n bytes filled with b. Used for fixed, deterministic input
// material so vectors are byte-for-byte reproducible without secrets.
func repeatByte(b byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}

// seq returns n bytes whose i-th byte is start+i (mod 256). Same intent as
// repeatByte: a known, easy-to-eyeball input pattern.
func seq(start, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = byte(start + i)
	}
	return out
}

// ---- HKDF-X25519 ----

func writeHKDFX25519(outDir string) error {
	// Vector 1: the existing TestX25519KDFTestVector input.
	shared1 := seq(1, 32)
	kek1, err := hkdfX25519(shared1)
	if err != nil {
		return err
	}

	// Vector 2: an all-0xAA shared secret for a second independent point.
	shared2 := repeatByte(0xAA, 32)
	kek2, err := hkdfX25519(shared2)
	if err != nil {
		return err
	}

	vf := vectorFile{
		Operation: "hkdf-x25519-kek",
		Spec:      "FORMAT.md / Key derivation / kek_algorithm: x25519-hkdf-xchacha20poly1305",
		Algorithm: "HKDF-SHA256",
		Encoding:  "hex",
		Vectors: []entry{
			{
				Description: "Derive 32-byte KEK from a known X25519 shared secret using HKDF-SHA256.",
				Inputs: map[string]any{
					"shared_secret": hex.EncodeToString(shared1),
				},
				Output: hex.EncodeToString(kek1),
				Notes: map[string]any{
					"hash":         "SHA-256",
					"salt":         "empty (nil)",
					"info_ascii":   "mcap-encrypt x25519 v1",
					"info_hex":     hex.EncodeToString([]byte("mcap-encrypt x25519 v1")),
					"output_len":   32,
					"go_reference": "deriveX25519KEK in pkg/mcapencrypt/key.go",
				},
			},
			{
				Description: "Second known-answer test with an all-0xAA shared secret.",
				Inputs: map[string]any{
					"shared_secret": hex.EncodeToString(shared2),
				},
				Output: hex.EncodeToString(kek2),
				Notes: map[string]any{
					"hash":       "SHA-256",
					"salt":       "empty (nil)",
					"info_ascii": "mcap-encrypt x25519 v1",
					"output_len": 32,
				},
			},
		},
	}
	return writeJSON(outDir, "hkdf_x25519.json", vf)
}

func hkdfX25519(shared []byte) ([]byte, error) {
	kdf := hkdf.New(sha256.New, shared, nil, []byte("mcap-encrypt x25519 v1"))
	out := make([]byte, 32)
	if _, err := io.ReadFull(kdf, out); err != nil {
		return nil, err
	}
	return out, nil
}

// ---- Chunk AAD ----
//
// We can't call the unexported chunkAAD from this main package, so we
// inline the spec serialization here. The vectors_test.go consumer reads
// these JSONs and re-runs the live (unexported) constructor — drift between
// the two definitions causes that test to fail, which is the whole point.

func chunkAADBytes(fileID []byte, chunkIdx uint64, slotID, compression string, uncompressedSize uint64, uncompressedCRC uint32, startTime, endTime uint64) []byte {
	buf := make([]byte, 0, 16+8+4+len(slotID)+4+len(compression)+8+4+8+8)
	buf = append(buf, fileID...)
	buf = binary.LittleEndian.AppendUint64(buf, chunkIdx)
	buf = appendLPString(buf, slotID)
	buf = appendLPString(buf, compression)
	buf = binary.LittleEndian.AppendUint64(buf, uncompressedSize)
	buf = binary.LittleEndian.AppendUint32(buf, uncompressedCRC)
	buf = binary.LittleEndian.AppendUint64(buf, startTime)
	buf = binary.LittleEndian.AppendUint64(buf, endTime)
	return buf
}

func appendLPString(buf []byte, s string) []byte {
	var n [4]byte
	binary.LittleEndian.PutUint32(n[:], uint32(len(s)))
	buf = append(buf, n[:]...)
	return append(buf, s...)
}

func writeChunkAAD(outDir string) error {
	fileID := seq(0xA0, 16)

	type chunkAADInputs struct {
		fileID           []byte
		chunkIdx         uint64
		slotID           string
		compression      string
		uncompressedSize uint64
		uncompressedCRC  uint32
		startTime        uint64
		endTime          uint64
	}

	cases := []struct {
		desc string
		in   chunkAADInputs
	}{
		{
			desc: "First chunk: zstd compression, non-empty plaintext, sample CRC and times.",
			in: chunkAADInputs{
				fileID: fileID, chunkIdx: 0, slotID: "key-1",
				compression: "zstd", uncompressedSize: 12345, uncompressedCRC: 0xDEADBEEF,
				startTime: 1_000_000_000, endTime: 2_000_000_000,
			},
		},
		{
			desc: "Second chunk: empty compression string, larger index and times.",
			in: chunkAADInputs{
				fileID: fileID, chunkIdx: 1, slotID: "key-1",
				compression: "", uncompressedSize: 0, uncompressedCRC: 0,
				startTime: 0, endTime: 0,
			},
		},
		{
			desc: "Chunk with max uint values to test field widths.",
			in: chunkAADInputs{
				fileID: fileID, chunkIdx: 0xFFFFFFFFFFFFFFFF, slotID: "key-1",
				compression: "zstd", uncompressedSize: 0xFFFFFFFFFFFFFFFF, uncompressedCRC: 0xFFFFFFFF,
				startTime: 0xFFFFFFFFFFFFFFFF, endTime: 0xFFFFFFFFFFFFFFFF,
			},
		},
	}

	var vectors []entry
	for _, c := range cases {
		out := chunkAADBytes(c.in.fileID, c.in.chunkIdx, c.in.slotID, c.in.compression,
			c.in.uncompressedSize, c.in.uncompressedCRC, c.in.startTime, c.in.endTime)
		vectors = append(vectors, entry{
			Description: c.desc,
			Inputs: map[string]any{
				"file_id_hex":       hex.EncodeToString(c.in.fileID),
				"chunk_index":       c.in.chunkIdx,
				"slot_id":           c.in.slotID,
				"compression":       c.in.compression,
				"uncompressed_size": c.in.uncompressedSize,
				"uncompressed_crc":  c.in.uncompressedCRC,
				"message_start_ns":  c.in.startTime,
				"message_end_ns":    c.in.endTime,
			},
			Output: hex.EncodeToString(out),
		})
	}

	vf := vectorFile{
		Operation: "chunk-aad",
		Spec:      "FORMAT.md / Authenticated Encryption / chunk AAD",
		Encoding:  "hex",
		Vectors:   vectors,
	}
	// One global notes block carrying the spec serialization rule, so
	// non-Go implementors don't have to read encrypt.go.
	for i := range vf.Vectors {
		if vf.Vectors[i].Notes == nil {
			vf.Vectors[i].Notes = map[string]any{}
		}
		vf.Vectors[i].Notes["serialization"] = "file_id(16) || chunk_index u64 LE || u32 LE len + slot_id utf8 || u32 LE len + compression utf8 || uncompressed_size u64 LE || uncompressed_crc u32 LE || message_start u64 LE || message_end u64 LE"
	}
	return writeJSON(outDir, "chunk_aad.json", vf)
}

// ---- Attachment AAD ----

func attachmentAADBytes(fileID []byte, name, mediaType string, logTime, createTime uint64) []byte {
	buf := make([]byte, 0, 16+4+len(name)+4+len(mediaType)+8+8)
	buf = append(buf, fileID...)
	buf = appendLPString(buf, name)
	buf = appendLPString(buf, mediaType)
	buf = binary.LittleEndian.AppendUint64(buf, logTime)
	buf = binary.LittleEndian.AppendUint64(buf, createTime)
	return buf
}

func writeAttachmentAAD(outDir string) error {
	fileID := seq(0xA0, 16)

	type attInputs struct {
		name, mediaType     string
		logTime, createTime uint64
	}
	cases := []struct {
		desc string
		in   attInputs
	}{
		{
			desc: "Typical attachment: ASCII name, image media type, two distinct timestamps.",
			in: attInputs{
				name: "image.png", mediaType: "image/png",
				logTime: 1_700_000_000_000_000_000, createTime: 1_699_999_999_000_000_000,
			},
		},
		{
			desc: "Attachment with empty name and empty media type (both length-zero strings).",
			in:   attInputs{name: "", mediaType: "", logTime: 0, createTime: 0},
		},
		{
			desc: "Attachment with multibyte UTF-8 name to confirm length prefix is byte count, not codepoint count.",
			in: attInputs{
				name: "résumé.pdf", mediaType: "application/pdf",
				logTime: 1_700_000_000_000_000_000, createTime: 1_700_000_000_000_000_000,
			},
		},
	}

	var vectors []entry
	for _, c := range cases {
		out := attachmentAADBytes(fileID, c.in.name, c.in.mediaType, c.in.logTime, c.in.createTime)
		vectors = append(vectors, entry{
			Description: c.desc,
			Inputs: map[string]any{
				"file_id_hex":    hex.EncodeToString(fileID),
				"name":           c.in.name,
				"media_type":     c.in.mediaType,
				"log_time_ns":    c.in.logTime,
				"create_time_ns": c.in.createTime,
			},
			Output: hex.EncodeToString(out),
			Notes: map[string]any{
				"serialization": "file_id(16) || u32 LE len + name utf8 || u32 LE len + media_type utf8 || log_time u64 LE || create_time u64 LE",
			},
		})
	}

	vf := vectorFile{
		Operation: "attachment-aad",
		Spec:      "FORMAT.md / EncryptedAttachment record / Attachment AAD",
		Encoding:  "hex",
		Vectors:   vectors,
	}
	return writeJSON(outDir, "attachment_aad.json", vf)
}

// ---- Metadata AAD ----

func metadataAADBytes(fileID []byte, flags byte, name string) []byte {
	if flags == 0x01 {
		out := make([]byte, 16)
		copy(out, fileID)
		return out
	}
	buf := make([]byte, 0, 16+4+len(name))
	buf = append(buf, fileID...)
	var n [4]byte
	binary.LittleEndian.PutUint32(n[:], uint32(len(name)))
	buf = append(buf, n[:]...)
	buf = append(buf, name...)
	return buf
}

func writeMetadataAAD(outDir string) error {
	fileID := seq(0xA0, 16)

	cases := []struct {
		desc  string
		flags byte
		name  string
	}{
		{
			desc:  "encrypt mode (flags=0x00): name is bound into AAD.",
			flags: 0x00,
			name:  "build-info",
		},
		{
			desc:  "encrypt-all mode (flags=0x01): AAD is file_id only, name is inside the ciphertext.",
			flags: 0x01,
			name:  "",
		},
		{
			desc:  "encrypt mode with empty name: still emits a length-prefixed empty string.",
			flags: 0x00,
			name:  "",
		},
	}

	var vectors []entry
	for _, c := range cases {
		out := metadataAADBytes(fileID, c.flags, c.name)
		vectors = append(vectors, entry{
			Description: c.desc,
			Inputs: map[string]any{
				"file_id_hex": hex.EncodeToString(fileID),
				"flags":       c.flags,
				"name":        c.name,
			},
			Output: hex.EncodeToString(out),
			Notes: map[string]any{
				"serialization_encrypt":     "flags=0x00: file_id(16) || u32 LE len + name utf8",
				"serialization_encrypt_all": "flags=0x01: file_id(16)  -- name is in ciphertext, not AAD",
			},
		})
	}

	vf := vectorFile{
		Operation: "metadata-aad",
		Spec:      "FORMAT.md / EncryptedMetadata record / Metadata AAD",
		Encoding:  "hex",
		Vectors:   vectors,
	}
	return writeJSON(outDir, "metadata_aad.json", vf)
}

// ---- Manifest HMAC ----

func writeManifestHMAC(outDir string) error {
	symKey := seq(0x10, 32)
	fileID := seq(0xA0, 16)

	cases := []struct {
		desc       string
		chunkCount uint64
	}{
		{"Single-chunk file.", 1},
		{"Zero chunks (schema/channel-only file).", 0},
		{"Many chunks (1024).", 1024},
		{"Maximum uint64 chunk count.", 0xFFFFFFFFFFFFFFFF},
	}

	var vectors []entry
	for _, c := range cases {
		h := hmac.New(sha256.New, symKey)
		var cnt [8]byte
		binary.LittleEndian.PutUint64(cnt[:], c.chunkCount)
		h.Write(cnt[:])
		h.Write(fileID)
		mac := h.Sum(nil)
		vectors = append(vectors, entry{
			Description: c.desc,
			Inputs: map[string]any{
				"sym_key_hex": hex.EncodeToString(symKey),
				"chunk_count": c.chunkCount,
				"file_id_hex": hex.EncodeToString(fileID),
			},
			Output: hex.EncodeToString(mac),
			Notes: map[string]any{
				"algorithm":      "HMAC-SHA-256",
				"message_layout": "u64 LE chunk_count || file_id(16)",
				"key":            "32-byte file symmetric key",
			},
		})
	}

	vf := vectorFile{
		Operation: "manifest-hmac",
		Spec:      "FORMAT.md / Manifest Attachment",
		Algorithm: "HMAC-SHA-256",
		Encoding:  "hex",
		Vectors:   vectors,
	}
	return writeJSON(outDir, "manifest_hmac.json", vf)
}

// ---- Full chunk AEAD (encrypt+decrypt roundtrip with fixed inputs) ----
//
// Real encryption draws a fresh nonce per chunk. To pin the AEAD primitive
// in a way an external implementation can verify byte-for-byte, we expose
// (sym_key, nonce, AAD fields, plaintext) -> (ciphertext+tag). Implementations
// run XChaCha20-Poly1305 Seal with those exact inputs and must produce the
// same ciphertext, then verify Open recovers the plaintext.

func writeChunkAEAD(outDir string) error {
	symKey := seq(0x10, 32)
	fileID := seq(0xA0, 16)
	nonce := seq(0xC0, 24) // XChaCha20 nonce is 24 bytes

	plaintext := []byte("hello mcap-encrypt chunk plaintext")
	aad := chunkAADBytes(fileID, 0, "key-1", "zstd", uint64(len(plaintext)), 0xCAFEBABE,
		1_000_000_000, 2_000_000_000)

	aead, err := chacha20poly1305.NewX(symKey)
	if err != nil {
		return err
	}
	ct := aead.Seal(nil, nonce, plaintext, aad)

	vf := vectorFile{
		Operation: "chunk-aead",
		Spec:      "FORMAT.md / EncryptedChunk record / Authenticated Encryption",
		Algorithm: "XChaCha20-Poly1305",
		Encoding:  "hex",
		Vectors: []entry{
			{
				Description: "Encrypt a known plaintext as if it were a single zstd-compressed chunk. Implementations: run XChaCha20-Poly1305 Seal with the given key, nonce, plaintext, and aad; the output (ciphertext || 16-byte tag) must equal `ciphertext_hex`.",
				Inputs: map[string]any{
					"sym_key_hex":    hex.EncodeToString(symKey),
					"nonce_hex":      hex.EncodeToString(nonce),
					"aad_hex":        hex.EncodeToString(aad),
					"plaintext_hex":  hex.EncodeToString(plaintext),
					"plaintext_utf8": string(plaintext),
					"aad_fields": map[string]any{
						"file_id_hex":       hex.EncodeToString(fileID),
						"chunk_index":       0,
						"slot_id":           "key-1",
						"compression":       "zstd",
						"uncompressed_size": len(plaintext),
						"uncompressed_crc":  uint32(0xCAFEBABE),
						"message_start_ns":  1_000_000_000,
						"message_end_ns":    2_000_000_000,
					},
				},
				Output: hex.EncodeToString(ct),
				Notes: map[string]any{
					"algorithm":       "XChaCha20-Poly1305",
					"nonce_size":      24,
					"tag_size":        16,
					"ciphertext_form": "ciphertext || poly1305_tag (last 16 bytes are the tag)",
				},
			},
		},
	}
	return writeJSON(outDir, "chunk_aead.json", vf)
}

func writeAttachmentAEAD(outDir string) error {
	symKey := seq(0x10, 32)
	fileID := seq(0xA0, 16)
	nonce := seq(0xC0, 24)
	plaintext := []byte("attachment payload bytes")

	aad := attachmentAADBytes(fileID, "image.png", "image/png",
		1_700_000_000_000_000_000, 1_699_999_999_000_000_000)

	aead, err := chacha20poly1305.NewX(symKey)
	if err != nil {
		return err
	}
	ct := aead.Seal(nil, nonce, plaintext, aad)

	vf := vectorFile{
		Operation: "attachment-aead",
		Spec:      "FORMAT.md / EncryptedAttachment record",
		Algorithm: "XChaCha20-Poly1305",
		Encoding:  "hex",
		Vectors: []entry{
			{
				Description: "Encrypt an attachment payload with the AAD bound to its plaintext metadata.",
				Inputs: map[string]any{
					"sym_key_hex":   hex.EncodeToString(symKey),
					"nonce_hex":     hex.EncodeToString(nonce),
					"aad_hex":       hex.EncodeToString(aad),
					"plaintext_hex": hex.EncodeToString(plaintext),
					"aad_fields": map[string]any{
						"file_id_hex":    hex.EncodeToString(fileID),
						"name":           "image.png",
						"media_type":     "image/png",
						"log_time_ns":    1_700_000_000_000_000_000,
						"create_time_ns": 1_699_999_999_000_000_000,
					},
				},
				Output: hex.EncodeToString(ct),
				Notes: map[string]any{
					"algorithm":  "XChaCha20-Poly1305",
					"nonce_size": 24,
					"tag_size":   16,
				},
			},
		},
	}
	return writeJSON(outDir, "attachment_aead.json", vf)
}

func writeMetadataAEAD(outDir string) error {
	symKey := seq(0x10, 32)
	fileID := seq(0xA0, 16)

	// Two vectors: encrypt (flags=0x00) and encrypt-all (flags=0x01).
	nonce := seq(0xC0, 24)
	mapBytes := []byte("\x10\x00\x00\x00key=value;flag=on")
	aadEncrypt := metadataAADBytes(fileID, 0x00, "build-info")
	aead, err := chacha20poly1305.NewX(symKey)
	if err != nil {
		return err
	}
	ctEncrypt := aead.Seal(nil, nonce, mapBytes, aadEncrypt)

	// encrypt-all: plaintext is the full Metadata payload (u32 name len + name + map bytes).
	fullName := "build-info"
	fullPayload := make([]byte, 4+len(fullName)+len(mapBytes))
	binary.LittleEndian.PutUint32(fullPayload[:4], uint32(len(fullName)))
	copy(fullPayload[4:], fullName)
	copy(fullPayload[4+len(fullName):], mapBytes)

	aadEncryptAll := metadataAADBytes(fileID, 0x01, "")
	ctEncryptAll := aead.Seal(nil, nonce, fullPayload, aadEncryptAll)

	vf := vectorFile{
		Operation: "metadata-aead",
		Spec:      "FORMAT.md / EncryptedMetadata record",
		Algorithm: "XChaCha20-Poly1305",
		Encoding:  "hex",
		Vectors: []entry{
			{
				Description: "Encrypt mode (flags=0x00): plaintext is the map bytes only; AAD binds the plaintext name.",
				Inputs: map[string]any{
					"sym_key_hex":   hex.EncodeToString(symKey),
					"nonce_hex":     hex.EncodeToString(nonce),
					"flags":         0,
					"name":          "build-info",
					"aad_hex":       hex.EncodeToString(aadEncrypt),
					"plaintext_hex": hex.EncodeToString(mapBytes),
				},
				Output: hex.EncodeToString(ctEncrypt),
				Notes: map[string]any{
					"plaintext_meaning": "raw bytes of the MCAP Metadata key-value map (everything after the name field in the standard Metadata payload).",
				},
			},
			{
				Description: "Encrypt-all mode (flags=0x01): plaintext is the full Metadata payload (name length + name + map); AAD = file_id only.",
				Inputs: map[string]any{
					"sym_key_hex":   hex.EncodeToString(symKey),
					"nonce_hex":     hex.EncodeToString(nonce),
					"flags":         1,
					"name":          "",
					"aad_hex":       hex.EncodeToString(aadEncryptAll),
					"plaintext_hex": hex.EncodeToString(fullPayload),
				},
				Output: hex.EncodeToString(ctEncryptAll),
				Notes: map[string]any{
					"plaintext_meaning": "byte-for-byte identical to the standard MCAP Metadata payload (name length + name utf8 + map bytes).",
				},
			},
		},
	}
	return writeJSON(outDir, "metadata_aead.json", vf)
}
