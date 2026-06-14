package mcapencrypt

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rsa"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/remete618/mcap-encrypt/pkg/mcapencrypt/kms"
)

// RotateKeysWithKMS reads an encrypted MCAP from r, unwraps the symmetric
// key via the supplied KMS Decrypter, re-wraps it for each key in
// newPublicKeyPems, and writes the result to w. The old private key never
// leaves the KMS boundary.
//
// This is the KMS-backed analogue of RotateKeys. It is identical in
// behaviour: encrypted chunk data is copied verbatim and no message
// decryption occurs.
func RotateKeysWithKMS(ctx context.Context, r io.Reader, w io.Writer, kmsDec kms.Decrypter, newPublicKeyPems []string) error {
	if kmsDec == nil {
		return fmt.Errorf("nil KMS decrypter")
	}
	if len(newPublicKeyPems) == 0 {
		return fmt.Errorf("at least one new public key is required")
	}

	unwrap := func(kekAlg string, wrappedKey []byte) ([]byte, error) {
		return kmsDec.Decrypt(ctx, kekAlg, wrappedKey)
	}
	return rotateKeysCore(r, w, unwrap, newPublicKeyPems)
}

// rotateKeysCore extracts the rotate engine so both RotateKeys (local key)
// and RotateKeysWithKMS share the same scan / rewrite path. The only thing
// that varies between callers is the unwrap closure.
//
// This is a near-verbatim copy of the body of RotateKeys minus the
// PEM/private-key parsing prefix; future refactor could DRY out the
// local-key entry point by routing it through this function too.
func rotateKeysCore(r io.Reader, w io.Writer, unwrap func(kekAlg string, wrappedKey []byte) ([]byte, error), newPublicKeyPems []string) error {
	raw, err := io.ReadAll(r)
	if err != nil {
		return fmt.Errorf("read input: %w", err)
	}
	if len(raw) < 8 {
		return fmt.Errorf("input too short to be an MCAP file")
	}
	if string(raw[:8]) != mcapMagic {
		return fmt.Errorf("not an MCAP file (bad magic bytes)")
	}
	src := bytes.NewReader(raw[8:])

	type pendingRecord struct {
		opcode byte
		data   []byte
	}
	var schemaRecs []pendingRecord
	var channelRecs []pendingRecord

	type chunkMeta struct {
		dataBufOffset  int64
		recordLen      int64
		msgStart       uint64
		msgEnd         uint64
		compression    string
		compressedSize uint64
		uncompSize     uint64
	}
	var chunkMetas []chunkMeta

	var symKey []byte
	var fileID []byte
	var wkaCount int

	var headerBuf bytes.Buffer
	var dataBuf bytes.Buffer
	var seenFirstChunk bool

	for {
		opcode, data, readErr := ReadRecord(src)
		if readErr != nil {
			if readErr == io.EOF {
				break
			}
			return fmt.Errorf("read record: %w", readErr)
		}

		switch opcode {
		case opcodeHeader:
			if _, err := headerBuf.Write(makeRotateRecord(opcode, data)); err != nil {
				return err
			}
		case opcodeSchema:
			if _, err := headerBuf.Write(makeRotateRecord(opcode, data)); err != nil {
				return err
			}
			cp := make([]byte, len(data))
			copy(cp, data)
			schemaRecs = append(schemaRecs, pendingRecord{opcode, cp})
		case opcodeChannel:
			if _, err := headerBuf.Write(makeRotateRecord(opcode, data)); err != nil {
				return err
			}
			cp := make([]byte, len(data))
			copy(cp, data)
			channelRecs = append(channelRecs, pendingRecord{opcode, cp})
		case opcodeMetadata:
			if _, err := dataBuf.Write(makeRotateRecord(opcode, data)); err != nil {
				return err
			}
		case opcodeAttach:
			name, mediaType, attData, parseErr := parseAttachmentRecord(data)
			if parseErr != nil {
				return fmt.Errorf("parse attachment: %w", parseErr)
			}
			if name == AttachmentName && mediaType == AttachmentMediaType {
				wkaCount++
				if symKey == nil {
					wkd, decErr := DecodeWrappedKeyData(attData)
					if decErr == nil {
						candidate, unwrapErr := unwrap(wkd.KEKAlg, wkd.WrappedKey)
						if unwrapErr == nil && len(candidate) == 32 {
							symKey = candidate
							fileID = wkd.FileID
						}
					}
				}
				continue
			}
			if name == ManifestAttachmentName && mediaType == ManifestAttachmentMediaType {
				continue
			}
			if _, err := dataBuf.Write(makeRotateRecord(opcode, data)); err != nil {
				return err
			}
		case OpcodeEncryptedChunk:
			seenFirstChunk = true
			ec, decErr := DecodeEncryptedChunk(data)
			if decErr != nil {
				return fmt.Errorf("decode encrypted chunk header: %w", decErr)
			}
			chunkMetas = append(chunkMetas, chunkMeta{
				dataBufOffset:  int64(dataBuf.Len()),
				recordLen:      int64(9 + len(data)),
				msgStart:       ec.MessageStartTime,
				msgEnd:         ec.MessageEndTime,
				compression:    ec.Compression,
				compressedSize: uint64(len(ec.EncryptedData)),
				uncompSize:     ec.UncompressedSize,
			})
			if _, err := dataBuf.Write(makeRotateRecord(opcode, data)); err != nil {
				return err
			}
		case OpcodeEncryptedAttachment:
			seenFirstChunk = true
			if _, err := dataBuf.Write(makeRotateRecord(opcode, data)); err != nil {
				return err
			}
		case opcodeDataEnd:
			goto doneScanning
		case opcodeFooter:
			goto doneScanning
		default:
			if !seenFirstChunk {
				if _, err := headerBuf.Write(makeRotateRecord(opcode, data)); err != nil {
					return err
				}
			} else {
				if _, err := dataBuf.Write(makeRotateRecord(opcode, data)); err != nil {
					return err
				}
			}
		}
	}

doneScanning:

	if symKey == nil {
		if wkaCount == 0 {
			return fmt.Errorf("no wrapped key attachment found: is this an encrypted MCAP file?")
		}
		return fmt.Errorf("old private key does not match any of the %d recipient key(s) in this file", wkaCount)
	}
	defer clear(symKey)

	now := uint64(time.Now().UnixNano())
	var newKeyRecords [][]byte
	for i, pubPem := range newPublicKeyPems {
		pub, loadErr := parsePublicKeyFromPEM(pubPem)
		if loadErr != nil {
			return fmt.Errorf("load new public key %d: %w", i+1, loadErr)
		}
		fingerprint, fpErr := SPKIFingerprint(pub)
		if fpErr != nil {
			return fmt.Errorf("fingerprint new key %d: %w", i+1, fpErr)
		}
		var wrapped []byte
		var kekAlg string
		var wrapErr error
		switch k := pub.(type) {
		case *rsa.PublicKey:
			kekAlg = "rsa-oaep-sha256"
			wrapped, wrapErr = WrapSymmetricKey(symKey, k)
		case *ecdh.PublicKey:
			kekAlg = "x25519-hkdf-xchacha20poly1305"
			wrapped, wrapErr = WrapSymmetricKeyX25519(symKey, k)
		default:
			return fmt.Errorf("unsupported public key type %T for new recipient %d", pub, i+1)
		}
		if wrapErr != nil {
			return fmt.Errorf("wrap key for new recipient %d: %w", i+1, wrapErr)
		}
		wkd := &WrappedKeyData{
			FileID:     fileID,
			KeyID:      fingerprint,
			Algorithm:  "xchacha20poly1305",
			KEKAlg:     kekAlg,
			WrappedKey: wrapped,
		}
		attBytes := buildAttachmentBytes(now, 0, AttachmentName, AttachmentMediaType, wkd.Encode())
		newKeyRecords = append(newKeyRecords, makeRotateRecord(opcodeAttach, attBytes))
	}

	chunkCount := uint64(len(chunkMetas))
	mac := ComputeManifestHMAC(symKey, chunkCount, fileID)
	var manifestPayload [manifestPayloadSize]byte
	binary.LittleEndian.PutUint64(manifestPayload[:8], chunkCount)
	copy(manifestPayload[8:], mac)
	manifestAttBytes := buildAttachmentBytes(now, 0, ManifestAttachmentName, ManifestAttachmentMediaType, manifestPayload[:])
	manifestRecord := makeRotateRecord(opcodeAttach, manifestAttBytes)

	prefixSize := int64(8) + int64(headerBuf.Len())
	for _, b := range newKeyRecords {
		prefixSize += int64(len(b))
	}
	prefixSize += int64(len(manifestRecord))

	for i := range chunkMetas {
		chunkMetas[i].dataBufOffset += prefixSize
	}

	if err := WriteMagic(w); err != nil {
		return err
	}
	if _, err := w.Write(headerBuf.Bytes()); err != nil {
		return err
	}
	for _, b := range newKeyRecords {
		if _, err := w.Write(b); err != nil {
			return err
		}
	}
	if _, err := w.Write(manifestRecord); err != nil {
		return err
	}
	dataBytes := dataBuf.Bytes()
	if _, err := w.Write(dataBytes); err != nil {
		return err
	}

	if err := WriteRecord(w, opcodeDataEnd, []byte{0, 0, 0, 0}); err != nil {
		return err
	}

	summaryStart := prefixSize + int64(len(dataBytes)) + int64(9+4)

	put16 := func(b []byte, v uint16) { binary.LittleEndian.PutUint16(b, v) }
	put32 := func(b []byte, v uint32) { binary.LittleEndian.PutUint32(b, v) }
	put64 := func(b []byte, v uint64) { binary.LittleEndian.PutUint64(b, v) }
	putStr := func(s string) []byte {
		b := make([]byte, 4+len(s))
		binary.LittleEndian.PutUint32(b, uint32(len(s)))
		copy(b[4:], s)
		return b
	}

	type group struct {
		opcode    byte
		absStart  int64
		absLength int64
	}
	var groups []group
	var sumBuf []byte
	written := int64(0)
	emitSumRec := func(op byte, d []byte) {
		hdr := [9]byte{op}
		binary.LittleEndian.PutUint64(hdr[1:], uint64(len(d)))
		sumBuf = append(sumBuf, hdr[:]...)
		sumBuf = append(sumBuf, d...)
		written += int64(9 + len(d))
	}

	schemaGroupStart := summaryStart + written
	for _, r := range schemaRecs {
		emitSumRec(r.opcode, r.data)
	}
	if l := summaryStart + written - schemaGroupStart; l > 0 {
		groups = append(groups, group{opcodeSchema, schemaGroupStart, l})
	}

	channelGroupStart := summaryStart + written
	for _, r := range channelRecs {
		emitSumRec(r.opcode, r.data)
	}
	if l := summaryStart + written - channelGroupStart; l > 0 {
		groups = append(groups, group{opcodeChannel, channelGroupStart, l})
	}

	statsGroupStart := summaryStart + written
	var globalMsgStart, globalMsgEnd uint64
	if len(chunkMetas) > 0 {
		globalMsgStart = chunkMetas[0].msgStart
		globalMsgEnd = chunkMetas[0].msgEnd
		for _, m := range chunkMetas[1:] {
			if m.msgStart < globalMsgStart {
				globalMsgStart = m.msgStart
			}
			if m.msgEnd > globalMsgEnd {
				globalMsgEnd = m.msgEnd
			}
		}
	}
	statsBuf := make([]byte, 8+2+4+4+4+4+8+8+4)
	o := 0
	put64(statsBuf[o:], 0)
	o += 8
	put16(statsBuf[o:], uint16(len(schemaRecs)))
	o += 2
	put32(statsBuf[o:], uint32(len(channelRecs)))
	o += 4
	put32(statsBuf[o:], 0)
	o += 4
	put32(statsBuf[o:], 0)
	o += 4
	put32(statsBuf[o:], uint32(len(chunkMetas)))
	o += 4
	put64(statsBuf[o:], globalMsgStart)
	o += 8
	put64(statsBuf[o:], globalMsgEnd)
	o += 8
	put32(statsBuf[o:], 0)
	o += 4
	emitSumRec(opcodeStatistics, statsBuf[:o])
	groups = append(groups, group{opcodeStatistics, statsGroupStart, summaryStart + written - statsGroupStart})

	chunkIdxGroupStart := summaryStart + written
	for _, m := range chunkMetas {
		comp := m.compression
		ci := make([]byte, 8+8+8+8+4+8+4+len(comp)+8+8)
		oi := 0
		put64(ci[oi:], m.msgStart)
		oi += 8
		put64(ci[oi:], m.msgEnd)
		oi += 8
		put64(ci[oi:], uint64(m.dataBufOffset))
		oi += 8
		put64(ci[oi:], uint64(m.recordLen))
		oi += 8
		put32(ci[oi:], 0)
		oi += 4
		put64(ci[oi:], 0)
		oi += 8
		copy(ci[oi:], putStr(comp))
		oi += 4 + len(comp)
		put64(ci[oi:], m.compressedSize)
		oi += 8
		put64(ci[oi:], m.uncompSize)
		oi += 8
		emitSumRec(opcodeChunkIndex, ci[:oi])
	}
	if l := summaryStart + written - chunkIdxGroupStart; l > 0 {
		groups = append(groups, group{opcodeChunkIndex, chunkIdxGroupStart, l})
	}

	summaryOffsetStart := summaryStart + written
	for _, g := range groups {
		so := make([]byte, 1+8+8)
		so[0] = g.opcode
		put64(so[1:], uint64(g.absStart))
		put64(so[9:], uint64(g.absLength))
		emitSumRec(opcodeSummaryOffset, so)
	}

	if _, err := w.Write(sumBuf); err != nil {
		return fmt.Errorf("write summary: %w", err)
	}

	footerBuf := make([]byte, 20)
	put64(footerBuf[0:], uint64(summaryStart))
	put64(footerBuf[8:], uint64(summaryOffsetStart))
	if err := WriteRecord(w, opcodeFooter, footerBuf); err != nil {
		return err
	}
	return WriteMagic(w)
}

// RotateKeyFileWithKMS is the file-path analogue of RotateKeysWithKMS. It
// writes atomically via a temp file in the output directory.
func RotateKeyFileWithKMS(ctx context.Context, inputPath, outputPath string, kmsDec kms.Decrypter, newPublicKeyPems []string) (retErr error) {
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

	inFile, err := os.Open(inputPath)
	if err != nil {
		return fmt.Errorf("open input: %w", err)
	}
	defer inFile.Close()

	tmpFile, err := os.CreateTemp(filepath.Dir(outputPath), ".mcap-rotate-tmp-*")
	if err != nil {
		return fmt.Errorf("create temp output: %w", err)
	}
	tmpPath := tmpFile.Name()
	var tmpClosed bool
	defer func() {
		if !tmpClosed {
			if closeErr := tmpFile.Close(); closeErr != nil && retErr == nil {
				retErr = fmt.Errorf("close temp output: %w", closeErr)
			}
		}
		if retErr != nil {
			os.Remove(tmpPath)
		}
	}()

	if err := RotateKeysWithKMS(ctx, inFile, tmpFile, kmsDec, newPublicKeyPems); err != nil {
		return err
	}
	if err := tmpFile.Close(); err != nil {
		return fmt.Errorf("flush temp output: %w", err)
	}
	tmpClosed = true
	return os.Rename(tmpPath, outputPath)
}
