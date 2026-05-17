package mcapencrypt

import (
	"encoding/binary"
	"fmt"
	"io"
)

const (
	mcapMagic = "\x89MCAP0\r\n"

	OpcodeEncryptedChunk = byte(0x81)

	opcodeHeader   = byte(0x01)
	opcodeFooter   = byte(0x02)
	opcodeSchema   = byte(0x03)
	opcodeChannel  = byte(0x04)
	opcodeAttach   = byte(0x09)
	opcodeDataEnd  = byte(0x0F)
	opcodeMetadata = byte(0x0C)
)

func ReadMagic(r io.Reader) error {
	buf := make([]byte, 8)
	if _, err := io.ReadFull(r, buf); err != nil {
		return fmt.Errorf("read magic: %w", err)
	}
	if string(buf) != mcapMagic {
		return fmt.Errorf("not an MCAP file (bad magic bytes)")
	}
	return nil
}

func WriteMagic(w io.Writer) error {
	_, err := w.Write([]byte(mcapMagic))
	return err
}

// ReadRecord reads one MCAP record: opcode (1 byte) + length (uint64 LE) + data.
// Returns io.EOF when there are no more records.
func ReadRecord(r io.Reader) (opcode byte, data []byte, err error) {
	var hdr [9]byte
	if _, err = io.ReadFull(r, hdr[:]); err != nil {
		return
	}
	opcode = hdr[0]
	length := binary.LittleEndian.Uint64(hdr[1:])
	if length > 0 {
		data = make([]byte, length)
		_, err = io.ReadFull(r, data)
	}
	return
}

// WriteRecord writes one MCAP record: opcode + uint64 length + data.
func WriteRecord(w io.Writer, opcode byte, data []byte) error {
	hdr := make([]byte, 9)
	hdr[0] = opcode
	binary.LittleEndian.PutUint64(hdr[1:], uint64(len(data)))
	if _, err := w.Write(hdr); err != nil {
		return err
	}
	if len(data) > 0 {
		_, err := w.Write(data)
		return err
	}
	return nil
}

// emptyFooter is a Footer record payload with SummaryStart=0 (no summary section).
var emptyFooter = make([]byte, 20)
