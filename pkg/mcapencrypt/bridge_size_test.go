package mcapencrypt

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestLoadBridgeStateRejectsOversizedFile confirms LoadBridgeState refuses to
// open a file larger than MaxBridgeFileSize before attempting to allocate any
// RAM for messages. A sparse file is used so the test does not consume
// MaxBridgeFileSize bytes of disk.
func TestLoadBridgeStateRejectsOversizedFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "huge.mcap")

	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	// Seek past the limit and write a single byte to mark EOF. On macOS and
	// Linux this creates a sparse file (logical size large, on-disk size tiny).
	if _, err := f.Seek(MaxBridgeFileSize+1, 0); err != nil {
		t.Fatalf("seek: %v", err)
	}
	if _, err := f.Write([]byte{0}); err != nil {
		t.Fatalf("write: %v", err)
	}
	f.Close()

	// privKeyPath does not need to exist; the size check should fire first.
	_, err = LoadBridgeState(path, "/nonexistent.priv.pem")
	if err == nil {
		t.Fatal("expected error for oversized file, got nil")
	}
	msg := err.Error()
	if !strings.Contains(msg, "exceeds the bridge limit") {
		t.Errorf("error should mention bridge limit; got %q", msg)
	}
	if !strings.Contains(msg, "mcap-encrypt decrypt") {
		t.Errorf("error should suggest using decrypt; got %q", msg)
	}
}
