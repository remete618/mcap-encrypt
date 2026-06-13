//go:build !windows

package mcapencrypt

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCheckPrivateKeyFilePermissions(t *testing.T) {
	dir := t.TempDir()

	cases := []struct {
		name      string
		mode      os.FileMode
		wantEmpty bool
	}{
		{"strict_0600", 0o600, true},
		{"stricter_0400", 0o400, true},
		{"world_readable_0644", 0o644, false},
		{"group_readable_0640", 0o640, false},
		{"other_readable_0604", 0o604, false},
		{"world_writable_0666", 0o666, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(dir, tc.name+".pem")
			if err := os.WriteFile(path, []byte("dummy"), tc.mode); err != nil {
				t.Fatalf("write file: %v", err)
			}
			// WriteFile honors umask; explicitly chmod to the desired mode.
			if err := os.Chmod(path, tc.mode); err != nil {
				t.Fatalf("chmod: %v", err)
			}

			got := CheckPrivateKeyFilePermissions(path)
			if tc.wantEmpty && got != "" {
				t.Errorf("expected no warning for mode %#o, got %q", tc.mode, got)
			}
			if !tc.wantEmpty {
				if got == "" {
					t.Errorf("expected warning for mode %#o, got none", tc.mode)
				}
				if !strings.Contains(got, "chmod 600") {
					t.Errorf("warning should suggest chmod 600, got %q", got)
				}
			}
		})
	}
}

func TestCheckPrivateKeyFilePermissions_MissingFile(t *testing.T) {
	got := CheckPrivateKeyFilePermissions("/nonexistent/path/to/key.pem")
	if got != "" {
		t.Errorf("expected empty string for missing file, got %q", got)
	}
}
