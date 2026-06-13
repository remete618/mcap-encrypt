//go:build !windows

package mcapencrypt

import (
	"fmt"
	"os"
)

// CheckPrivateKeyFilePermissions returns a human-readable warning message if
// the file at path is readable by group or other. Returns an empty string if
// the file mode is safe (0600 or stricter), or if the file cannot be stat'd.
//
// On Windows this function always returns an empty string because Windows
// uses ACLs rather than POSIX mode bits.
func CheckPrivateKeyFilePermissions(path string) string {
	info, err := os.Stat(path)
	if err != nil {
		return ""
	}
	mode := info.Mode().Perm()
	if mode&0o077 != 0 {
		return fmt.Sprintf("private key file %s has insecure permissions %#o (readable by group or others); use chmod 600 %s", path, mode, path)
	}
	return ""
}
