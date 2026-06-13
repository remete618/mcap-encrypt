//go:build windows

package mcapencrypt

// CheckPrivateKeyFilePermissions is a no-op on Windows because Windows uses
// ACLs rather than POSIX mode bits. Returns an empty string always.
func CheckPrivateKeyFilePermissions(path string) string {
	return ""
}
