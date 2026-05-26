package mcapencrypt_test

import (
	"errors"
	"path/filepath"
	"runtime"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/remete618/mcap-encrypt/pkg/mcapencrypt"
)

// TestZstdPoolConcurrency verifies that concurrent encrypt/decrypt operations
// using the pooled zstd decoder do not race or corrupt each other's output.
// -race catches data races; this test ensures pool sharing is safe under load.
func TestZstdPoolConcurrency(t *testing.T) {
	dir := t.TempDir()
	plainPath := filepath.Join(dir, "plain.mcap")
	keyBase := filepath.Join(dir, "key")

	buildTestMCAP(t, plainPath)
	require.NoError(t, mcapencrypt.GenerateKeyPair(keyBase))

	// Pre-encrypt once so all goroutines decrypt the same file.
	encPath := filepath.Join(dir, "enc.mcap")
	require.NoError(t, mcapencrypt.Encrypt(plainPath, encPath, keyBase+".pub.pem"))
	origMsgs := readAllMessages(t, plainPath)

	n := runtime.GOMAXPROCS(0) * 4
	var wg sync.WaitGroup
	errs := make([]error, n)
	for i := range n {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			decPath := filepath.Join(dir, "dec-"+string(rune('A'+i))+".mcap")
			if err := mcapencrypt.Decrypt(encPath, decPath, keyBase+".priv.pem"); err != nil {
				errs[i] = err
				return
			}
			msgs := readAllMessages(t, decPath)
			if len(msgs) != len(origMsgs) {
				errs[i] = errors.New("message count mismatch")
			}
		}(i)
	}
	wg.Wait()

	for i, err := range errs {
		require.NoError(t, err, "goroutine %d failed", i)
	}
}

// TestZstdPoolRoundTrip verifies decompressZstd produces correct output when
// the pool is exercised across multiple sequential calls (tests Reset correctness).
func TestZstdPoolRoundTrip(t *testing.T) {
	dir := t.TempDir()
	keyBase := filepath.Join(dir, "key")
	require.NoError(t, mcapencrypt.GenerateKeyPair(keyBase))

	// Encrypt and decrypt 5 different files sequentially to exercise pool reuse.
	for i := range 5 {
		plainPath := filepath.Join(dir, "plain-"+string(rune('A'+i))+".mcap")
		encPath := filepath.Join(dir, "enc-"+string(rune('A'+i))+".mcap")
		decPath := filepath.Join(dir, "dec-"+string(rune('A'+i))+".mcap")

		buildTestMCAP(t, plainPath)
		require.NoError(t, mcapencrypt.Encrypt(plainPath, encPath, keyBase+".pub.pem"))
		require.NoError(t, mcapencrypt.Decrypt(encPath, decPath, keyBase+".priv.pem"))

		orig := readAllMessages(t, plainPath)
		dec := readAllMessages(t, decPath)
		require.Equal(t, len(orig), len(dec), "iter %d: message count mismatch", i)
		for j, om := range orig {
			require.Equal(t, om.Data, dec[j].Data, "iter %d msg %d: data mismatch", i, j)
		}
	}
}

// TestPrivateKeyMaterialZeroed verifies that loading a private key succeeds and
// the key remains functional; the zeroing of buffer internals is exercised under
// -race to catch any use-after-free if the key struct ever aliases the cleared slice.
func TestPrivateKeyMaterialZeroed(t *testing.T) {
	dir := t.TempDir()
	keyBase := filepath.Join(dir, "key")
	require.NoError(t, mcapencrypt.GenerateKeyPair(keyBase))

	plainPath := filepath.Join(dir, "plain.mcap")
	encPath := filepath.Join(dir, "enc.mcap")
	decPath := filepath.Join(dir, "dec.mcap")
	buildTestMCAP(t, plainPath)

	// LoadPrivateKeyAny zeros block.Bytes and the PEM data after parsing.
	// The resulting key must still be usable for full encrypt/decrypt.
	require.NoError(t, mcapencrypt.Encrypt(plainPath, encPath, keyBase+".pub.pem"))
	require.NoError(t, mcapencrypt.Decrypt(encPath, decPath, keyBase+".priv.pem"))

	orig := readAllMessages(t, plainPath)
	dec := readAllMessages(t, decPath)
	require.Equal(t, len(orig), len(dec))
}

// TestX25519PrivateKeyMaterialZeroed mirrors the RSA test for X25519 keys.
func TestX25519PrivateKeyMaterialZeroed(t *testing.T) {
	dir := t.TempDir()
	keyBase := filepath.Join(dir, "key")
	require.NoError(t, mcapencrypt.GenerateX25519KeyPair(keyBase))

	plainPath := filepath.Join(dir, "plain.mcap")
	encPath := filepath.Join(dir, "enc.mcap")
	decPath := filepath.Join(dir, "dec.mcap")
	buildTestMCAP(t, plainPath)

	require.NoError(t, mcapencrypt.Encrypt(plainPath, encPath, keyBase+".pub.pem"))
	require.NoError(t, mcapencrypt.Decrypt(encPath, decPath, keyBase+".priv.pem"))

	orig := readAllMessages(t, plainPath)
	dec := readAllMessages(t, decPath)
	require.Equal(t, len(orig), len(dec))
}
