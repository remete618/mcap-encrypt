package mcapencrypt_test

import (
	"bytes"
	"math"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/remete618/mcap-encrypt/pkg/mcapencrypt"
)

// TestDecryptSlotTrialConstantTime is a wall-clock smoke test for issue #21:
// the wrapped-key slot trial in DecryptWithOptions must run every slot
// regardless of which one matches, so an attacker cannot infer the matching
// recipient from decrypt latency.
//
// Method:
//  1. Encrypt one plaintext file for N=8 recipients in a fixed key order.
//  2. Build two test files by re-encrypting with the target recipient placed
//     first (slot 0) vs last (slot N-1) in the recipient list. The wrapped-key
//     attachments are written in recipient order, so the matching slot
//     position matches its list index.
//  3. Decrypt each file iters times, measuring wall-clock time per decrypt.
//  4. Compare medians (median is more robust than mean to GC pauses).
//
// This is a smoke test, not a cryptographic proof of constant-time. A real
// timing audit needs nanosecond-resolution measurement with statistical
// tooling such as dudect (https://github.com/oreparaz/dudect) or t-test
// based analysis over many thousands of samples with cache flushes. The
// goal here is to catch the obvious "first-match early-return" regression.
//
// To keep the test fast in CI while still meaningful, RSA-4096 (the slow
// path) is used: each unwrap takes ~milliseconds, so even a few hundred
// iterations produce a clear signal over GC noise.
func TestDecryptSlotTrialConstantTime(t *testing.T) {
	if testing.Short() {
		t.Skip("timing test skipped under -short")
	}

	const (
		numRecipients = 8
		iters         = 200 // ~200 * 8 unwraps * a few ms RSA = ~few seconds total
		// Constant-time should keep median ratio close to 1.0. Allow ample
		// margin for OS jitter; a regression to early-return makes
		// last-slot decrypt take ~N times longer than first-slot.
		maxRatio = 1.5
	)

	dir := t.TempDir()
	plainPath := filepath.Join(dir, "plain.mcap")
	buildTestMCAP(t, plainPath)

	// Generate N RSA recipient keypairs.
	pubKeys := make([]string, numRecipients)
	privKeys := make([]string, numRecipients)
	for i := 0; i < numRecipients; i++ {
		base := filepath.Join(dir, "k"+itoa(i))
		require.NoError(t, mcapencrypt.GenerateKeyPair(base))
		pubKeys[i] = base + ".pub.pem"
		privKeys[i] = base + ".priv.pem"
	}

	// Two recipient orders: target first, target last. The target key
	// (privKeys[0]) decrypts both. With a constant-time slot trial, decrypt
	// latency should be near-identical.
	target := pubKeys[0]
	others := append([]string{}, pubKeys[1:]...)

	firstOrder := append([]string{target}, others...)
	lastOrder := append(append([]string{}, others...), target)

	firstEnc := filepath.Join(dir, "first.mcap")
	lastEnc := filepath.Join(dir, "last.mcap")
	require.NoError(t, mcapencrypt.EncryptMulti(plainPath, firstEnc, firstOrder))
	require.NoError(t, mcapencrypt.EncryptMulti(plainPath, lastEnc, lastOrder))

	firstBytes, err := os.ReadFile(firstEnc)
	require.NoError(t, err)
	lastBytes, err := os.ReadFile(lastEnc)
	require.NoError(t, err)

	privPEM, err := os.ReadFile(privKeys[0])
	require.NoError(t, err)
	priv := string(privPEM)

	decryptOnce := func(enc []byte) time.Duration {
		out := &bytes.Buffer{}
		t0 := time.Now()
		err := mcapencrypt.DecryptWithOptions(bytes.NewReader(enc), out, priv, mcapencrypt.DecryptOptions{})
		dt := time.Since(t0)
		require.NoError(t, err)
		return dt
	}

	// Warm-up: prime caches and the Go runtime so the first sample is
	// not an outlier. Discarded.
	for i := 0; i < 5; i++ {
		_ = decryptOnce(firstBytes)
		_ = decryptOnce(lastBytes)
	}

	firstSamples := make([]time.Duration, iters)
	lastSamples := make([]time.Duration, iters)
	// Interleave to share noise: alternating samples spreads transient
	// system load across both groups equally.
	for i := 0; i < iters; i++ {
		firstSamples[i] = decryptOnce(firstBytes)
		lastSamples[i] = decryptOnce(lastBytes)
	}

	mFirst := medianDuration(firstSamples)
	mLast := medianDuration(lastSamples)
	ratio := math.Max(float64(mFirst), float64(mLast)) / math.Min(float64(mFirst), float64(mLast))

	t.Logf("N=%d recipients, %d iters: median first=%v median last=%v ratio=%.3f",
		numRecipients, iters, mFirst, mLast, ratio)

	require.Less(t, ratio, maxRatio,
		"slot-trial timing ratio %.3f exceeds %.2f; matching slot position may be observable via wall-clock timing (regression of issue #21)",
		ratio, maxRatio)
}

// medianDuration returns the median of samples (samples is mutated by Sort).
func medianDuration(samples []time.Duration) time.Duration {
	cp := make([]time.Duration, len(samples))
	copy(cp, samples)
	// Simple insertion sort: small N, fine.
	for i := 1; i < len(cp); i++ {
		for j := i; j > 0 && cp[j-1] > cp[j]; j-- {
			cp[j-1], cp[j] = cp[j], cp[j-1]
		}
	}
	n := len(cp)
	if n%2 == 1 {
		return cp[n/2]
	}
	return (cp[n/2-1] + cp[n/2]) / 2
}

// itoa is a tiny strconv.Itoa to avoid importing strconv for a 1-digit number.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}
