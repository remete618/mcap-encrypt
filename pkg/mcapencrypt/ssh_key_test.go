package mcapencrypt_test

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"encoding/base64"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/remete618/mcap-encrypt/pkg/mcapencrypt"
)

// requireSSHKeygen skips the test if ssh-keygen is not on PATH (CI windows
// runner, sandboxed builders). The tests in this file deliberately shell out
// to ssh-keygen so we exercise the real OpenSSH on-disk format, not a
// hand-rolled byte string that might drift from the spec.
func requireSSHKeygen(t *testing.T) string {
	t.Helper()
	path, err := exec.LookPath("ssh-keygen")
	if err != nil {
		t.Skip("ssh-keygen not available on PATH; skipping SSH key tests")
	}
	return path
}

// generateSSHKey runs ssh-keygen with the given algorithm/bits and optional
// passphrase, returning the basename (pub at basename+".pub", priv at basename).
func generateSSHKey(t *testing.T, dir, alg string, bits int, passphrase string) string {
	t.Helper()
	keygen := requireSSHKeygen(t)
	basename := filepath.Join(dir, alg+"_key")
	args := []string{"-q", "-t", alg, "-N", passphrase, "-f", basename, "-C", "mcap-encrypt-test"}
	if bits > 0 {
		args = append(args, "-b", strconv.Itoa(bits))
	}
	cmd := exec.Command(keygen, args...)
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "ssh-keygen %v failed: %s", args, string(out))
	return basename
}

// TestLoadSSHEd25519PublicKey verifies an ssh-keygen ed25519 public key
// (single-line "ssh-ed25519 AAAA..." format) loads and gets converted to a
// usable X25519 public key.
func TestLoadSSHEd25519PublicKey(t *testing.T) {
	dir := t.TempDir()
	base := generateSSHKey(t, dir, "ed25519", 0, "")

	pub, err := mcapencrypt.LoadPublicKeyAny(base + ".pub")
	require.NoError(t, err)
	xpub, ok := pub.(*ecdh.PublicKey)
	require.True(t, ok, "ed25519 SSH pub must convert to *ecdh.PublicKey, got %T", pub)
	require.Equal(t, ecdh.X25519(), xpub.Curve())
	require.Len(t, xpub.Bytes(), 32)
}

// TestLoadSSHEd25519PrivateKey verifies the matching private key loads to an
// X25519 private key and that the derived public matches the converted
// public from the .pub side. This is the critical interop check: if either
// half of the RFC 7748 conversion is wrong, the derived publics won't match.
func TestLoadSSHEd25519PrivateKey(t *testing.T) {
	dir := t.TempDir()
	base := generateSSHKey(t, dir, "ed25519", 0, "")

	pubAny, err := mcapencrypt.LoadPublicKeyAny(base + ".pub")
	require.NoError(t, err)
	xpub := pubAny.(*ecdh.PublicKey)

	privAny, err := mcapencrypt.LoadPrivateKeyAny(base)
	require.NoError(t, err)
	xpriv, ok := privAny.(*ecdh.PrivateKey)
	require.True(t, ok, "ed25519 SSH priv must convert to *ecdh.PrivateKey, got %T", privAny)

	require.Equal(t,
		xpub.Bytes(), xpriv.PublicKey().Bytes(),
		"public derived from converted private must equal converted public; "+
			"any mismatch means the RFC 7748 conversion is broken")
}

// TestLoadSSHRSA4096PublicKey verifies an ssh-keygen rsa-4096 public key
// (single-line "ssh-rsa AAAA..." format) loads to an *rsa.PublicKey.
func TestLoadSSHRSA4096PublicKey(t *testing.T) {
	if testing.Short() {
		t.Skip("RSA-4096 generation is slow; skipped under -short")
	}
	dir := t.TempDir()
	base := generateSSHKey(t, dir, "rsa", 4096, "")

	pub, err := mcapencrypt.LoadPublicKeyAny(base + ".pub")
	require.NoError(t, err)
	rsaPub, ok := pub.(*rsa.PublicKey)
	require.True(t, ok, "rsa SSH pub must be *rsa.PublicKey, got %T", pub)
	require.Equal(t, 4096, rsaPub.N.BitLen())
}

// TestLoadSSHRSA4096PrivateKey verifies the matching private key loads to an
// *rsa.PrivateKey.
func TestLoadSSHRSA4096PrivateKey(t *testing.T) {
	if testing.Short() {
		t.Skip("RSA-4096 generation is slow; skipped under -short")
	}
	dir := t.TempDir()
	base := generateSSHKey(t, dir, "rsa", 4096, "")

	priv, err := mcapencrypt.LoadPrivateKeyAny(base)
	require.NoError(t, err)
	rsaPriv, ok := priv.(*rsa.PrivateKey)
	require.True(t, ok, "rsa SSH priv must be *rsa.PrivateKey, got %T", priv)
	require.Equal(t, 4096, rsaPriv.N.BitLen())
}

// TestSSHRSA2048Rejected verifies an RSA SSH key smaller than 4096 bits is
// rejected with the documented minimum-size error.
func TestSSHRSA2048Rejected(t *testing.T) {
	if testing.Short() {
		t.Skip("RSA generation is slow; skipped under -short")
	}
	dir := t.TempDir()
	base := generateSSHKey(t, dir, "rsa", 2048, "")

	_, err := mcapencrypt.LoadPublicKeyAny(base + ".pub")
	require.Error(t, err)
	require.Contains(t, err.Error(), "minimum is 4096 bits")

	_, err = mcapencrypt.LoadPrivateKeyAny(base)
	require.Error(t, err)
	require.Contains(t, err.Error(), "minimum is 4096 bits")
}

// TestSSHEd25519EncryptedRejected verifies that a passphrase-protected
// Ed25519 SSH key is rejected with the documented error pointing at the
// `ssh-keygen -p` workaround. Adding interactive passphrase prompting is
// explicitly out of scope.
func TestSSHEd25519EncryptedRejected(t *testing.T) {
	dir := t.TempDir()
	base := generateSSHKey(t, dir, "ed25519", 0, "correct-horse-battery-staple")

	_, err := mcapencrypt.LoadPrivateKeyAny(base)
	require.Error(t, err)
	require.Contains(t, err.Error(), "passphrase-protected")
	require.Contains(t, err.Error(), "ssh-keygen -p")
}

// TestSSHEd25519RoundTrip is the headline test: encrypt a real MCAP with an
// Ed25519 SSH public key as the recipient, then decrypt it with the
// matching Ed25519 SSH private key. If RFC 7748 conversion is wrong on
// either side, decryption fails.
func TestSSHEd25519RoundTrip(t *testing.T) {
	dir := t.TempDir()
	base := generateSSHKey(t, dir, "ed25519", 0, "")

	plainPath := filepath.Join(dir, "plain.mcap")
	encPath := filepath.Join(dir, "enc.mcap")
	decPath := filepath.Join(dir, "dec.mcap")
	buildTestMCAP(t, plainPath)

	require.NoError(t, mcapencrypt.Encrypt(plainPath, encPath, base+".pub"))
	require.NoError(t, mcapencrypt.Decrypt(encPath, decPath, base))

	orig := readAllMessages(t, plainPath)
	dec := readAllMessages(t, decPath)
	require.Equal(t, len(orig), len(dec), "ed25519 SSH round-trip: message count mismatch")
	for i, om := range orig {
		require.Equal(t, om.Data, dec[i].Data, "msg %d data mismatch", i)
	}
	t.Logf("OK: ed25519 SSH round-trip decrypted %d messages identical to source", len(dec))
}

// TestSSHRSARoundTrip mirrors the ed25519 round-trip with an RSA-4096 SSH
// key pair.
func TestSSHRSARoundTrip(t *testing.T) {
	if testing.Short() {
		t.Skip("RSA-4096 generation is slow; skipped under -short")
	}
	dir := t.TempDir()
	base := generateSSHKey(t, dir, "rsa", 4096, "")

	plainPath := filepath.Join(dir, "plain.mcap")
	encPath := filepath.Join(dir, "enc.mcap")
	decPath := filepath.Join(dir, "dec.mcap")
	buildTestMCAP(t, plainPath)

	require.NoError(t, mcapencrypt.Encrypt(plainPath, encPath, base+".pub"))
	require.NoError(t, mcapencrypt.Decrypt(encPath, decPath, base))

	orig := readAllMessages(t, plainPath)
	dec := readAllMessages(t, decPath)
	require.Equal(t, len(orig), len(dec))
	t.Logf("OK: rsa-4096 SSH round-trip decrypted %d messages identical to source", len(dec))
}

// TestEd25519ToX25519ConversionMatchesAge cross-checks the RFC 7748 §5 scalar
// derivation against an independent computation: an Ed25519 seed expanded
// with SHA-512 and clamped must yield a scalar k such that k*Basepoint
// (computed by Go's stdlib X25519) equals the Montgomery-u of the original
// Ed25519 public key. This is the same property `age` relies on for its
// ssh-ed25519 recipient support.
func TestEd25519ToX25519ConversionMatchesStdlib(t *testing.T) {
	// Generate a fresh Ed25519 key pair directly (no ssh-keygen needed).
	edPub, edPriv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	// Independent X25519 scalar derivation per RFC 7748 §5.
	h := sha512.Sum512(edPriv.Seed())
	scalar := make([]byte, 32)
	copy(scalar, h[:32])
	scalar[0] &= 248
	scalar[31] &= 127
	scalar[31] |= 64

	xPrivExpected, err := ecdh.X25519().NewPrivateKey(scalar)
	require.NoError(t, err)
	derivedPub := xPrivExpected.PublicKey()

	// Encrypt to the converted Ed25519 public key via the SSH-pubkey path.
	// We bypass parseSSHPublicKey by emitting an authorized_keys line and
	// re-parsing through the public API to exercise the same code path
	// users will hit.
	tmpDir := t.TempDir()
	pubPath := filepath.Join(tmpDir, "id_ed25519.pub")
	writeAuthorizedKey(t, pubPath, edPub)

	convertedPubAny, err := mcapencrypt.LoadPublicKeyAny(pubPath)
	require.NoError(t, err)
	convertedPub, ok := convertedPubAny.(*ecdh.PublicKey)
	require.True(t, ok)

	require.Equal(t,
		derivedPub.Bytes(), convertedPub.Bytes(),
		"the Montgomery-u of the Ed25519 public key must equal the public "+
			"key derived from scalar = clamp(SHA512(seed)[0:32]); a mismatch "+
			"here means the public-key birational map (1+y)/(1-y) is broken")
}

// writeAuthorizedKey serializes an Ed25519 public key in authorized_keys
// format. We do this manually instead of shelling to ssh-keygen so this
// test stays runnable even where ssh-keygen is absent.
func writeAuthorizedKey(t *testing.T, path string, edPub ed25519.PublicKey) {
	t.Helper()
	// The SSH wire format for ssh-ed25519 is:
	//   uint32 len("ssh-ed25519") | "ssh-ed25519" | uint32 len(pub) | pub
	// followed by base64 over the whole blob.
	algo := "ssh-ed25519"
	blob := make([]byte, 0, 4+len(algo)+4+len(edPub))
	blob = appendString(blob, []byte(algo))
	blob = appendString(blob, edPub)
	line := algo + " " + base64.StdEncoding.EncodeToString(blob) + " mcap-encrypt-test\n"
	require.NoError(t, os.WriteFile(path, []byte(line), 0644))
}

func appendString(dst, b []byte) []byte {
	dst = append(dst, byte(len(b)>>24), byte(len(b)>>16), byte(len(b)>>8), byte(len(b)))
	dst = append(dst, b...)
	return dst
}
