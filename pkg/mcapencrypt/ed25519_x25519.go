package mcapencrypt

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/sha512"
	"fmt"
	"math/big"
)

// Ed25519 and X25519 (Curve25519) are birationally equivalent. Per RFC 7748
// section 4.1 ("Curve25519") and section 5 ("Edwards-y to Montgomery-u"),
// every Edwards25519 point (x, y) maps to a Montgomery point (u, v) via
//
//	u = (1 + y) / (1 - y)  mod p
//
// where p = 2^255 - 19. Public keys carry only the y coordinate (the sign of
// x is recoverable from a single bit but is unused for ECDH on the Montgomery
// curve), so the encoded transformation is just the formula above applied to
// the 32-byte little-endian y value.
//
// For the scalar (private key), an Ed25519 seed s is expanded via
//
//	h = SHA-512(s)
//	clamp(h[0:32])
//
// where clamp clears the bottom three bits, clears bit 255, and sets bit 254.
// The resulting 32-byte little-endian scalar k is exactly the value that
// X25519 multiplies by the base point to obtain the corresponding public key.
// This is the well-known construction used by `age` and signal-protocol's
// XEd25519 design.
//
// The conversion is correct because the underlying group operation is
// preserved by the birational map, so an ECDH performed with the
// X25519-converted key pair yields the same shared secret as one performed
// with a "native" X25519 key pair derived from the same scalar.

// curve25519P is the prime 2^255 - 19 used for both Ed25519 and Curve25519.
var curve25519P = func() *big.Int {
	p := new(big.Int).Lsh(big.NewInt(1), 255)
	return p.Sub(p, big.NewInt(19))
}()

// ed25519PublicKeyToX25519 converts an Ed25519 public key (32-byte
// little-endian encoded y coordinate with the x-sign bit in the high bit of
// the last byte) to a 32-byte X25519 public key per RFC 7748 section 5.
//
// The sign bit on the input is ignored: only the y coordinate participates
// in the Montgomery-u formula u = (1 + y) / (1 - y) mod p.
func ed25519PublicKeyToX25519(edPub ed25519.PublicKey) ([]byte, error) {
	if len(edPub) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("ed25519 public key must be %d bytes, got %d", ed25519.PublicKeySize, len(edPub))
	}

	// Decode the 32-byte little-endian y. Clear the high bit of the last
	// byte because Ed25519 stores the x-sign there; it is not part of y.
	yLE := make([]byte, 32)
	copy(yLE, edPub)
	yLE[31] &= 0x7f

	y := new(big.Int).SetBytes(reverseBytes(yLE))

	// u = (1 + y) * (1 - y)^-1 mod p
	one := big.NewInt(1)
	num := new(big.Int).Add(one, y)
	num.Mod(num, curve25519P)
	denom := new(big.Int).Sub(one, y)
	denom.Mod(denom, curve25519P)

	denomInv := new(big.Int).ModInverse(denom, curve25519P)
	if denomInv == nil {
		// Happens only for y == 1, which is not a valid Ed25519 public key.
		return nil, fmt.Errorf("ed25519 public key has no Montgomery image (y == 1)")
	}
	u := new(big.Int).Mul(num, denomInv)
	u.Mod(u, curve25519P)

	// Encode u as 32-byte little-endian.
	out := make([]byte, 32)
	uBytes := u.Bytes() // big-endian
	for i, b := range uBytes {
		out[len(uBytes)-1-i] = b
	}
	return out, nil
}

// ed25519PrivateKeyToX25519 converts an Ed25519 seed (the 32-byte secret) to
// a 32-byte X25519 scalar per RFC 7748 section 5. The Ed25519 PrivateKey
// type stores seed || pub; this function accepts either form and extracts
// the seed.
func ed25519PrivateKeyToX25519(edPriv ed25519.PrivateKey) ([]byte, error) {
	if len(edPriv) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("ed25519 private key must be %d bytes, got %d", ed25519.PrivateKeySize, len(edPriv))
	}
	seed := edPriv.Seed()
	defer clear(seed)

	// Expand seed with SHA-512 and clamp the lower half per RFC 7748 §5.
	h := sha512.Sum512(seed)
	defer clear(h[:])
	scalar := make([]byte, 32)
	copy(scalar, h[:32])
	scalar[0] &= 248
	scalar[31] &= 127
	scalar[31] |= 64
	return scalar, nil
}

// ed25519SSHKeyToX25519PublicKey converts an Ed25519 public key into an
// *ecdh.PublicKey suitable for use with WrapSymmetricKeyX25519.
func ed25519SSHKeyToX25519PublicKey(edPub ed25519.PublicKey) (*ecdh.PublicKey, error) {
	xPubBytes, err := ed25519PublicKeyToX25519(edPub)
	if err != nil {
		return nil, err
	}
	return ecdh.X25519().NewPublicKey(xPubBytes)
}

// ed25519SSHKeyToX25519PrivateKey converts an Ed25519 private key into an
// *ecdh.PrivateKey suitable for use with UnwrapSymmetricKeyX25519.
func ed25519SSHKeyToX25519PrivateKey(edPriv ed25519.PrivateKey) (*ecdh.PrivateKey, error) {
	scalar, err := ed25519PrivateKeyToX25519(edPriv)
	if err != nil {
		return nil, err
	}
	defer clear(scalar)
	return ecdh.X25519().NewPrivateKey(scalar)
}

// reverseBytes returns a new slice containing b reversed.
func reverseBytes(b []byte) []byte {
	out := make([]byte, len(b))
	for i, v := range b {
		out[len(b)-1-i] = v
	}
	return out
}
