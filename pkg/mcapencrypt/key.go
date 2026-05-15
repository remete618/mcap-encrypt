package mcapencrypt

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"os"
)

const (
	AttachmentName      = "mcap_encryption_key"
	AttachmentMediaType = "application/x-mcap-wrapped-key"
	wrappedKeyVersion   = byte(2)
	fileIDSize          = 16
)

// WrappedKeyData is the binary payload stored inside the WrappedKey Attachment.
type WrappedKeyData struct {
	FileID     []byte // 16 random bytes, same for every recipient of a given file
	KeyID      string
	Algorithm  string // "xchacha20poly1305"
	KEKAlg     string // "rsa-oaep-sha256"
	WrappedKey []byte
}

func (k *WrappedKeyData) Encode() []byte {
	keyID := []byte(k.KeyID)
	alg := []byte(k.Algorithm)
	kekAlg := []byte(k.KEKAlg)

	n := 1 +
		fileIDSize +
		4 + len(keyID) +
		4 + len(alg) +
		4 + len(kekAlg) +
		4 + len(k.WrappedKey)

	buf := make([]byte, n)
	o := 0

	buf[o] = wrappedKeyVersion
	o++
	copy(buf[o:], k.FileID)
	o += fileIDSize
	putBytes := func(b []byte) {
		binary.LittleEndian.PutUint32(buf[o:], uint32(len(b)))
		o += 4
		copy(buf[o:], b)
		o += len(b)
	}
	putBytes(keyID)
	putBytes(alg)
	putBytes(kekAlg)
	putBytes(k.WrappedKey)
	return buf
}

func DecodeWrappedKeyData(data []byte) (*WrappedKeyData, error) {
	if len(data) < 1 {
		return nil, fmt.Errorf("empty wrapped key data")
	}
	if data[0] != wrappedKeyVersion {
		return nil, fmt.Errorf("unsupported wrapped key version %d (want %d)", data[0], wrappedKeyVersion)
	}
	if len(data) < 1+fileIDSize {
		return nil, fmt.Errorf("truncated: too short for file_id")
	}
	k := &WrappedKeyData{}
	k.FileID = make([]byte, fileIDSize)
	copy(k.FileID, data[1:1+fileIDSize])
	o := 1 + fileIDSize

	getBytes := func() ([]byte, error) {
		if o+4 > len(data) {
			return nil, fmt.Errorf("truncated")
		}
		n := int(binary.LittleEndian.Uint32(data[o:]))
		o += 4
		if o+n > len(data) {
			return nil, fmt.Errorf("truncated")
		}
		v := make([]byte, n)
		copy(v, data[o:o+n])
		o += n
		return v, nil
	}
	getString := func() (string, error) { b, err := getBytes(); return string(b), err }

	var err error
	if k.KeyID, err = getString(); err != nil {
		return nil, fmt.Errorf("read key_id: %w", err)
	}
	if k.Algorithm, err = getString(); err != nil {
		return nil, fmt.Errorf("read algorithm: %w", err)
	}
	if k.KEKAlg, err = getString(); err != nil {
		return nil, fmt.Errorf("read kek_algorithm: %w", err)
	}
	if k.WrappedKey, err = getBytes(); err != nil {
		return nil, fmt.Errorf("read wrapped_key: %w", err)
	}

	if k.Algorithm != "xchacha20poly1305" {
		return nil, fmt.Errorf("unsupported encryption algorithm %q (want xchacha20poly1305)", k.Algorithm)
	}
	if k.KEKAlg != "rsa-oaep-sha256" {
		return nil, fmt.Errorf("unsupported key-wrapping algorithm %q (want rsa-oaep-sha256)", k.KEKAlg)
	}
	if len(k.WrappedKey) != 256 {
		return nil, fmt.Errorf("wrapped key length %d invalid (RSA-2048 produces 256 bytes)", len(k.WrappedKey))
	}
	return k, nil
}

// GenerateKeyPair writes basename.priv.pem (0600) and basename.pub.pem (0644).
func GenerateKeyPair(basename string) error {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("generate RSA key: %w", err)
	}
	privDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return fmt.Errorf("marshal private key: %w", err)
	}
	privPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER})
	if err := os.WriteFile(basename+".priv.pem", privPEM, 0600); err != nil {
		return fmt.Errorf("write private key: %w", err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		return fmt.Errorf("marshal public key: %w", err)
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})
	if err := os.WriteFile(basename+".pub.pem", pubPEM, 0644); err != nil {
		return fmt.Errorf("write public key: %w", err)
	}
	return nil
}

func LoadPublicKey(path string) (*rsa.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block in %s", path)
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("%s does not contain an RSA public key", path)
	}
	return rsaPub, nil
}

func LoadPrivateKey(path string) (*rsa.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block in %s", path)
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	rsaKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("%s does not contain an RSA private key", path)
	}
	return rsaKey, nil
}

func WrapSymmetricKey(symKey []byte, pub *rsa.PublicKey) ([]byte, error) {
	return rsa.EncryptOAEP(sha256.New(), rand.Reader, pub, symKey, nil)
}

func UnwrapSymmetricKey(wrapped []byte, priv *rsa.PrivateKey) ([]byte, error) {
	return rsa.DecryptOAEP(sha256.New(), rand.Reader, priv, wrapped, nil)
}
