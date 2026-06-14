package kms

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
)

// stubKMS implements awsKMSAPI in-process: it holds a real *rsa.PrivateKey and
// performs OAEP locally, so we can exercise the AWS code path with no network.
type stubKMS struct {
	priv          *rsa.PrivateKey
	wantKeyID     string
	wantAlg       types.EncryptionAlgorithmSpec
	getPublicErr  error
	decryptErr    error
	getKeyUsage   types.KeyUsageType
	gotDecryptKey string
}

func (s *stubKMS) Decrypt(ctx context.Context, in *kms.DecryptInput, _ ...func(*kms.Options)) (*kms.DecryptOutput, error) {
	if s.decryptErr != nil {
		return nil, s.decryptErr
	}
	if in.EncryptionAlgorithm != s.wantAlg {
		return nil, errors.New("stubKMS: wrong algorithm")
	}
	if aws.ToString(in.KeyId) != s.wantKeyID {
		return nil, errors.New("stubKMS: wrong KeyId")
	}
	s.gotDecryptKey = aws.ToString(in.KeyId)
	plain, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, s.priv, in.CiphertextBlob, nil)
	if err != nil {
		return nil, err
	}
	return &kms.DecryptOutput{Plaintext: plain, KeyId: in.KeyId}, nil
}

func (s *stubKMS) GetPublicKey(ctx context.Context, in *kms.GetPublicKeyInput, _ ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error) {
	if s.getPublicErr != nil {
		return nil, s.getPublicErr
	}
	der, err := x509.MarshalPKIXPublicKey(&s.priv.PublicKey)
	if err != nil {
		return nil, err
	}
	usage := s.getKeyUsage
	if usage == "" {
		usage = types.KeyUsageTypeEncryptDecrypt
	}
	return &kms.GetPublicKeyOutput{PublicKey: der, KeyUsage: usage}, nil
}

func TestAWSDecryptRoundTrip(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	const arn = "arn:aws:kms:us-east-1:111122223333:key/abcd"
	stub := &stubKMS{priv: priv, wantKeyID: arn, wantAlg: types.EncryptionAlgorithmSpecRsaesOaepSha256}
	a := newAWSWithClient(stub, arn)

	symKey := make([]byte, 32)
	if _, err := rand.Read(symKey); err != nil {
		t.Fatalf("rand: %v", err)
	}
	wrapped, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, &priv.PublicKey, symKey, nil)
	if err != nil {
		t.Fatalf("EncryptOAEP: %v", err)
	}
	got, err := a.Decrypt(context.Background(), KEKAlgRSAOAEPSHA256, wrapped)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if string(got) != string(symKey) {
		t.Fatal("plaintext mismatch")
	}
	if stub.gotDecryptKey != arn {
		t.Fatalf("stub got KeyId=%q want %q", stub.gotDecryptKey, arn)
	}
}

func TestAWSRejectsUnsupportedKEKAlg(t *testing.T) {
	a := newAWSWithClient(&stubKMS{}, "arn:aws:kms:us-east-1:111122223333:key/abcd")
	_, err := a.Decrypt(context.Background(), "x25519-hkdf-xchacha20poly1305", []byte("x"))
	if err == nil {
		t.Fatal("expected error for unsupported kekAlg")
	}
}

func TestAWSPublicKeyPEM(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048) // smaller key for test speed
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	stub := &stubKMS{priv: priv}
	a := newAWSWithClient(stub, "arn:aws:kms:us-east-1:111122223333:key/abcd")
	pemBytes, err := a.PublicKey(context.Background())
	if err != nil {
		t.Fatalf("PublicKey: %v", err)
	}
	// Trivial sanity check: starts with PEM header.
	if len(pemBytes) < len("-----BEGIN PUBLIC KEY-----") || string(pemBytes[:26]) != "-----BEGIN PUBLIC KEY-----" {
		t.Fatalf("not a PEM PUBLIC KEY block: %q", pemBytes[:40])
	}
}

func TestAWSPublicKeyRejectsWrongUsage(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	stub := &stubKMS{priv: priv, getKeyUsage: types.KeyUsageTypeSignVerify}
	a := newAWSWithClient(stub, "arn:aws:kms:us-east-1:111122223333:key/abcd")
	if _, err := a.PublicKey(context.Background()); err == nil {
		t.Fatal("expected error when KeyUsage is SIGN_VERIFY")
	}
}
