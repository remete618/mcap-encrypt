package kms

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
)

// awsKMSAPI is the slice of *kms.Client we actually use. Defining it as an
// interface lets unit tests inject a stub without hitting AWS.
type awsKMSAPI interface {
	Decrypt(ctx context.Context, in *kms.DecryptInput, optFns ...func(*kms.Options)) (*kms.DecryptOutput, error)
	GetPublicKey(ctx context.Context, in *kms.GetPublicKeyInput, optFns ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error)
}

// AWS is a Decrypter that delegates to AWS KMS. Construct via NewAWS or
// NewAWSWithConfig. The constructor only stores the ARN and a client; no
// network calls happen until Decrypt or PublicKey is invoked.
//
// The private key never leaves the KMS boundary. kms.Decrypt returns the
// plaintext symmetric key (32 bytes) over TLS to the calling process, which
// matches mcapencrypt's existing trust boundary: the symmetric key must
// reach the host that decrypts chunks.
type AWS struct {
	keyARN string
	client awsKMSAPI
}

// NewAWS constructs an AWS Decrypter using the default AWS config chain
// (environment, shared config, IMDS). keyARN is the full ARN of an
// asymmetric RSA-4096 ENCRYPT_DECRYPT KMS key.
//
// For LocalStack or other non-default endpoints, use NewAWSWithConfig and
// pass an aws.Config built with config.WithBaseEndpoint(...).
func NewAWS(ctx context.Context, keyARN string) (*AWS, error) {
	if keyARN == "" {
		return nil, fmt.Errorf("kms/aws: empty keyARN")
	}
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("kms/aws: load default config: %w", err)
	}
	return NewAWSWithConfig(cfg, keyARN), nil
}

// NewAWSWithConfig constructs an AWS Decrypter from an explicit aws.Config.
// Use this when you need a custom endpoint (LocalStack), region, or
// credential chain.
func NewAWSWithConfig(cfg aws.Config, keyARN string) *AWS {
	return &AWS{
		keyARN: keyARN,
		client: kms.NewFromConfig(cfg),
	}
}

// newAWSWithClient is the test seam: it lets unit tests inject a stub
// implementation of awsKMSAPI without touching aws.Config.
func newAWSWithClient(client awsKMSAPI, keyARN string) *AWS {
	return &AWS{keyARN: keyARN, client: client}
}

// Decrypt implements Decrypter by calling kms:Decrypt with the
// RSAES_OAEP_SHA_256 algorithm. The ciphertext blob is the wrapped-key
// bytes as produced by mcapencrypt.WrapSymmetricKey, bit-identical to the
// on-disk path so existing files decrypt without conversion.
func (a *AWS) Decrypt(ctx context.Context, kekAlg string, wrappedKey []byte) ([]byte, error) {
	if kekAlg != KEKAlgRSAOAEPSHA256 {
		return nil, fmt.Errorf("kms/aws: only %q supported, got %q", KEKAlgRSAOAEPSHA256, kekAlg)
	}
	out, err := a.client.Decrypt(ctx, &kms.DecryptInput{
		CiphertextBlob:      wrappedKey,
		KeyId:               aws.String(a.keyARN),
		EncryptionAlgorithm: types.EncryptionAlgorithmSpecRsaesOaepSha256,
	})
	if err != nil {
		return nil, fmt.Errorf("kms/aws: Decrypt: %w", err)
	}
	return out.Plaintext, nil
}

// PublicKey implements Decrypter by calling kms:GetPublicKey and wrapping
// the SPKI DER blob in a PEM "PUBLIC KEY" block, ready to feed into
// mcapencrypt.Encrypt via the --key path.
func (a *AWS) PublicKey(ctx context.Context) ([]byte, error) {
	out, err := a.client.GetPublicKey(ctx, &kms.GetPublicKeyInput{
		KeyId: aws.String(a.keyARN),
	})
	if err != nil {
		return nil, fmt.Errorf("kms/aws: GetPublicKey: %w", err)
	}
	if out.KeyUsage != types.KeyUsageTypeEncryptDecrypt {
		return nil, fmt.Errorf("kms/aws: key usage is %q, need ENCRYPT_DECRYPT", out.KeyUsage)
	}
	// AWS returns SPKI DER. Wrap it in PEM so it matches the format
	// LoadPublicKeyAny expects.
	return SPKIToPEM(out.PublicKey), nil
}
