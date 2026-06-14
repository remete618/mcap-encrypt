//go:build localstack
// +build localstack

package kms_test

// LocalStack-backed integration test for the AWS Decrypter. Stands up a
// real KMS RSA-4096 key against a LocalStack endpoint and exercises
// PublicKey + Decrypt end-to-end.
//
// Build with -tags=localstack and AWS_ENDPOINT_URL pointing at LocalStack:
//
//   docker run --rm -p 4566:4566 localstack/localstack
//   export AWS_ENDPOINT_URL=http://localhost:4566
//   export AWS_ACCESS_KEY_ID=test
//   export AWS_SECRET_ACCESS_KEY=test
//   export AWS_REGION=us-east-1
//   go test -tags=localstack -race ./pkg/mcapencrypt/kms/...
//
// Skips (does not fail) if AWS_ENDPOINT_URL is unset or the endpoint is
// unreachable, so CI environments without LocalStack are unaffected.

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"

	mcapkms "github.com/remete618/mcap-encrypt/pkg/mcapencrypt/kms"
)

func TestAWSIntegrationLocalStack(t *testing.T) {
	endpoint := os.Getenv("AWS_ENDPOINT_URL")
	if endpoint == "" {
		t.Skip("AWS_ENDPOINT_URL not set; LocalStack integration test skipped")
	}

	// Quick TCP probe so we skip cleanly when LocalStack is down rather
	// than hanging inside the SDK retry loop.
	if u, err := url.Parse(endpoint); err == nil && u.Host != "" {
		conn, dialErr := net.DialTimeout("tcp", u.Host, 2*time.Second)
		if dialErr != nil {
			t.Skipf("LocalStack not reachable at %s: %v", u.Host, dialErr)
		}
		_ = conn.Close()
	}

	ctx := context.Background()
	cfg, err := config.LoadDefaultConfig(ctx, config.WithBaseEndpoint(endpoint))
	if err != nil {
		t.Fatalf("LoadDefaultConfig: %v", err)
	}

	client := kms.NewFromConfig(cfg)

	createOut, err := client.CreateKey(ctx, &kms.CreateKeyInput{
		KeyUsage:    types.KeyUsageTypeEncryptDecrypt,
		KeySpec:     types.KeySpecRsa4096,
		Description: aws.String("mcap-encrypt integration test"),
	})
	if err != nil {
		t.Fatalf("CreateKey: %v", err)
	}
	keyARN := aws.ToString(createOut.KeyMetadata.Arn)
	t.Logf("created LocalStack KMS key: %s", keyARN)

	decrypter := mcapkms.NewAWSWithConfig(cfg, keyARN)

	pubPEM, err := decrypter.PublicKey(ctx)
	if err != nil {
		t.Fatalf("PublicKey: %v", err)
	}
	pub, err := parseRSAPublicKey(pubPEM)
	if err != nil {
		t.Fatalf("parse pub: %v", err)
	}

	symKey := make([]byte, 32)
	if _, err := rand.Read(symKey); err != nil {
		t.Fatalf("rand: %v", err)
	}
	wrapped, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pub, symKey, nil)
	if err != nil {
		t.Fatalf("EncryptOAEP: %v", err)
	}

	got, err := decrypter.Decrypt(ctx, mcapkms.KEKAlgRSAOAEPSHA256, wrapped)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if !bytes.Equal(got, symKey) {
		t.Fatal("round-trip plaintext mismatch")
	}
}

func parseRSAPublicKey(pemBytes []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("no PEM block")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("not an RSA public key: %T", pub)
	}
	return rsaPub, nil
}
