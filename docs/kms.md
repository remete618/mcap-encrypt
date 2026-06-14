# AWS KMS backend

`mcap-encrypt` can unwrap the per-file symmetric key by calling out to AWS
KMS instead of reading a private key from disk. The RSA-4096 private half
stays inside the KMS HSM boundary; only the 32-byte symmetric key returns
to the host that decrypts chunks.

The wire format does not change. A file encrypted with a recipient's
public key can be decrypted by either:

- the matching private key on disk, via `--key <priv.pem>`, or
- the KMS that holds the matching private key, via `--kms aws:<arn>`.

## Why use KMS

- The RSA-4096 private key never leaves the HSM. An attacker with full
  host access cannot exfiltrate the unwrap key, only force individual
  unwraps that get logged in CloudTrail.
- IAM controls who can decrypt. Revoking access is a policy edit instead
  of rotating every file on disk.
- CloudTrail logs every `kms:Decrypt` call, including the principal and
  ARN, giving you a per-file audit trail without changes to the file format.

## Setup

### 1. Create an asymmetric RSA-4096 ENCRYPT_DECRYPT key

```bash
aws kms create-key \
  --key-spec RSA_4096 \
  --key-usage ENCRYPT_DECRYPT \
  --description "mcap-encrypt recipient key"
```

Note the `KeyMetadata.Arn` from the response, for example:

```
arn:aws:kms:us-east-1:111122223333:key/abcd1234-...
```

Optionally give the key an alias for ergonomics:

```bash
aws kms create-alias \
  --alias-name alias/mcap-encrypt-prod \
  --target-key-id <key-id-from-above>
```

The ARN form is recommended in production because it is unambiguous across
regions and accounts.

### 2. Export the public key

The encrypt path runs locally and needs an SPKI PEM file. Two options:

**Option A: use the CLI helper (when the host has KMS access).** Not yet
implemented; see `kms.Decrypter.PublicKey` if you want to write one.

**Option B: use the AWS CLI.**

```bash
aws kms get-public-key \
  --key-id <arn> \
  --output text \
  --query PublicKey \
  | base64 -d > kms.pub.der

openssl pkey -pubin -inform DER -in kms.pub.der -out kms.pub.pem
```

`kms.pub.pem` now contains a standard PKIX SubjectPublicKeyInfo PEM block
that you can feed to `mcap-encrypt encrypt --key kms.pub.pem ...`.

### 3. Minimum IAM policy

The decrypting principal needs `kms:Decrypt`. `kms:GetPublicKey` is only
needed if you fetch the public key through the SDK at runtime; if you ship
the public key as a file you can omit it.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "McapEncryptUnwrap",
      "Effect": "Allow",
      "Action": [
        "kms:Decrypt",
        "kms:GetPublicKey"
      ],
      "Resource": "arn:aws:kms:us-east-1:111122223333:key/abcd1234-..."
    }
  ]
}
```

Tighten as needed. `kms:Decrypt` accepts an optional
`kms:EncryptionAlgorithm` condition that you can pin to
`RSAES_OAEP_SHA_256` to refuse any other algorithm at the IAM layer.

## CLI examples

Encrypt locally, using the public key exported from KMS:

```bash
mcap-encrypt encrypt --key kms.pub.pem input.mcap encrypted.mcap
```

Decrypt via the KMS:

```bash
mcap-encrypt decrypt \
  --kms aws:arn:aws:kms:us-east-1:111122223333:key/abcd1234-... \
  encrypted.mcap decrypted.mcap
```

Rotate to a new on-disk recipient without ever exposing the old private key:

```bash
mcap-encrypt rotate \
  --old-kms aws:arn:aws:kms:us-east-1:111122223333:key/abcd1234-... \
  --new-key new-recipient.pub.pem \
  encrypted.mcap rotated.mcap
```

Stream via the Foxglove WebSocket bridge with KMS-backed unwrap:

```bash
mcap-encrypt bridge \
  --kms aws:arn:aws:kms:us-east-1:111122223333:key/abcd1234-... \
  encrypted.mcap
```

The `aws:` URI scheme uses the default AWS SDK chain (environment
variables, shared config, IMDS), so the standard `AWS_REGION`,
`AWS_PROFILE`, and credential variables all apply.

## Rotation guidance

The wrapped key inside an encrypted MCAP is the result of
`RSA-OAEP-SHA-256(public-key, symmetric-key)`. AWS KMS rotation of the
underlying RSA key material is independent of the bytes in your MCAP
file: KMS keeps every prior version, so `kms:Decrypt` continues to
work against historical files.

If you want to change the recipient set, run `mcap-encrypt rotate`. That
re-wraps the symmetric key against the new set of public keys without
touching any chunk data.

## LocalStack integration test

A build-tag-gated integration test stands up a real KMS RSA-4096 key
against a local LocalStack endpoint and exercises the AWS Decrypter
end-to-end:

```bash
docker run --rm -p 4566:4566 localstack/localstack

export AWS_ENDPOINT_URL=http://localhost:4566
export AWS_REGION=us-east-1
export AWS_ACCESS_KEY_ID=test
export AWS_SECRET_ACCESS_KEY=test

go test -tags=localstack -race ./pkg/mcapencrypt/kms/...
```

Without `AWS_ENDPOINT_URL`, the test skips cleanly so it does not break
CI environments that have no LocalStack.

## Limitations

- Only AWS KMS is implemented in this release. GCP KMS, Azure Key Vault,
  HashiCorp Vault, and PKCS#11 are tracked as separate issues.
- AWS KMS does not support X25519. Use an X25519 key only if both
  recipients are on disk.
- Encryption still happens locally. KMS only unwraps. If you need
  server-side wrap as well, file an issue.
