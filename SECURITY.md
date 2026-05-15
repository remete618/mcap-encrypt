# Security Policy

## Supported versions

Only the latest release on `main` receives security fixes.

## Reporting a vulnerability

Please **do not** open a public GitHub issue for security vulnerabilities.

Email: radu@cioplea.com

Include:
- A description of the vulnerability and its potential impact
- Steps to reproduce or a minimal proof of concept
- The affected component (Go library, TypeScript library, CLI, or file format)

Expected response time: within 7 days. If a fix is warranted, a patched release will be issued and the reporter credited (unless anonymity is requested).

## Scope

In scope:
- Incorrect AEAD usage (nonce reuse, missing authentication, AAD bypass)
- Key unwrapping vulnerabilities (RSA-OAEP misuse, oracle attacks)
- Format parsing vulnerabilities (buffer overflows, integer overflows in record parsing)
- Logic errors that allow decryption without the private key

Out of scope:
- Plaintext schema and channel metadata (intentional by design)
- Attachment content not being encrypted (documented known limitation)
- Vulnerabilities in dependencies — please report those upstream

## Security status

This library uses standard primitives (XChaCha20-Poly1305, RSA-2048-OAEP-SHA-256) and has
adversarial unit tests. It has **not** been externally audited. Use accordingly.
