# Contributing to mcap-encrypt

Thank you for helping improve mcap-encrypt. Issues and pull requests are welcome at [github.com/remete618/mcap-encrypt](https://github.com/remete618/mcap-encrypt).

## Prerequisites

| Tool   | Version |
|--------|---------|
| Go     | 1.26+   |
| Node   | 20+     |
| npm    | 10+     |
| Python | 3.10+   |
| uv     | 0.4+    |

## Build

```bash
# Go CLI
go build ./cmd/mcap-encrypt

# TypeScript library
cd ts && npm ci && npm run build
```

## Tests

```bash
# Go (all tests + race detector)
go test -race ./...

# Go (benchmarks, 3 iterations each)
go test ./pkg/mcapencrypt/... -run='^$' -bench=. -benchmem -benchtime=3x

# TypeScript unit tests
cd ts && npm test

# Python library tests (requires uv)
cd py && uv sync --extra dev && uv run python -m pytest

# Cross-language interop tests (requires Go binary in PATH)
cd ts && npm run test:interop

# Go fuzzing
go test -fuzz=FuzzDecodeEncryptedChunk ./pkg/mcapencrypt/
```

## Code style

- Go: `gofmt` is enforced by CI. Run `gofmt -w .` before committing.
- TypeScript: no linter currently configured; follow the existing style.
- No new comments unless the *why* is non-obvious.
- Use [Conventional Commits](https://www.conventionalcommits.org/) prefixes: `fix:`, `feat:`, `test:`, `docs:`, etc.

## PR checklist

- [ ] `go test -race ./...` passes locally
- [ ] `cd ts && npm run typecheck && npm test` passes locally
- [ ] `cd py && uv sync --extra dev && uv run python -m pytest` passes locally
- [ ] New behavior has a test (Go, TypeScript, and/or Python as appropriate)
- [ ] No secrets, PEM keys, or `.env` files committed
- [ ] PR targets `main`; branch name is `your-github-username/short-description`

## Versioning

The Go CLI and the npm package are versioned independently:

- Go releases are tagged `v<major>.<minor>.<patch>` and built by GoReleaser.
- The npm package version lives in `ts/package.json` and is published by the `publish-npm` workflow on tag push.

## Security

To report a vulnerability, see [SECURITY.md](.github/SECURITY.md).

The maintainer merges from the `remete618` GitHub account; fork and open PRs as you normally would.
