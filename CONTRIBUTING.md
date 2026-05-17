# Contributing to mcap-encrypt

Thank you for helping improve mcap-encrypt. Issues and pull requests are welcome at [github.com/remete618/mcap-encrypt](https://github.com/remete618/mcap-encrypt).

## Local development

```bash
# Go unit tests
go test ./...

# TypeScript tests
cd ts && npm test

# Cross-language interop (requires Go installed)
cd ts && npm run test:interop

# Go fuzzing
go test -fuzz=FuzzDecodeEncryptedChunk ./pkg/mcapencrypt/
```

## Pull requests

- Branch from `main`.
- One pull request per issue when possible.
- Use [Conventional Commits](https://www.conventionalcommits.org/) prefixes: `fix:`, `feat:`, `test:`, `docs:`, etc.
- Describe what changed and how you tested it in the PR template.

The maintainer merges from the `remete618` GitHub account; fork and open PRs as you normally would.
