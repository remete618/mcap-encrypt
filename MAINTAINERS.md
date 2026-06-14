# Maintainers

## Active maintainers

| Name | GitHub | Role | Contact |
|---|---|---|---|
| Radu Cioplea | [@remete618](https://github.com/remete618) | Lead maintainer, primary committer | radu@cioplea.com |

## Security contact

Security issues should be reported via [`.github/SECURITY.md`](.github/SECURITY.md), not in public issues. Active backup contact for security disclosures: same email as above.

## Decision rules

- Code changes land via pull request; the lead maintainer reviews and merges.
- Format-version bumps require a PR with updated `FORMAT.md`, updated `testdata/vectors/`, and updated cross-language interop tests.
- Breaking changes to a public API or wire format require a major version bump.

## Looking for co-maintainers

The project would benefit from a second active maintainer with cryptography, robotics tooling, or Go release-engineering background. Interested? Open an issue with the `help wanted` label or email the contact above. The bar is steady review participation and willingness to triage incoming issues.
