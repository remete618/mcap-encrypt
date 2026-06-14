# Full project audit, 2026-06-14

This document captures an independent twelve-dimension audit of mcap-encrypt
at commit `483f6648`. Each dimension was graded by a blind reviewer with no
access to prior reviews or maintainer summaries, and each finding cites
`file:line` evidence. The grades use a uniform 0-10 scale where 10 is
reference quality, 9 is production-grade, 8 is strong with one known gap,
7 is functional with a real defect, 6 is usable but unwise for serious work,
and 5 or below is a material risk.

The intent of this audit is to set a public, defensible baseline that a
prospective enterprise buyer or external security assessor can read cold.
The findings are ordered by value per week of work so the maintainer can act
on the highest leverage items first.

## Executive summary

mcap-encrypt is a credible, security-aware open-source library. Eight of the
twelve dimensions land at 8 or 9, with cryptographic correctness, CI/CD, and
release engineering at 9. The three lowest grades are project sustainability
at 6 (single-author bus factor), Python code quality at 7 (idiomatic surface
but missing the `py.typed` marker and using loose dict-based internal
contracts), and strategic positioning at 7 (no explicit competitive
narrative, no funding angle). No active security defect was identified.
None of the gaps are blockers for a public open-source release; they are the
short list of items a buyer would expect to see closed before signing a paid
contract.

## Grade matrix

| Dimension | Grade | Rationale |
|---|---|---|
| Cryptographic correctness | 9 | Chunk AAD binds every mutable field, nonces are fresh per record, the slot trial is constant-time, manifest HMAC uses constant-time compare (`pkg/mcapencrypt/decrypt.go:328-354`). |
| Code quality (Go) | 8 | gofmt-clean, `%w` error wrapping, deferred cleanup, explicit `clear()` of sensitive memory; a few functions sit above 200 lines (`pkg/mcapencrypt/encrypt.go:240-602`). |
| Code quality (TypeScript) | 8 | Strict types, browser-safe (no Node-only APIs), RFC 8410 DER prefixes pinned with tests; some attachment helpers duplicated across files (`ts/src/rotate.ts:39-74` vs `ts/src/attachment.ts:92-107`). |
| Code quality (Python) | 7 | Parser bounds checks and error chaining are clean, but no `py.typed` marker and loose `dict` returns from internal codecs (`py/src/mcap_encrypt/decrypt.py:59`). |
| Format and spec maturity | 8 | `FORMAT.md` covers wire layout, conformance vectors pin every active primitive with CI drift detection; spec-version and on-wire `WrappedKeyData.version` live in separate namespaces (`FORMAT.md:3` vs `pkg/mcapencrypt/key.go:31`). |
| Documentation | 7 | CLI reference matches the binary exactly, KMS docs include a copy-pasteable IAM policy; test counts disagree across `README.md:422`, `docs/one-pager.md:60`, and `.github/SECURITY.md:202`. |
| Tests | 8 | Four Go fuzz targets plus the Python Hypothesis suite, race detector and conformance vectors in CI; conformance vectors are Go-only and TypeScript has no fuzz layer (`pkg/mcapencrypt/vectors_test.go:138`). |
| CI / CD | 9 | All actions pinned to commit SHAs, least-privilege permissions, OIDC publishing, reproducible-build verification with on-tag cross-check (`.github/workflows/repro.yml:74-152`); a few tools resolve as `@latest` (`ci.yml:45-49`). |
| Release engineering | 9 | Multi-platform GoReleaser with Cosign signing, GitHub attestations, SBOM, npm provenance, PyPI Trusted Publishers (`.goreleaser.yaml:45-55`); PyPI step still lacks SBOM and sigstore signing (`publish-pypi.yml:50-56`). |
| UX | 8 | Progress bar with throughput plus pause/resume, no-overwrite default, actionable error messages including the chmod fix; `--kms` decrypt and rotate skip the equivalent of the key-perm warning (`cmd/mcap-encrypt/main.go:408-432`). |
| Project sustainability | 6 | Solid governance hygiene (LICENSE, SECURITY.md, CONTRIBUTING.md, Renovate, templates, format version policy) but 151 of 159 commits are from a single author with no CODEOWNERS or named backup contact. |
| Strategic positioning | 7 | Crisp positioning, honest origin story, three-path Foxglove adoption matrix; no explicit competitive landscape and no funding or sustainability commercial path (`README.md:21-26`, `docs/one-pager.md:90-92`). |

## Top strengths across dimensions

1. The cryptographic core is well-anchored: per-chunk fresh nonces, complete
   AAD binding, RSA-4096 minimum, constant-time slot trial, manifest HMAC
   with constant-time compare, and a pinned X25519 HKDF test vector
   (`pkg/mcapencrypt/kdf_test.go:16-33`, `pkg/mcapencrypt/decrypt.go:329-354`).
2. The release pipeline is supply-chain-aware: SHA-pinned actions, OIDC
   publishing to npm and PyPI, byte-exact reproducible-build verification
   with on-tag cross-check against the published artifact
   (`.github/workflows/repro.yml:104-152`).
3. Conformance test vectors (`testdata/vectors/*.json`) re-verify live AAD,
   HKDF, manifest HMAC, and AEAD output on every CI run, with explicit
   drift-detection semantics (`pkg/mcapencrypt/vectors_test.go:138-147`).
4. Three resolved security findings (INT-2025-001 through INT-2025-003) plus
   the constant-time hardening (INT-2025-004) are documented honestly with
   trigger, impact, and fix (`.github/SECURITY.md`), which is the right
   posture for a security-critical OSS project.
5. The CLI defaults are safe: no silent overwrite, world-readable private
   keys produce a stderr warning with the exact `chmod 600` fix
   (`pkg/mcapencrypt/keyperms_unix.go:22-24`).

## Gaps (priority action table)

Each gap below has an impact score (1 low to 5 high) and an effort score
(1 low to 5 high). The score in the first column is `impact / effort`, so
items with the highest value per week of work appear first. Items below the
horizontal line are still useful but offer less leverage.

| Score | Dimension | Gap | Action | Impact | Effort |
|---:|---|---|---|---:|---:|
| 5.0 | Documentation | em-dash sweep & test-count consistency across `README.md:422`, `docs/one-pager.md:60`, `.github/SECURITY.md:202`. *(Initial auditor flagged em dashes; on rescan no U+2014 remain. Test-count inconsistency is real.)* | Pick one source of truth, update all docs to match the actual `go test`, `npm test`, `pytest -q` output. | 3 | 1 |
| 5.0 | CI / CD | `staticcheck`, `govulncheck`, and `goreleaser` resolve as `latest` and can change silently. | Pin each tool to an explicit version in `ci.yml` and `release.yml`. | 3 | 1 |
| 5.0 | Python | Library ships full type hints but no `py.typed` marker, so downstream type checkers ignore the annotations. | Add empty `py/src/mcap_encrypt/py.typed` and force-include in the wheel and sdist. | 3 | 1 |
| 5.0 | Sustainability | Stale issue #19 is still open although CONTRIBUTING.md and issue templates have shipped. | Close #19 with a link to the merged commits and add a monthly triage cadence note in CONTRIBUTING.md. | 2 | 1 |
| 4.0 | UX | `mcap-encrypt --help` / `-h` are not wired; only `version`/`--version`/`-v`. | Add `help`, `--help`, `-h` cases that print usage to stdout with exit 0. | 2 | 1 |
| 3.0 | Tests | Conformance vectors load only in Go; TypeScript and Python do not re-verify them. | Add `ts/test/vectors.test.ts` and `py/tests/test_vectors.py` that read `testdata/vectors/*.json` and compare live AAD/HKDF/HMAC outputs. | 5 | 2 |
| 3.0 | Format / spec | Spec version (6) and on-wire `WrappedKeyData.version` (3) live in separate namespaces with no on-wire signal of spec-level version. | Add a `spec_version` byte to `WrappedKeyData`, bind it into chunk AAD, and document the downgrade-resistance policy in `FORMAT.md`. | 4 | 2 |
| 3.0 | Format / spec | Conformance vectors omit RSA-OAEP-SHA-256 key wrapping and the `WrappedKeyData` binary layout. | Add `testdata/vectors/rsa_oaep.json` (fixed key, fixed-RNG vector) and `testdata/vectors/wrapped_key_layout.json`. | 4 | 2 |
| 3.0 | Strategic | No explicit competitive landscape; alternatives such as age or GPG envelope encryption are not named or compared. | Add a "Why not age/GPG/envelope encryption?" table to `README.md` citing chunk-level seek, the bridge, and multi-recipient as the three differentiators. | 4 | 2 |
| 3.0 | Crypto | Manifest HMAC covers chunk count and FileID only, not encrypted attachment or metadata counts. | Extend the manifest payload to bind attachment and metadata counts, bump manifest to v4, require counts on decrypt. | 3 | 3 → 1 |
| 3.0 | Release-eng | Cosign signs only `checksums.txt`, not individual archives; verification recipe uses a regex identity. | Set `signs.artifacts: all` (or add a second sign block) and tighten the verify recipe to `--certificate-identity` with the exact workflow path and tag. | 3 | 2 |
| 2.5 | TS | `parseAttachmentFields` and `encodeAttachment` are duplicated across four files. | Centralize in `ts/src/attachment.ts` and import from one source. | 3 | 1 |
| 2.5 | Go | Block-scoped `defer scanFile.Close()` actually runs at function return, holding two file descriptors during the second encrypt pass. | Move pass-1 work into a helper so the deferred Close fires at the boundary. | 2 | 1 |
| 2.0 | Sustainability | Bus factor of one (151 of 159 commits from the maintainer); no `MAINTAINERS.md` or `CODEOWNERS`. | Recruit at least one backup maintainer and add `MAINTAINERS.md` plus `.github/CODEOWNERS`. | 5 | 3 |
| 2.0 | Tests | TypeScript has no fuzz or property-based tests despite being the browser distribution. | Add `ts/test/fuzz.test.ts` using `fast-check` to drive the parsers with random bytes; target ~5 s per run. | 4 | 3 |
| 2.0 | UX | Library API surfaces diverge: Go exposes streaming and bridge helpers that TypeScript and Python lack. | Add a feature-parity table to `README.md` so TypeScript and Python users do not assume bridge or streaming exist on their side. | 3 | 3 |
| 2.0 | Strategic | No named target customer; market-fit story is in generalities. | Add two or three concrete user stories to `README.md` with the exact CLI flow per role. | 4 | 2 |
| 1.5 | Documentation | KMS doc references a "not yet implemented" public-key helper without a tracking issue. | Drop the placeholder, lead with the `aws kms get-public-key | base64 -d | openssl pkey` recipe, or link a tracking issue. | 2 | 1 |
| 1.5 | Strategic | The "where should this live" question sits open in the public one-pager. | Commit to a stance (independent through v1.0, then re-evaluate) or move the strategic-home question to an internal doc. | 3 | 2 |
| 1.3 | Python | Internal codecs return loose `dict`, requiring `# type: ignore` and inviting key typos. | Replace dict returns with frozen dataclasses and remove `# type: ignore` clusters. | 3 | 2 |
| 1.0 | Release-eng | PyPI workflow ships no SBOM, no sigstore signing, no GitHub attestation for the wheel/sdist. | Add `actions/attest-build-provenance` and `anchore/sbom-action` to `publish-pypi.yml`. | 3 | 2 |
| 1.0 | Crypto | X25519 KEK derivation is HPKE-equivalent but not RFC 9180 conformant. | Migrate to HPKE once a stable Go API exists; until then document the deviation in `FORMAT.md`. | 2 | 3 |
| 1.0 | Sustainability | No PGP key on the security contact; only a personal email. | Add a PGP fingerprint and a backup contact, or enable GitHub private vulnerability reporting. | 2 | 2 |
| 1.0 | Strategic | No funding or sustainability commercial path is described. | Add a short "Support and sustainability" section to `README.md` (open-source MIT core, optional paid support, sponsor link, maintenance cadence). | 3 | 3 |
| 0.7 | Format / spec | No explicit opcode-reservation or backwards-compat SLA. | Add an "Opcode allocation" section reserving 0x80-0x8F and a "Backwards-compatibility policy" section to `FORMAT.md`. | 3 | 1 |
| 0.7 | Strategic | No public audit-scope artifact a vendor can quote from. | Publish `docs/audit-scope.md` listing in-scope packages, threat model, resolved findings, and conformance vector status. | 3 | 3 |

## Recommendation

Three honest paths forward, listed without preference:

**Path A: tighten the quick wins, then publish v1.0.** Close every gap in
the first eleven rows of the table (test-count consistency, `py.typed`,
SHA-pin the linters, conformance vectors in TS and Python, help flag, KMS
parity warnings, attachment helpers consolidation). Roughly two engineering
weeks. Tag v1.0 once the audit-scope artifact is published. This is the
shortest path to a defensible enterprise pitch without changing the project
shape.

**Path B: book the external audit now and let it set the agenda.** The
cryptographic core is at 9 and the release pipeline is at 9; an external
auditor will probably find one or two of the same items already listed.
Booking the audit puts a date in the calendar, which forces the open
strategic questions ("where does this live", "who is the second maintainer")
to a decision. Expect six to twelve weeks of calendar time and the cost
quoted by the chosen firm.

**Path C: keep the current shape, harden over the next quarter.** Treat the
audit table as a punch list. Take one row per week. Re-audit at the end of
the quarter and reassess. Lowest stress, slowest signal to the market.

## Notes on this audit's methodology

Twelve independent blind reviewers were each given the same dimension brief,
the same pinned commit, and the same grading scale. Each was instructed to
cite file:line for every claim, list exactly three concrete gaps, and use
constructive language. The grades were normalized after collection, not
during. One auditor reported a banned-phrase auto-fail on Documentation that
did not reproduce on a fresh scan; that score is shown above with the
underlying gaps left intact for the maintainer to act on.

Total wall-clock time, 12 audits in three parallel batches: about 18 minutes.
