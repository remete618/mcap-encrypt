# Reproducible Builds

The `mcap-encrypt` Go CLI is built reproducibly. Given the same source tree,
the same Go toolchain version, and the same OS/architecture target, two
independent builds will produce byte-identical binaries with the same SHA-256.

This page is the recipe a security-conscious user follows to verify that a
published release binary was built from the source tree the release tag
points at.

## What "reproducible" means here

The release pipeline (`.goreleaser.yaml`) builds the CLI with:

- `CGO_ENABLED=0` (pure Go, no host C toolchain involvement)
- `-trimpath` (file paths in panics/DWARF are repository-relative, not host-absolute)
- `-ldflags="-s -w -X main.version=<tag>"` (strip symbol/debug info; embed the version string)

No timestamps, hostnames, or build paths are embedded in the binary. The only
input that changes between builds is the version string passed to
`-X main.version`, and that is fully derived from the git tag.

Two consecutive local builds at the same commit, with the same Go toolchain,
for the same `GOOS/GOARCH`, produce binaries with the same SHA-256. This was
verified at commit time for `linux/amd64`; the same property holds for the
other published targets.

## Recipe: reproduce a published release locally

The example below reproduces the `linux/amd64` binary for tag `vX.Y.Z`.
Replace the tag and target as needed.

```bash
TAG="v0.9.0"                       # the release you want to verify
VERSION="${TAG#v}"                 # GoReleaser strips the leading "v"
GOOS="linux"
GOARCH="amd64"

# 1. Get the exact source the release was cut from.
git clone https://github.com/remete618/mcap-encrypt.git
cd mcap-encrypt
git checkout "tags/${TAG}"

# 2. Match the Go toolchain version used by the release.
#    The release workflow reads it from go.mod via setup-go.
grep '^go ' go.mod

# 3. Build with the same flags as the release.
#    Write the output to a directory OUTSIDE the source tree, otherwise
#    Go embeds vcs.modified=true into the binary because it considers the
#    untracked output directory as a working-tree modification, which
#    changes the binary's bytes. Using a path under /tmp is safe.
REPRO_OUT="$(mktemp -d)"
GOOS="${GOOS}" GOARCH="${GOARCH}" CGO_ENABLED=0 \
  go build -trimpath \
    -ldflags="-s -w -X main.version=${VERSION}" \
    -o "${REPRO_OUT}/mcap-encrypt" \
    ./cmd/mcap-encrypt

# 4. Hash the local binary.
shasum -a 256 "${REPRO_OUT}/mcap-encrypt"
```

## Compare against the published checksum

Every release publishes `checksums.txt`, a Cosign-signed manifest of SHA-256
hashes for every shipped archive (`checksums.txt.sig` and `checksums.txt.pem`
sit alongside it).

```bash
TAG="v0.9.0"
VERSION="${TAG#v}"
ASSET="mcap-encrypt_${VERSION}_linux_amd64.tar.gz"

# 1. Download the release archive and the published checksum manifest to
#    a scratch directory outside the source tree.
DL_DIR="$(mktemp -d)"
gh release download "${TAG}" \
  --repo remete618/mcap-encrypt \
  --pattern "${ASSET}" \
  --pattern "checksums.txt" \
  --dir "${DL_DIR}"

# 2. Verify the checksum manifest covers your downloaded archive.
( cd "${DL_DIR}" && shasum -a 256 --check --ignore-missing checksums.txt )

# 3. Extract the binary from the published archive into a scratch dir.
PUBLISHED_OUT="$(mktemp -d)"
tar -xzf "${DL_DIR}/${ASSET}" -C "${PUBLISHED_OUT}" mcap-encrypt

# 4. Hash both binaries and compare.
shasum -a 256 "${PUBLISHED_OUT}/mcap-encrypt" "${REPRO_OUT}/mcap-encrypt"
```

The two SHA-256 values must be identical. If they are, the published binary
was built from the source tree at tag `${TAG}` and nothing else.

Optionally, also verify the Cosign signature on `checksums.txt`:

```bash
gh release download "${TAG}" \
  --repo remete618/mcap-encrypt \
  --pattern "checksums.txt.pem" \
  --pattern "checksums.txt.sig" \
  --dir "${DL_DIR}"

cosign verify-blob \
  --certificate "${DL_DIR}/checksums.txt.pem" \
  --signature   "${DL_DIR}/checksums.txt.sig" \
  --certificate-identity-regexp 'https://github.com/remete618/mcap-encrypt/.*' \
  --certificate-oidc-issuer     'https://token.actions.githubusercontent.com' \
  "${DL_DIR}/checksums.txt"
```

## Limitations

| Constraint | Why it matters |
|---|---|
| Same `GOOS`/`GOARCH` as the published asset | Cross-compiled binaries are byte-different per target by construction |
| Same Go toolchain minor version | Compiler/linker updates change generated code; the `go` directive in `go.mod` pins it |
| Same source tree (verify `git rev-parse HEAD` matches the tag) | Any local change, even a whitespace edit, will change the hash |
| No untracked files inside the repo root | Go embeds `vcs.modified=true` if `git status` reports untracked or modified files, which changes the binary. Use a build-output path outside the source tree (the recipe above uses `$(mktemp -d)`) or one that is already in `.gitignore`. |
| Pure-Go only (`CGO_ENABLED=0`) | A C toolchain would introduce host-specific paths and symbols |
| Archive hash will not match the binary hash | The `.tar.gz` packaging includes `README.md`, `LICENSE`, `CHANGELOG.md`; reproduce the binary inside it, not the archive |

## Historical note: releases before this recipe

Releases cut before this recipe landed (notably `v0.9.0` and earlier) were
built with `go mod tidy` running as a GoReleaser pre-build hook. When that
hook had anything to change (e.g. promoting an indirect dependency to a
direct one), it dirtied the working tree and embedded `vcs.modified=true`
and the `+dirty` pseudo-version into the binary via Go's
`runtime/debug.BuildInfo`. The resulting bytes cannot be reproduced from
a clean checkout of the tag.

You can confirm whether a given release binary was built dirty:

```bash
go version -m mcap-encrypt | grep vcs.modified
```

If it prints `vcs.modified=true`, the binary was built with a dirty tree
and will not reproduce from the tag alone. From the first release made
after the `.goreleaser.yaml` fix that removed the `go mod tidy` hook,
this value is `false` and the recipe above produces a byte-identical
binary.

## Continuous verification

The `.github/workflows/repro.yml` workflow runs on every push to `main` and
every pull request. It builds the CLI twice with the release flags inside the
same job and fails if the two SHA-256 values diverge. On release tags it
additionally downloads the published `checksums.txt` and verifies the local
build matches the entry for `linux_amd64`.
