"""Hypothesis-based fuzz tests for the Python parser surface.

Mirrors the Go fuzz targets in ``pkg/mcapencrypt/fuzz_test.go``:

- ``FuzzDecodeEncryptedChunk``       -> ``test_fuzz_decode_encrypted_chunk``
- ``FuzzDecodeEncryptedAttachment``  -> ``test_fuzz_decode_encrypted_attachment``
- ``FuzzDecodeWrappedKeyData``       -> ``test_fuzz_decode_wrapped_key_data``
- ``FuzzStreamDecrypt``              -> ``test_fuzz_decrypt_pipeline``

The Go suite found three input-validation bugs (INT-2025-001/002/003); these
harnesses cover the equivalent Python entry points. Each test treats only the
documented "well-behaved parser" exceptions (ValueError, struct.error,
UnicodeDecodeError, cryptography.exceptions.*, decompression errors, OSError)
as expected. Notably, IndexError and KeyError are NOT in the expected set:
in parser code those usually indicate a missing bounds check, and the parser
SHOULD raise ValueError on short or malformed input. Any other exception,
including AssertionError, OverflowError, SystemError, MemoryError, TypeError,
IndexError, or KeyError, is allowed to propagate so Hypothesis reports it as
a finding.

Regression-seed workflow
------------------------
If a fuzz test fails, Hypothesis writes the failing example to
``.hypothesis/examples/``. To commit it as a regression seed:

1. Copy the failing example file to
   ``py/tests/fuzz_regressions/<target_name>/`` (one subdirectory per
   fuzz target, e.g. ``fuzz_regressions/test_fuzz_decode_encrypted_chunk/``).
2. ``py/tests/fuzz_regressions/`` is exempted from the ``.hypothesis``
   gitignore via ``!py/tests/fuzz_regressions/**`` so seeds checked into
   that subdirectory ARE tracked by git.
3. The seed replays on every test run via ``@example`` (add the literal
   bytes to the corresponding ``@example`` decorator on the fuzz target,
   or load them from the file in a setup hook).

This mirrors the Go corpus workflow under ``pkg/mcapencrypt/testdata/fuzz/``.
"""
from __future__ import annotations

import struct

from hypothesis import HealthCheck, given, settings, strategies as st

import cryptography.exceptions as _crypto_exc

from mcap_encrypt import generate_key_pair
from mcap_encrypt._keys import WrappedKeyData
from mcap_encrypt.decrypt import (
    _decode_encrypted_attachment,
    _decode_encrypted_chunk,
    _decode_encrypted_metadata,
    decrypt_mcap,
)


# Exceptions a well-behaved parser may legitimately raise on hostile input.
# Anything outside this tuple is a finding. IndexError and KeyError are
# DELIBERATELY excluded: in parser code they almost always indicate a missing
# bounds check, and the parser should raise ValueError instead.
_EXPECTED_PARSER_EXC: tuple[type[BaseException], ...] = (
    ValueError,
    UnicodeDecodeError,
    struct.error,
    _crypto_exc.InvalidKey,
    _crypto_exc.InvalidSignature,
    _crypto_exc.InvalidTag,
    _crypto_exc.NotYetFinalized,
    _crypto_exc.AlreadyFinalized,
    OSError,
)


# Hypothesis profile: 200 examples per target, no per-example deadline so
# slower CI runners do not flake. Each test still completes well under 30s.
_FUZZ_SETTINGS = settings(
    max_examples=200,
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow, HealthCheck.data_too_large],
)


# ---------------------------------------------------------------------------
# Standalone parser fuzz targets
# ---------------------------------------------------------------------------


@_FUZZ_SETTINGS
@given(data=st.binary(min_size=0, max_size=10_000))
def test_fuzz_decode_encrypted_chunk(data: bytes) -> None:
    """EncryptedChunk parser must not crash on arbitrary bytes."""
    try:
        _decode_encrypted_chunk(data)
    except _EXPECTED_PARSER_EXC:
        pass


@_FUZZ_SETTINGS
@given(data=st.binary(min_size=0, max_size=10_000))
def test_fuzz_decode_encrypted_attachment(data: bytes) -> None:
    """EncryptedAttachment parser must not crash on arbitrary bytes."""
    try:
        _decode_encrypted_attachment(data)
    except _EXPECTED_PARSER_EXC:
        pass


@_FUZZ_SETTINGS
@given(data=st.binary(min_size=0, max_size=10_000))
def test_fuzz_decode_encrypted_metadata(data: bytes) -> None:
    """EncryptedMetadata parser must not crash on arbitrary bytes.

    Not in the Go suite but a peer parser of the same shape; cheap to cover.
    """
    try:
        _decode_encrypted_metadata(data)
    except _EXPECTED_PARSER_EXC:
        pass


@_FUZZ_SETTINGS
@given(data=st.binary(min_size=0, max_size=10_000))
def test_fuzz_decode_wrapped_key_data(data: bytes) -> None:
    """WrappedKeyData parser must not crash on arbitrary bytes."""
    try:
        WrappedKeyData.decode(data)
    except _EXPECTED_PARSER_EXC:
        pass


# ---------------------------------------------------------------------------
# Full-pipeline fuzz target (mirrors FuzzStreamDecrypt)
# ---------------------------------------------------------------------------


# Generated once per process: RSA key generation is ~1s and we only need a
# valid key so the pipeline reaches every code path. The fuzz cases never
# decrypt successfully; they only drive the parser surface.
# Cached at module level (not a pytest fixture) so Hypothesis's @given can
# read it directly without fighting fixture-scoping rules.
_PIPELINE_PRIVATE_KEY: str | None = None


def _get_pipeline_private_key() -> str:
    global _PIPELINE_PRIVATE_KEY
    if _PIPELINE_PRIVATE_KEY is None:
        _, _PIPELINE_PRIVATE_KEY = generate_key_pair()
    return _PIPELINE_PRIVATE_KEY


# MCAP magic seeds, same idea as Go's f.Add() corpus. Hypothesis blends these
# with random bytes via st.one_of below so the parser actually reaches the
# encrypted-record code paths instead of bouncing off "not an MCAP" early.
_MCAP_MAGIC = b"\x89MCAP0\r\n"

_pipeline_strategy = st.one_of(
    st.binary(min_size=0, max_size=10_000),
    st.builds(
        lambda tail: _MCAP_MAGIC + tail,
        st.binary(min_size=0, max_size=10_000),
    ),
    st.builds(
        lambda tail: _MCAP_MAGIC + tail + _MCAP_MAGIC,
        st.binary(min_size=0, max_size=10_000),
    ),
)


# Decompression failures and downstream library errors are also legitimate.
_PIPELINE_EXPECTED_EXC: tuple[type[BaseException], ...] = _EXPECTED_PARSER_EXC + (
    EOFError,
    RuntimeError,
)


@_FUZZ_SETTINGS
@given(data=_pipeline_strategy)
def test_fuzz_decrypt_pipeline(data: bytes) -> None:
    """End-to-end decrypt_mcap pipeline must not crash on arbitrary bytes."""
    priv_pem = _get_pipeline_private_key()
    try:
        decrypt_mcap(data, priv_pem)
    except _PIPELINE_EXPECTED_EXC:
        pass
    except Exception as exc:
        # zstandard raises a private exception class (ZstdError) that derives
        # from Exception but not from any of our expected bases. Accept it
        # here rather than letting it surface as a finding.
        name = type(exc).__name__
        if name in ("ZstdError", "LZ4FrameError", "Lz4FrameError"):
            return
        raise
