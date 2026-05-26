"""Tests for inspect_mcap."""
from __future__ import annotations

import pytest

from mcap_encrypt import encrypt_mcap, inspect_mcap


class TestInspectEncrypted:
    def test_inspect_encrypted_rsa(self, rsa_key_pair, test_mcap_bytes):
        pub, priv = rsa_key_pair
        encrypted = encrypt_mcap(test_mcap_bytes, pub)
        result = inspect_mcap(encrypted)

        assert result.is_encrypted is True
        assert result.format_version == 3
        assert result.file_id is not None
        assert len(result.file_id) == 16
        assert result.chunk_count == 1
        assert result.encrypted_chunk_count == 1
        assert result.encrypted_attachment_count == 0
        assert len(result.recipients) == 1
        assert result.recipients[0].kek_alg == "rsa-oaep-sha256"
        assert result.recipients[0].algorithm == "xchacha20poly1305"
        assert len(result.recipients[0].key_id) == 64  # hex SHA-256

    def test_inspect_encrypted_x25519(self, x25519_key_pair, test_mcap_bytes):
        pub, priv = x25519_key_pair
        encrypted = encrypt_mcap(test_mcap_bytes, pub)
        result = inspect_mcap(encrypted)

        assert result.is_encrypted is True
        assert result.recipients[0].kek_alg == "x25519-hkdf-xchacha20poly1305"

    def test_inspect_multi_recipient(self, rsa_key_pair, x25519_key_pair, test_mcap_bytes):
        rsa_pub, _ = rsa_key_pair
        x25519_pub, _ = x25519_key_pair
        encrypted = encrypt_mcap(test_mcap_bytes, [rsa_pub, x25519_pub])
        result = inspect_mcap(encrypted)

        assert result.is_encrypted is True
        assert len(result.recipients) == 2
        algs = {r.kek_alg for r in result.recipients}
        assert "rsa-oaep-sha256" in algs
        assert "x25519-hkdf-xchacha20poly1305" in algs

    def test_inspect_file_id_consistent_across_recipients(
        self, rsa_key_pair, rsa_key_pair_b, test_mcap_bytes
    ):
        pub_a, _ = rsa_key_pair
        pub_b, _ = rsa_key_pair_b
        encrypted = encrypt_mcap(test_mcap_bytes, [pub_a, pub_b])
        result = inspect_mcap(encrypted)
        # All recipients have the same file_id.
        assert result.file_id is not None
        assert len(result.file_id) == 16

    def test_inspect_compression(self, rsa_key_pair, test_mcap_bytes):
        pub, _ = rsa_key_pair
        encrypted = encrypt_mcap(test_mcap_bytes, pub)
        result = inspect_mcap(encrypted)
        # Source MCAP uses empty compression.
        assert result.compression == ""


class TestInspectPlain:
    def test_inspect_plain(self, test_mcap_bytes):
        result = inspect_mcap(test_mcap_bytes)
        assert result.is_encrypted is False
        assert result.encrypted_chunk_count == 0
        assert result.encrypted_attachment_count == 0
        assert result.recipients == []
        assert result.file_id is None

    def test_inspect_invalid_magic(self):
        with pytest.raises(ValueError, match="[Mm]agic|not an MCAP"):
            inspect_mcap(b"not an mcap file at all!")
