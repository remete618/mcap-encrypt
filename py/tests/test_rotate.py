"""Tests for rotate_mcap_keys."""
from __future__ import annotations

import pytest

from mcap_encrypt import (
    decrypt_mcap,
    encrypt_mcap,
    inspect_mcap,
    rotate_mcap_keys,
)
from mcap_encrypt._records import iter_records


def _extract_message_data(mcap_bytes: bytes) -> list[bytes]:
    """Extract raw message data bytes from a plain MCAP (from Chunk records)."""
    import struct
    msgs = []
    for opcode, payload in iter_records(mcap_bytes, start=8):
        if opcode == 0x06:  # Chunk
            off = 28
            (clen,) = struct.unpack_from("<I", payload, off)
            off += 4 + clen
            (rsz,) = struct.unpack_from("<Q", payload, off)
            off += 8
            inner = payload[off : off + rsz]
            inner_off = 0
            while inner_off < len(inner):
                if inner_off + 9 > len(inner):
                    break
                iop = inner[inner_off]
                (ilen,) = struct.unpack_from("<Q", inner, inner_off + 1)
                inner_off += 9
                if iop == 0x05 and ilen >= 22:
                    msgs.append(inner[inner_off + 22 : inner_off + ilen])
                inner_off += ilen
    return msgs


class TestRotateRoundTrip:
    def test_rotate_rsa_to_rsa(self, rsa_key_pair, rsa_key_pair_b, test_mcap_bytes):
        pub_a, priv_a = rsa_key_pair
        pub_b, priv_b = rsa_key_pair_b

        encrypted_a = encrypt_mcap(test_mcap_bytes, pub_a)
        rotated = rotate_mcap_keys(encrypted_a, priv_a, pub_b)

        # New key can decrypt.
        decrypted = decrypt_mcap(rotated, priv_b)
        original_msgs = _extract_message_data(test_mcap_bytes)
        rotated_msgs = _extract_message_data(decrypted)
        assert rotated_msgs == original_msgs

    def test_rotate_x25519_to_x25519(self, x25519_key_pair, x25519_key_pair_b, test_mcap_bytes):
        pub_a, priv_a = x25519_key_pair
        pub_b, priv_b = x25519_key_pair_b

        encrypted_a = encrypt_mcap(test_mcap_bytes, pub_a)
        rotated = rotate_mcap_keys(encrypted_a, priv_a, pub_b)

        decrypted = decrypt_mcap(rotated, priv_b)
        original_msgs = _extract_message_data(test_mcap_bytes)
        assert _extract_message_data(decrypted) == original_msgs

    def test_rotate_rsa_to_x25519(self, rsa_key_pair, x25519_key_pair, test_mcap_bytes):
        rsa_pub, rsa_priv = rsa_key_pair
        x25519_pub, x25519_priv = x25519_key_pair

        encrypted = encrypt_mcap(test_mcap_bytes, rsa_pub)
        rotated = rotate_mcap_keys(encrypted, rsa_priv, x25519_pub)

        decrypted = decrypt_mcap(rotated, x25519_priv)
        original_msgs = _extract_message_data(test_mcap_bytes)
        assert _extract_message_data(decrypted) == original_msgs

    def test_rotate_multi_recipient(
        self, rsa_key_pair, rsa_key_pair_b, x25519_key_pair, test_mcap_bytes
    ):
        pub_a, priv_a = rsa_key_pair
        pub_b, _ = rsa_key_pair_b
        x25519_pub, x25519_priv = x25519_key_pair

        encrypted = encrypt_mcap(test_mcap_bytes, pub_a)
        rotated = rotate_mcap_keys(encrypted, priv_a, [pub_b, x25519_pub])

        # Both new recipients can decrypt.
        original_msgs = _extract_message_data(test_mcap_bytes)
        for priv in (rsa_key_pair_b[1], x25519_priv):
            msgs = _extract_message_data(decrypt_mcap(rotated, priv))
            assert msgs == original_msgs

    def test_rotate_preserves_is_encrypted(self, rsa_key_pair, rsa_key_pair_b, test_mcap_bytes):
        pub_a, priv_a = rsa_key_pair
        pub_b, _ = rsa_key_pair_b
        encrypted = encrypt_mcap(test_mcap_bytes, pub_a)
        rotated = rotate_mcap_keys(encrypted, priv_a, pub_b)
        result = inspect_mcap(rotated)
        assert result.is_encrypted is True

    def test_rotate_preserves_chunk_count(self, rsa_key_pair, rsa_key_pair_b, test_mcap_bytes):
        pub_a, priv_a = rsa_key_pair
        pub_b, _ = rsa_key_pair_b
        encrypted = encrypt_mcap(test_mcap_bytes, pub_a)
        rotated = rotate_mcap_keys(encrypted, priv_a, pub_b)
        result_orig = inspect_mcap(encrypted)
        result_rotated = inspect_mcap(rotated)
        assert result_rotated.chunk_count == result_orig.chunk_count
        assert result_rotated.encrypted_chunk_count == result_orig.encrypted_chunk_count


class TestRotateNegative:
    def test_old_key_rejected_after_rotation(
        self, rsa_key_pair, rsa_key_pair_b, test_mcap_bytes
    ):
        pub_a, priv_a = rsa_key_pair
        pub_b, _ = rsa_key_pair_b

        encrypted = encrypt_mcap(test_mcap_bytes, pub_a)
        rotated = rotate_mcap_keys(encrypted, priv_a, pub_b)

        # Old key must fail.
        with pytest.raises((ValueError, Exception)):
            decrypt_mcap(rotated, priv_a)

    def test_wrong_old_key_rejected(self, rsa_key_pair, rsa_key_pair_b, test_mcap_bytes):
        pub_a, priv_a = rsa_key_pair
        pub_b, priv_b = rsa_key_pair_b

        encrypted = encrypt_mcap(test_mcap_bytes, pub_a)
        with pytest.raises(ValueError):
            rotate_mcap_keys(encrypted, priv_b, pub_a)

    def test_empty_new_keys_rejected(self, rsa_key_pair, test_mcap_bytes):
        pub, priv = rsa_key_pair
        encrypted = encrypt_mcap(test_mcap_bytes, pub)
        with pytest.raises(ValueError, match="at least one new public key"):
            rotate_mcap_keys(encrypted, priv, [])
