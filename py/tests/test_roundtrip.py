"""Round-trip encrypt -> decrypt tests."""
from __future__ import annotations

import pytest

from mcap_encrypt import (
    decrypt_mcap,
    encrypt_mcap,
    generate_key_pair,
    generate_x25519_key_pair,
)
from mcap_encrypt._records import (
    MCAP_MAGIC,
    iter_records,
)


def _extract_messages(mcap_bytes: bytes) -> list[bytes]:
    """Extract raw message data bytes from a plain MCAP."""
    msgs = []
    for opcode, payload in iter_records(mcap_bytes, start=8):
        if opcode == 0x06:  # Chunk
            # Parse chunk to get inner records.
            import struct
            off = 28  # skip 3*u64 + u32
            # compression string
            (clen,) = struct.unpack_from("<I", payload, off)
            off += 4 + clen
            # records_size
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
                if iop == 0x05:  # Message
                    msg_payload = inner[inner_off : inner_off + ilen]
                    msgs.append(msg_payload[22:])  # skip header fields
                inner_off += ilen
    return msgs


class TestRSARoundTrip:
    def test_rsa_round_trip(self, rsa_key_pair, test_mcap_bytes):
        pub, priv = rsa_key_pair
        encrypted = encrypt_mcap(test_mcap_bytes, pub)

        assert encrypted[:8] == MCAP_MAGIC
        assert encrypted[-8:] == MCAP_MAGIC
        assert b"EncryptedChunk" not in encrypted  # sanity

        decrypted = decrypt_mcap(encrypted, priv)

        assert decrypted[:8] == MCAP_MAGIC
        original_msgs = _extract_messages(test_mcap_bytes)
        decrypted_msgs = _extract_messages(decrypted)
        assert len(decrypted_msgs) == len(original_msgs)
        for orig, dec in zip(original_msgs, decrypted_msgs):
            assert orig == dec

    def test_rsa_encrypted_output_contains_encrypted_chunk(self, rsa_key_pair, test_mcap_bytes):
        pub, priv = rsa_key_pair
        encrypted = encrypt_mcap(test_mcap_bytes, pub)
        # Verify opcode 0x81 present
        found = any(op == 0x81 for op, _ in iter_records(encrypted, start=8))
        assert found, "expected EncryptedChunk (0x81) record in output"


class TestX25519RoundTrip:
    def test_x25519_round_trip(self, x25519_key_pair, test_mcap_bytes):
        pub, priv = x25519_key_pair
        encrypted = encrypt_mcap(test_mcap_bytes, pub)
        decrypted = decrypt_mcap(encrypted, priv)

        original_msgs = _extract_messages(test_mcap_bytes)
        decrypted_msgs = _extract_messages(decrypted)
        assert len(decrypted_msgs) == len(original_msgs)
        for orig, dec in zip(original_msgs, decrypted_msgs):
            assert orig == dec


class TestMultiRecipient:
    def test_multi_recipient(self, rsa_key_pair, x25519_key_pair, test_mcap_bytes):
        rsa_pub, rsa_priv = rsa_key_pair
        x25519_pub, x25519_priv = x25519_key_pair
        encrypted = encrypt_mcap(test_mcap_bytes, [rsa_pub, x25519_pub])

        # Both recipients can decrypt.
        dec_rsa = decrypt_mcap(encrypted, rsa_priv)
        dec_x25519 = decrypt_mcap(encrypted, x25519_priv)

        orig_msgs = _extract_messages(test_mcap_bytes)
        for dec in (dec_rsa, dec_x25519):
            msgs = _extract_messages(dec)
            assert len(msgs) == len(orig_msgs)
            for o, d in zip(orig_msgs, msgs):
                assert o == d

    def test_multi_recipient_two_rsa(self, rsa_key_pair, rsa_key_pair_b, test_mcap_bytes):
        pub_a, priv_a = rsa_key_pair
        pub_b, priv_b = rsa_key_pair_b
        encrypted = encrypt_mcap(test_mcap_bytes, [pub_a, pub_b])

        orig_msgs = _extract_messages(test_mcap_bytes)
        for priv in (priv_a, priv_b):
            msgs = _extract_messages(decrypt_mcap(encrypted, priv))
            assert msgs == orig_msgs


class TestNegative:
    def test_wrong_key_rejected(self, rsa_key_pair, test_mcap_bytes):
        pub, _ = rsa_key_pair
        _, wrong_priv = generate_key_pair()  # different key pair
        encrypted = encrypt_mcap(test_mcap_bytes, pub)
        with pytest.raises((ValueError, Exception)):
            decrypt_mcap(encrypted, wrong_priv)

    def test_wrong_x25519_key_rejected(self, x25519_key_pair, test_mcap_bytes):
        pub, _ = x25519_key_pair
        _, wrong_priv = generate_x25519_key_pair()
        encrypted = encrypt_mcap(test_mcap_bytes, pub)
        with pytest.raises((ValueError, Exception)):
            decrypt_mcap(encrypted, wrong_priv)

    def test_already_encrypted_rejected(self, rsa_key_pair, test_mcap_bytes):
        pub, priv = rsa_key_pair
        encrypted = encrypt_mcap(test_mcap_bytes, pub)
        with pytest.raises(ValueError, match="already encrypted"):
            encrypt_mcap(encrypted, pub)

    def test_plain_mcap_rejected_for_decrypt(self, rsa_key_pair, test_mcap_bytes):
        _, priv = rsa_key_pair
        with pytest.raises(ValueError, match="no wrapped key attachment found|not.*encrypted"):
            decrypt_mcap(test_mcap_bytes, priv)

    def test_empty_public_keys_rejected(self, test_mcap_bytes):
        with pytest.raises(ValueError, match="at least one public key"):
            encrypt_mcap(test_mcap_bytes, [])

    def test_unchunked_mcap_rejected(self, rsa_key_pair):
        """An unchunked MCAP with no Chunk records should be rejected."""
        import struct

        def _rec(opcode: int, payload: bytes) -> bytes:
            return struct.pack("<BQ", opcode, len(payload)) + payload

        buf = bytearray(b"\x89MCAP0\r\n")
        # Header: profile="test", library=""
        hdr = struct.pack("<I", 4) + b"test" + struct.pack("<I", 0)
        buf += _rec(0x01, hdr)
        # DataEnd: data_section_crc = 0
        buf += _rec(0x0F, struct.pack("<I", 0))
        # Footer: summary_start=0, summary_offset_start=0, summary_crc=0
        buf += _rec(0x02, struct.pack("<QQI", 0, 0, 0))
        buf += b"\x89MCAP0\r\n"

        pub, _ = rsa_key_pair
        with pytest.raises(ValueError, match="[Cc]hunk"):
            encrypt_mcap(bytes(buf), pub)
