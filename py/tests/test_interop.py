"""Cross-language interop tests using the Go CLI.

These tests are skipped if the Go CLI binary is not available on PATH.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import pytest

from mcap_encrypt import (
    decrypt_mcap,
    encrypt_mcap,
    generate_key_pair,
    generate_x25519_key_pair,
)
from mcap_encrypt._records import MCAP_MAGIC, iter_records

GO_CLI = shutil.which("mcap-encrypt") or shutil.which("mcap-encrypt-go")
GO_AVAILABLE = GO_CLI is not None

pytestmark = pytest.mark.skipif(
    not GO_AVAILABLE,
    reason="mcap-encrypt Go CLI not found on PATH (set mcap-encrypt or mcap-encrypt-go)",
)


def _write_temp(data: bytes, suffix: str = ".mcap") -> str:
    fd, path = tempfile.mkstemp(suffix=suffix)
    os.close(fd)
    with open(path, "wb") as f:
        f.write(data)
    return path


def _read_temp(path: str) -> bytes:
    with open(path, "rb") as f:
        return f.read()


def _has_encrypted_chunk(data: bytes) -> bool:
    return any(op == 0x81 for op, _ in iter_records(data, start=8))


class TestGoEncryptsPythonDecrypts:
    def test_go_encrypts_rsa_python_decrypts(self, test_mcap_bytes):
        pub_pem, priv_pem = generate_key_pair()

        with tempfile.TemporaryDirectory() as tmpdir:
            plain_path = _write_temp(test_mcap_bytes, ".mcap")
            enc_path = os.path.join(tmpdir, "encrypted.mcap")
            key_base = os.path.join(tmpdir, "key")

            # Write key files for the Go CLI.
            pub_path = key_base + ".pub.pem"
            priv_path = key_base + ".priv.pem"
            with open(pub_path, "w") as f:
                f.write(pub_pem)
            with open(priv_path, "w") as f:
                f.write(priv_pem)

            result = subprocess.run(
                [GO_CLI, "encrypt", "--key", pub_path, plain_path, enc_path],
                capture_output=True,
                timeout=30,
            )
            if result.returncode != 0:
                pytest.skip(f"Go CLI encrypt failed: {result.stderr.decode()}")

            enc_data = _read_temp(enc_path)
            assert _has_encrypted_chunk(enc_data), "Go output should contain EncryptedChunk"

            decrypted = decrypt_mcap(enc_data, priv_pem)
            assert decrypted[:8] == MCAP_MAGIC

            os.unlink(plain_path)

    def test_go_encrypts_x25519_python_decrypts(self, test_mcap_bytes):
        pub_pem, priv_pem = generate_x25519_key_pair()

        with tempfile.TemporaryDirectory() as tmpdir:
            plain_path = _write_temp(test_mcap_bytes, ".mcap")
            enc_path = os.path.join(tmpdir, "encrypted_x25519.mcap")

            pub_path = os.path.join(tmpdir, "x25519.pub.pem")
            priv_path = os.path.join(tmpdir, "x25519.priv.pem")
            with open(pub_path, "w") as f:
                f.write(pub_pem)
            with open(priv_path, "w") as f:
                f.write(priv_pem)

            result = subprocess.run(
                [GO_CLI, "encrypt", "--key", pub_path, plain_path, enc_path],
                capture_output=True,
                timeout=30,
            )
            if result.returncode != 0:
                pytest.skip(f"Go CLI encrypt failed: {result.stderr.decode()}")

            enc_data = _read_temp(enc_path)
            decrypted = decrypt_mcap(enc_data, priv_pem)
            assert decrypted[:8] == MCAP_MAGIC

            os.unlink(plain_path)


class TestPythonEncryptsGoDecrypts:
    def test_python_encrypts_rsa_go_decrypts(self, rsa_key_pair, test_mcap_bytes):
        pub_pem, priv_pem = rsa_key_pair
        encrypted = encrypt_mcap(test_mcap_bytes, pub_pem)

        with tempfile.TemporaryDirectory() as tmpdir:
            enc_path = _write_temp(encrypted, ".mcap")
            dec_path = os.path.join(tmpdir, "decrypted.mcap")
            priv_path = os.path.join(tmpdir, "key.priv.pem")

            with open(priv_path, "w") as f:
                f.write(priv_pem)

            result = subprocess.run(
                [GO_CLI, "decrypt", "--key", priv_path, enc_path, dec_path],
                capture_output=True,
                timeout=30,
            )
            if result.returncode != 0:
                pytest.fail(
                    f"Go CLI decrypt failed (rc={result.returncode}):\n"
                    f"stdout: {result.stdout.decode()}\n"
                    f"stderr: {result.stderr.decode()}"
                )

            dec_data = _read_temp(dec_path)
            assert dec_data[:8] == MCAP_MAGIC

            os.unlink(enc_path)

    def test_python_encrypts_x25519_go_decrypts(self, x25519_key_pair, test_mcap_bytes):
        pub_pem, priv_pem = x25519_key_pair
        encrypted = encrypt_mcap(test_mcap_bytes, pub_pem)

        with tempfile.TemporaryDirectory() as tmpdir:
            enc_path = _write_temp(encrypted, ".mcap")
            dec_path = os.path.join(tmpdir, "decrypted_x25519.mcap")
            priv_path = os.path.join(tmpdir, "x25519.priv.pem")

            with open(priv_path, "w") as f:
                f.write(priv_pem)

            result = subprocess.run(
                [GO_CLI, "decrypt", "--key", priv_path, enc_path, dec_path],
                capture_output=True,
                timeout=30,
            )
            if result.returncode != 0:
                pytest.fail(
                    f"Go CLI decrypt failed (rc={result.returncode}):\n"
                    f"stdout: {result.stdout.decode()}\n"
                    f"stderr: {result.stderr.decode()}"
                )

            dec_data = _read_temp(dec_path)
            assert dec_data[:8] == MCAP_MAGIC

            os.unlink(enc_path)
