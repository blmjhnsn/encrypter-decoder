from pathlib import Path

import pytest

from crypto_tool.file_crypto import (
    AuthenticationError,
    FileFormatError,
    decrypt_file,
    encrypt_file,
)


def test_empty_file_round_trip(tmp_path: Path):
    original = tmp_path / "empty.bin"
    encrypted = tmp_path / "empty.bin.enc"
    decrypted = tmp_path / "empty-restored.bin"
    original.write_bytes(b"")

    encrypt_file(original, encrypted, "correct horse battery staple", chunk_size=8)
    decrypt_file(encrypted, decrypted, "correct horse battery staple")

    assert decrypted.read_bytes() == b""
    assert encrypted.read_bytes().startswith(b"ENC1")


def test_large_file_round_trip_uses_multiple_chunks(tmp_path: Path):
    original = tmp_path / "large.bin"
    encrypted = tmp_path / "large.bin.enc"
    decrypted = tmp_path / "large-restored.bin"
    contents = bytes(range(256)) * 5000
    original.write_bytes(contents)

    encrypt_file(original, encrypted, "a strong password", chunk_size=257)
    decrypt_file(encrypted, decrypted, "a strong password")

    assert decrypted.read_bytes() == contents
    assert encrypted.read_bytes() != contents


def test_wrong_password_does_not_publish_plaintext(tmp_path: Path):
    original = tmp_path / "secret.txt"
    encrypted = tmp_path / "secret.txt.enc"
    decrypted = tmp_path / "should-not-exist.txt"
    original.write_text("private material", encoding="utf-8")
    encrypt_file(original, encrypted, "right password")

    with pytest.raises(AuthenticationError, match="wrong password"):
        decrypt_file(encrypted, decrypted, "wrong password")

    assert not decrypted.exists()


def test_corruption_is_rejected(tmp_path: Path):
    original = tmp_path / "secret.txt"
    encrypted = tmp_path / "secret.txt.enc"
    decrypted = tmp_path / "restored.txt"
    original.write_bytes(b"authenticated bytes")
    encrypt_file(original, encrypted, "password")
    damaged = bytearray(encrypted.read_bytes())
    damaged[-1] ^= 0x01
    encrypted.write_bytes(damaged)

    with pytest.raises(AuthenticationError):
        decrypt_file(encrypted, decrypted, "password")

    assert not decrypted.exists()


def test_truncated_header_is_rejected(tmp_path: Path):
    encrypted = tmp_path / "broken.enc"
    decrypted = tmp_path / "restored.bin"
    encrypted.write_bytes(b"ENC1")

    with pytest.raises(FileFormatError, match="incomplete header"):
        decrypt_file(encrypted, decrypted, "password")