"""Chunked AES-256-GCM file encryption with password-based key derivation.

The file format is intentionally small and documented in the project README:

    header = magic | version | salt | nonce prefix | chunk size
    repeated records = encrypted chunk length | AES-GCM ciphertext + tag

Every chunk gets a unique nonce made from the random nonce prefix and a
monotonically increasing counter. The header is authenticated as GCM
associated data so changes to the format metadata are detected.
"""

from __future__ import annotations

import os
import struct
import tempfile
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


MAGIC = b"ENC1"
VERSION = 1
SALT_SIZE = 16
NONCE_PREFIX_SIZE = 4
NONCE_COUNTER_SIZE = 8
NONCE_SIZE = NONCE_PREFIX_SIZE + NONCE_COUNTER_SIZE
TAG_SIZE = 16
DEFAULT_CHUNK_SIZE = 1024 * 1024
MAX_CHUNK_SIZE = 64 * 1024 * 1024
PBKDF2_ITERATIONS = 600_000
HEADER = struct.Struct(">4sB16s4sI")
RECORD_LENGTH = struct.Struct(">I")


class CryptoToolError(Exception):
    """Base class for expected user-facing errors."""


class FileFormatError(CryptoToolError):
    """Raised when an encrypted file is malformed or unsupported."""


class AuthenticationError(CryptoToolError):
    """Raised when a password cannot authenticate encrypted data."""


def _validate_chunk_size(chunk_size: int) -> None:
    if not 1 <= chunk_size <= MAX_CHUNK_SIZE:
        raise ValueError(f"chunk size must be between 1 and {MAX_CHUNK_SIZE} bytes")


def _derive_key(password: str, salt: bytes) -> bytes:
    if not password:
        raise ValueError("password must not be empty")

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    return kdf.derive(password.encode("utf-8"))


def _make_nonce(nonce_prefix: bytes, counter: int) -> bytes:
    if len(nonce_prefix) != NONCE_PREFIX_SIZE:
        raise ValueError("invalid nonce prefix")
    if not 0 <= counter < 2**64:
        raise ValueError("file contains too many chunks")
    return nonce_prefix + counter.to_bytes(NONCE_COUNTER_SIZE, "big")


def _write_atomically(
    output_path: Path,
    writer,
) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="wb",
            dir=output_path.parent,
            prefix=f".{output_path.name}.",
            suffix=".tmp",
            delete=False,
        ) as temporary:
            temporary_path = temporary.name
            writer(temporary)
            temporary.flush()
            os.fsync(temporary.fileno())
        os.replace(temporary_path, output_path)
        temporary_path = None
    finally:
        if temporary_path is not None:
            try:
                os.unlink(temporary_path)
            except FileNotFoundError:
                pass


def encrypt_file(
    input_path: str | os.PathLike[str],
    output_path: str | os.PathLike[str],
    password: str,
    *,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
) -> None:
    """Encrypt a file using AES-256-GCM and PBKDF2-HMAC-SHA256."""

    _validate_chunk_size(chunk_size)
    source = Path(input_path)
    destination = Path(output_path)
    if source.resolve() == destination.resolve():
        raise ValueError("input and output paths must be different")

    salt = os.urandom(SALT_SIZE)
    nonce_prefix = os.urandom(NONCE_PREFIX_SIZE)
    header = HEADER.pack(MAGIC, VERSION, salt, nonce_prefix, chunk_size)
    cipher = AESGCM(_derive_key(password, salt))

    def write_encrypted(destination_file) -> None:
        destination_file.write(header)
        with source.open("rb") as source_file:
            counter = 0
            while chunk := source_file.read(chunk_size):
                encrypted = cipher.encrypt(
                    _make_nonce(nonce_prefix, counter), chunk, header
                )
                destination_file.write(RECORD_LENGTH.pack(len(encrypted)))
                destination_file.write(encrypted)
                counter += 1

    _write_atomically(destination, write_encrypted)


def _read_exact(file_object, size: int) -> bytes:
    data = file_object.read(size)
    if len(data) != size:
        raise FileFormatError("encrypted file is truncated")
    return data


def decrypt_file(
    input_path: str | os.PathLike[str],
    output_path: str | os.PathLike[str],
    password: str,
) -> None:
    """Decrypt and authenticate an encrypted file.

    No output file is published until every chunk has authenticated.
    """

    source = Path(input_path)
    destination = Path(output_path)
    if source.resolve() == destination.resolve():
        raise ValueError("input and output paths must be different")

    with source.open("rb") as source_file:
        header_bytes = source_file.read(HEADER.size)
        if len(header_bytes) != HEADER.size:
            raise FileFormatError("encrypted file is missing or has an incomplete header")

        magic, version, salt, nonce_prefix, chunk_size = HEADER.unpack(header_bytes)
        if magic != MAGIC:
            raise FileFormatError("not an ENC1 encrypted file")
        if version != VERSION:
            raise FileFormatError(f"unsupported encrypted file version: {version}")
        try:
            _validate_chunk_size(chunk_size)
        except ValueError as error:
            raise FileFormatError("encrypted file contains an invalid chunk size") from error

        cipher = AESGCM(_derive_key(password, salt))

        def write_decrypted(destination_file) -> None:
            counter = 0
            while length_bytes := source_file.read(RECORD_LENGTH.size):
                if len(length_bytes) != RECORD_LENGTH.size:
                    raise FileFormatError("encrypted file has an incomplete chunk length")
                encrypted_length = RECORD_LENGTH.unpack(length_bytes)[0]
                if not TAG_SIZE <= encrypted_length <= chunk_size + TAG_SIZE:
                    raise FileFormatError("encrypted file contains an invalid chunk length")

                encrypted = _read_exact(source_file, encrypted_length)
                try:
                    plaintext = cipher.decrypt(
                        _make_nonce(nonce_prefix, counter), encrypted, header_bytes
                    )
                except InvalidTag as error:
                    raise AuthenticationError(
                        "wrong password or corrupted encrypted data"
                    ) from error
                destination_file.write(plaintext)
                counter += 1

        _write_atomically(destination, write_decrypted)