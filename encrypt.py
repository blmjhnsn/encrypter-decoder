#!/usr/bin/env python3
"""Command-line interface for classical ciphers and AES-256-GCM file encryption."""

from __future__ import annotations

import argparse
import getpass
import sys
from pathlib import Path

from crypto_tool.ciphers import (
    brute_force_caesar,
    caesar_decrypt,
    caesar_encrypt,
    vigenere_decrypt,
    vigenere_encrypt,
)
from crypto_tool.file_crypto import (
    AuthenticationError,
    CryptoToolError,
    decrypt_file,
    encrypt_file,
)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Learn classical ciphers and encrypt files with AES-256-GCM."
    )
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("-e", "--encrypt", action="store_true", help="encrypt input")
    action.add_argument("-d", "--decrypt", action="store_true", help="decrypt input")
    action.add_argument(
        "--crack-caesar",
        action="store_true",
        help="print all 26 possible Caesar plaintexts",
    )
    parser.add_argument(
        "--cipher",
        choices=("aes", "caesar", "vigenere"),
        default="aes",
        help="cipher to use (default: aes)",
    )
    parser.add_argument("-f", "--file", type=Path, help="input file for AES mode")
    parser.add_argument("-o", "--output", type=Path, help="output file or text file")
    parser.add_argument("--text", help="text input for classical cipher modes")
    parser.add_argument(
        "-k",
        "--key",
        help="Caesar shift or Vigenère key for classical ciphers",
    )
    parser.add_argument(
        "-p",
        "--password",
        help="AES password (prefer the hidden prompt when possible)",
    )
    parser.add_argument(
        "--chunk-size",
        type=int,
        default=1024 * 1024,
        help="AES file chunk size in bytes (default: 1048576)",
    )
    return parser


def _password_from_args(args: argparse.Namespace) -> str:
    if args.password is not None:
        return args.password
    return getpass.getpass("Password: ")


def _classical_text(args: argparse.Namespace, parser: argparse.ArgumentParser) -> str:
    if args.text is None:
        parser.error("--text is required for classical ciphers")
    if args.file is not None:
        parser.error("--file is only used with AES mode")
    return args.text


def _run_classical(args: argparse.Namespace, parser: argparse.ArgumentParser) -> str:
    text = _classical_text(args, parser)
    if args.crack_caesar:
        if args.cipher != "aes" and args.cipher != "caesar":
            parser.error("--crack-caesar cannot be combined with --cipher vigenere")
        return "\n".join(
            f"shift {shift:2}: {plaintext}"
            for shift, plaintext in brute_force_caesar(text)
        )

    if args.cipher == "aes":
        parser.error("--cipher caesar or --cipher vigenere is required for text mode")
    if args.key is None:
        parser.error("--key is required for classical ciphers")

    if args.cipher == "caesar":
        try:
            shift = int(args.key)
        except ValueError as error:
            parser.error("Caesar --key must be an integer shift")
            raise AssertionError("argparse.error exits") from error
        result = caesar_encrypt(text, shift) if args.encrypt else caesar_decrypt(text, shift)
    else:
        result = (
            vigenere_encrypt(text, args.key)
            if args.encrypt
            else vigenere_decrypt(text, args.key)
        )

    if args.output is not None:
        args.output.write_text(result, encoding="utf-8")
        return f"Wrote {args.output}"
    return result


def _default_output(input_path: Path, decrypting: bool) -> Path:
    if decrypting and input_path.suffix == ".enc":
        return input_path.with_suffix("")
    return input_path.with_name(f"{input_path.name}.dec" if decrypting else f"{input_path.name}.enc")


def _run_aes(args: argparse.Namespace, parser: argparse.ArgumentParser) -> str:
    if args.text is not None or args.key is not None:
        parser.error("--text and --key are only used with classical ciphers")
    if args.file is None:
        parser.error("--file is required for AES mode")
    if not args.file.is_file():
        parser.error(f"input file does not exist: {args.file}")
    output = args.output or _default_output(args.file, args.decrypt)
    password = _password_from_args(args)
    if args.encrypt:
        encrypt_file(args.file, output, password, chunk_size=args.chunk_size)
        return f"Encrypted {args.file} -> {output}"
    decrypt_file(args.file, output, password)
    return f"Decrypted {args.file} -> {output}"


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    try:
        if args.crack_caesar or args.cipher != "aes":
            print(_run_classical(args, parser))
        else:
            print(_run_aes(args, parser))
    except (AuthenticationError, CryptoToolError, OSError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())