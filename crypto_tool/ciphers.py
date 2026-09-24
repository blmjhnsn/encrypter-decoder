"""Classical ciphers used for the learning portion of the project."""

from __future__ import annotations

import string


ALPHABET_SIZE = 26


def _shift_character(character: str, shift: int) -> str:
    if character in string.ascii_uppercase:
        alphabet_start = ord("A")
    elif character in string.ascii_lowercase:
        alphabet_start = ord("a")
    else:
        return character

    return chr((ord(character) - alphabet_start + shift) % ALPHABET_SIZE + alphabet_start)


def caesar_encrypt(text: str, shift: int) -> str:
    """Shift letters by ``shift`` places, preserving case and punctuation."""

    return "".join(_shift_character(character, shift) for character in text)


def caesar_decrypt(text: str, shift: int) -> str:
    """Reverse a Caesar shift."""

    return caesar_encrypt(text, -shift)


def brute_force_caesar(text: str) -> list[tuple[int, str]]:
    """Return every possible Caesar plaintext as ``(shift, plaintext)`` pairs."""

    return [(shift, caesar_decrypt(text, shift)) for shift in range(ALPHABET_SIZE)]


def _key_shifts(key: str) -> list[int]:
    shifts = [ord(character.upper()) - ord("A") for character in key if character.isalpha()]
    if not shifts:
        raise ValueError("Vigenère key must contain at least one letter")
    if any(shift < 0 or shift >= ALPHABET_SIZE for shift in shifts):
        raise ValueError("Vigenère key must contain ASCII letters only")
    return shifts


def _vigenere_transform(text: str, key: str, decrypt: bool) -> str:
    shifts = _key_shifts(key)
    output: list[str] = []
    key_index = 0

    for character in text:
        if character not in string.ascii_letters:
            output.append(character)
            continue

        shift = shifts[key_index % len(shifts)]
        output.append(_shift_character(character, -shift if decrypt else shift))
        key_index += 1

    return "".join(output)


def vigenere_encrypt(text: str, key: str) -> str:
    """Encrypt text with a Vigenère key, leaving non-letters unchanged."""

    return _vigenere_transform(text, key, decrypt=False)


def vigenere_decrypt(text: str, key: str) -> str:
    """Decrypt text with a Vigenère key, leaving non-letters unchanged."""

    return _vigenere_transform(text, key, decrypt=True)