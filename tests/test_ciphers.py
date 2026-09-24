import pytest

from crypto_tool.ciphers import (
    brute_force_caesar,
    caesar_decrypt,
    caesar_encrypt,
    vigenere_decrypt,
    vigenere_encrypt,
)


def test_caesar_round_trip_preserves_case_and_punctuation():
    plaintext = "Attack at dawn! 123"
    ciphertext = caesar_encrypt(plaintext, 3)

    assert ciphertext == "Dwwdfn dw gdzq! 123"
    assert caesar_decrypt(ciphertext, 3) == plaintext


def test_caesar_brute_force_contains_original_plaintext():
    plaintext = "meet me at the park"
    ciphertext = caesar_encrypt(plaintext, 7)

    candidates = dict(brute_force_caesar(ciphertext))

    assert candidates[7] == plaintext
    assert len(candidates) == 26


def test_vigenere_round_trip_ignores_non_letters_for_key_position():
    plaintext = "Attack at dawn!"
    ciphertext = vigenere_encrypt(plaintext, "LEMON")

    assert ciphertext == "Lxfopv ef rnhr!"
    assert vigenere_decrypt(ciphertext, "LEMON") == plaintext


def test_vigenere_rejects_empty_or_non_ascii_key():
    with pytest.raises(ValueError, match="at least one letter"):
        vigenere_encrypt("hello", "---")
    with pytest.raises(ValueError, match="ASCII"):
        vigenere_encrypt("hello", "é")