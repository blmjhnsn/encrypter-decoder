# Encrypter / Decoder

A learning-focused Python CLI that starts with breakable classical ciphers and
progresses to authenticated AES-256 file encryption. It can encrypt and decrypt
binary files such as images, PDFs, and text without loading the whole file into
memory.

## Features

- Caesar cipher: encrypt, decrypt, and print all 26 brute-force candidates.
- Vigenère cipher: encrypt and decrypt with a repeating alphabetic key.
- AES-256-GCM file encryption.
- PBKDF2-HMAC-SHA256 password derivation with a random 128-bit salt.
- Randomized, unique per-chunk nonces and authenticated metadata.
- Chunked I/O with atomic output publishing.
- Tests for round trips, wrong passwords, tampering, truncation, empty files,
  and multi-chunk files.

The classical ciphers are intentionally educational. They are not safe for
protecting secrets.

## Setup

Python 3.10+ is recommended.

```bash
cd encrypter-decoder
python -m venv .venv
source .venv/bin/activate       # Windows: .venv\Scripts\activate
python -m pip install -r requirements.txt
```

## Usage

### Caesar

```bash
python encrypt.py -e --cipher caesar --text "Attack at dawn!" -k 3
python encrypt.py -d --cipher caesar --text "Dwwdfn dw gdzq!" -k 3
python encrypt.py --crack-caesar --text "Dwwdfn dw gdzq!"
```

`--crack-caesar` prints every possible shift. It does not pretend to identify
the correct English sentence automatically; a human or a future scoring
function can inspect the candidates.

### Vigenère

```bash
python encrypt.py -e --cipher vigenere --text "Attack at dawn!" -k LEMON
python encrypt.py -d --cipher vigenere --text "Lxfopv ef rnhr!" -k LEMON
```

### AES-256-GCM file mode

```bash
# -p is convenient for demos, but exposes a password in shell history/process listings.
python encrypt.py -e -f report.pdf -p "a long password"

# Without -p, the tool prompts without echoing the password.
python encrypt.py -e -f report.pdf

# The first command writes report.pdf.enc by default.
python encrypt.py -d -f report.pdf.enc
```

Use `-o/--output` to select an explicit destination:

```bash
python encrypt.py -e -f photo.jpg -o photo.jpg.enc
python encrypt.py -d -f photo.jpg.enc -o photo-restored.jpg
```

The CLI exits with a non-zero status for missing inputs, malformed encrypted
files, wrong passwords, authentication failures, or invalid arguments.

## Encrypted file format

Each file begins with a fixed header:

```text
magic (ENC1) | version | random salt | random nonce prefix | chunk size
```

The password is converted into a 32-byte AES-256 key with
PBKDF2-HMAC-SHA256 and 600,000 iterations. Every plaintext chunk is encrypted
with AES-GCM and receives a 16-byte authentication tag. A nonce is the
4-byte random prefix followed by an 8-byte counter, so nonces do not repeat
within a file. The header is passed as AES-GCM associated data, which detects
tampering with the metadata too.

Decryption writes to a temporary file and only replaces the requested output
after every chunk authenticates. A wrong password or modified ciphertext never
publishes partially decrypted plaintext.

## Security choices and threat model

### Why AES-256-GCM?

AES is a widely reviewed symmetric block cipher. A 256-bit key provides a
large security margin against brute-force key search. GCM supplies both
confidentiality and integrity, so the tool detects modified ciphertext instead
of silently returning altered bytes. The implementation uses the
`cryptography` library's vetted AES-GCM primitive rather than implementing AES
itself.

Fernet is a good beginner-friendly API, but its standard construction uses
AES-128-CBC with HMAC. This project uses AES-GCM directly so the AES-256 and
authenticated-encryption choices are explicit and visible.

### Why salt and derive the key?

A human password is not a uniformly random 256-bit key. PBKDF2 turns it into a
key suitable for AES while making password guessing more expensive. A fresh
random salt ensures that the same password produces different keys for
different files and prevents reuse of precomputed password guesses. The salt
is stored in the header because it is not secret.

### Assumed threat model

This tool protects file contents from someone who obtains the encrypted file
but does not know the password. It also detects accidental corruption and
active modification of the encrypted bytes and metadata.

It does **not** protect against:

- a weak or reused password;
- malware, keyloggers, or an attacker who can read the password;
- plaintext already exposed in backups, editors, swap, or temporary files;
- traffic analysis such as file size and timing;
- future cryptanalytic advances or a compromised Python environment.

For high-value production data, use a maintained, reviewed storage encryption
product with key management, password policy, recovery procedures, and
security review. This project is an educational utility, not a replacement
for one.

## Tests

```bash
pytest -q
```

## Resume-ready summary

> Built a Python CLI utility implementing AES-256-GCM file encryption with
> PBKDF2 key derivation, per-file salting, per-chunk nonce management, atomic
> output handling, and automated tests for correctness, tampering, and wrong
> passwords.