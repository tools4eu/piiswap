"""Fernet-based encryption for the mapping database file."""

import base64
import os
from pathlib import Path

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


SALT_SIZE = 16
SALT_HEADER = b"PIISWAP-SALT:"


def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480_000,
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode("utf-8")))


def encrypt_file(source_path: Path, dest_path: Path, password: str) -> None:
    salt = os.urandom(SALT_SIZE)
    key = derive_key(password, salt)
    fernet = Fernet(key)

    plaintext = source_path.read_bytes()
    ciphertext = fernet.encrypt(plaintext)

    dest_path.write_bytes(SALT_HEADER + salt + b"\n" + ciphertext)


def decrypt_file(encrypted_path: Path, dest_path: Path, password: str) -> None:
    raw = encrypted_path.read_bytes()

    if not raw.startswith(SALT_HEADER):
        raise ValueError("Not a valid PiiSwap encrypted file.")

    newline_pos = raw.index(b"\n", len(SALT_HEADER))
    salt = raw[len(SALT_HEADER):newline_pos]
    ciphertext = raw[newline_pos + 1:]

    key = derive_key(password, salt)
    fernet = Fernet(key)

    plaintext = fernet.decrypt(ciphertext)
    dest_path.write_bytes(plaintext)


def is_encrypted(path: Path) -> bool:
    if not path.exists():
        return False
    with open(path, "rb") as f:
        header = f.read(len(SALT_HEADER))
    return header == SALT_HEADER
