import os
import pytest
from crypto import (
    pad, unpad,
    encrypt_bytes, decrypt_bytes,
    encrypt_with_password, decrypt_with_password,
    SALT_LEN, IV_LEN, HMAC_LEN
)

def test_pad_unpad_roundtrip():
    examples = [b"", b"a", b"1234567890abcdef", b"hello world!!"]
    for ex in examples:
        padded = pad(ex, block_size=16)
        assert len(padded) % 16 == 0
        unp = unpad(padded, block_size=16)
        assert unp == ex

    bad = pad(b"abc", 16)
    tampered = bad[:-1] + bytes([bad[-1] ^ 0xFF])
    with pytest.raises(ValueError):
        unpad(tampered, 16)

def test_encrypt_decrypt_bytes_roundtrip():
    plaintext = b"The quick brown fox jumps over the lazy dog"
    key = os.urandom(32)
    iv = os.urandom(IV_LEN)
    ciphertext = encrypt_bytes(key, iv, plaintext)
    decrypted = decrypt_bytes(key, iv, ciphertext)
    assert decrypted == plaintext

def test_encrypt_with_password_roundtrip():
    plaintext = b"My secret data"
    password = "mypassword123"
    package = encrypt_with_password(password, plaintext)
    # basic length checks
    assert package.startswith(package[:SALT_LEN])  # salt present
    assert len(package) > SALT_LEN + IV_LEN + HMAC_LEN
    # decrypt
    decrypted = decrypt_with_password(password, package)
    assert decrypted == plaintext

def test_wrong_password_fails():
    plaintext = b"secret-data"
    package = encrypt_with_password("correct-pass", plaintext)
    with pytest.raises(ValueError):
        _ = decrypt_with_password("wrong-pass", package)

def test_tampered_hmac_fails():
    plaintext = b"hello"
    package = encrypt_with_password("password", plaintext)
    tampered = bytearray(package)
    tampered[SALT_LEN + IV_LEN] ^= 0xFF  # flip one bit in hmac
    with pytest.raises(ValueError):
        _ = decrypt_with_password("password", bytes(tampered))

def test_tampered_ciphertext_fails():
    plaintext = b"hello"
    package = encrypt_with_password("password", plaintext)
    tampered = bytearray(package)
    tampered[-1] ^= 0xFF  # flip one byte in ciphertext
    with pytest.raises(ValueError):
        _ = decrypt_with_password("password", bytes(tampered))
