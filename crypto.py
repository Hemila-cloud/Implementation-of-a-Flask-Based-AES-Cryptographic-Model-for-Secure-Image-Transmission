import os
import hmac
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

# ===== PKCS#7 padding =====
def pad(data: bytes, block_size: int = 16) -> bytes:
    if block_size <= 0 or block_size > 255:
        raise ValueError("block_size must be between 1 and 255")
    pad_len = block_size - (len(data) % block_size)
    if pad_len == 0:
        pad_len = block_size
    return data + bytes([pad_len]) * pad_len

def unpad(data: bytes, block_size: int = 16) -> bytes:
    if not data or len(data) % block_size != 0:
        raise ValueError("Invalid padded data length")
    pad_len = data[-1]
    if pad_len <= 0 or pad_len > block_size:
        raise ValueError("Invalid padding length")
    if data[-pad_len:] != bytes([pad_len]) * pad_len:
        raise ValueError("Invalid PKCS#7 padding bytes")
    return data[:-pad_len]

# ===== AES-CBC encrypt/decrypt =====
def encrypt_bytes(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    if not isinstance(plaintext, (bytes, bytearray)):
        raise TypeError("plaintext must be bytes")
    if len(iv) != 16:
        raise ValueError("iv must be 16 bytes")
    if len(key) not in (16, 24, 32):
        raise ValueError("key must be 16, 24, or 32 bytes long")

    padded = pad(plaintext, block_size=16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    return encryptor.update(padded) + encryptor.finalize()

def decrypt_bytes(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    if not isinstance(ciphertext, (bytes, bytearray)):
        raise TypeError("ciphertext must be bytes")
    if len(iv) != 16:
        raise ValueError("iv must be 16 bytes")
    if len(key) not in (16, 24, 32):
        raise ValueError("key must be 16, 24, or 32 bytes long")
    if len(ciphertext) % 16 != 0:
        raise ValueError("ciphertext length must be a multiple of 16 bytes")

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()
    return unpad(padded, block_size=16)

# ===== Convenience wrappers with HMAC =====
SALT_LEN = 16
IV_LEN = 16
HMAC_LEN = 32  # sha256 digest size

def _derive_keys(password: str, salt: bytes, key_len=32):
    """Derive separate keys for encryption and HMAC from password+salt."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=key_len * 2,  # encryption + hmac key
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    fullkey = kdf.derive(password.encode())
    return fullkey[:key_len], fullkey[key_len:]  # (enc_key, hmac_key)

def encrypt_with_password(password: str, plaintext: bytes) -> bytes:
    """
    Derive encryption+HMAC keys from password+salt, encrypt plaintext,
    and return package = salt||iv||hmac||ciphertext.
    """
    salt = os.urandom(SALT_LEN)
    enc_key, mac_key = _derive_keys(password, salt)
    iv = os.urandom(IV_LEN)
    ciphertext = encrypt_bytes(enc_key, iv, plaintext)
    mac = hmac.new(mac_key, iv + ciphertext, hashlib.sha256).digest()
    return salt + iv + mac + ciphertext

def decrypt_with_password(password: str, package: bytes) -> bytes:
    """
    Reverse encrypt_with_password.
    Raises ValueError on HMAC mismatch or decryption errors.
    """
    if len(package) < SALT_LEN + IV_LEN + HMAC_LEN + 16:
        raise ValueError("package too short")
    salt = package[:SALT_LEN]
    iv = package[SALT_LEN:SALT_LEN + IV_LEN]
    mac = package[SALT_LEN + IV_LEN:SALT_LEN + IV_LEN + HMAC_LEN]
    ciphertext = package[SALT_LEN + IV_LEN + HMAC_LEN:]

    enc_key, mac_key = _derive_keys(password, salt)

    expected_mac = hmac.new(mac_key, iv + ciphertext, hashlib.sha256).digest()
    if not hmac.compare_digest(mac, expected_mac):
        raise ValueError("HMAC verification failed or data tampered")

    return decrypt_bytes(enc_key, iv, ciphertext)
