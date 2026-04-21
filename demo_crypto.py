# demo_crypto.py  (new small script just to test)
from crypto import encrypt_with_password, decrypt_with_password

data = b"My super secret message"
password = "strongpassword"

# Encrypt
package = encrypt_with_password(password, data)
print("Encrypted package (salt||iv||hmac||ciphertext):", package.hex())

# Decrypt
original = decrypt_with_password(password, package)
print("Decrypted back:", original)
