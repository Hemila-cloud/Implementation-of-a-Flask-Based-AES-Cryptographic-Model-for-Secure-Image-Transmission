import getpass
from pathlib import Path
from preprocess import load_image, resize_image, to_bytes, from_bytes, save_image
from crypto import encrypt_with_password, decrypt_with_password

# ==================== Config ====================
IMAGE_PATH = Path("sample_images/test image.jpg")
RESIZED_PATH = Path("sample_images/resized.jpg")
REBUILT_PATH = Path("sample_images/rebuilt_decrypted.jpg")
ENCRYPTED_FILE = Path("sample_images/encrypted_image.bin")
RESIZE_DIM = (300, 300)

# ==================== Step 0: Get user password ====================
password = getpass.getpass("Enter encryption password: ")

# ==================== Step 1: Load and resize ====================
img = load_image(IMAGE_PATH)
resized = resize_image(img, *RESIZE_DIM)
save_image(resized, RESIZED_PATH)
print(f"Resized image saved as {RESIZED_PATH}")

# ==================== Step 2: Convert to bytes ====================
byte_data, size, mode = to_bytes(resized)
print(f"Image converted to bytes, length={len(byte_data)}, mode={mode}")

# ==================== Step 3: Encrypt bytes ====================
package = encrypt_with_password(password, byte_data)
ENCRYPTED_FILE.write_bytes(package)
print(f"Encrypted package saved as {ENCRYPTED_FILE}")

# ==================== Step 4: Decrypt bytes ====================
password2 = getpass.getpass("Enter password to decrypt image: ")
package_from_file = ENCRYPTED_FILE.read_bytes()
decrypted_bytes = decrypt_with_password(password2, package_from_file)
print(f"Decrypted bytes length={len(decrypted_bytes)}")

# ==================== Step 5: Rebuild image ====================
rebuilt_img = from_bytes(decrypted_bytes, size, mode)
save_image(rebuilt_img, REBUILT_PATH)
print(f"Rebuilt image saved as {REBUILT_PATH}")
