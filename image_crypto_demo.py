from preprocess import load_image, to_bytes, from_bytes, resize_image, save_image
from crypto import encrypt_with_password, decrypt_with_password

# ==================== Config ====================
IMAGE_PATH = "sample_images/test image.jpg"
RESIZED_PATH = "sample_images/resized.jpg"
REBUILT_PATH = "sample_images/rebuilt_encrypted.jpg"
PASSWORD = "strongpassword"
RESIZE_DIM = (300, 300)

# ==================== Step 1: Load and resize ====================
img = load_image(IMAGE_PATH)
resized = resize_image(img, *RESIZE_DIM)
save_image(resized, RESIZED_PATH)
print(f"Resized image saved as {RESIZED_PATH}")

# ==================== Step 2: Convert to bytes ====================
byte_data, size, mode = to_bytes(resized)
print(f"Image converted to bytes, size={len(byte_data)} bytes, mode={mode}")

# ==================== Step 3: Encrypt bytes ====================
package = encrypt_with_password(PASSWORD, byte_data)
print(f"Encrypted image bytes, total package length={len(package)}")

# ==================== Step 4: Decrypt bytes ====================
decrypted_bytes = decrypt_with_password(PASSWORD, package)
print(f"Decrypted bytes length={len(decrypted_bytes)}")

# ==================== Step 5: Rebuild image ====================
rebuilt_img = from_bytes(decrypted_bytes, size, mode)
save_image(rebuilt_img, REBUILT_PATH)
print(f"Rebuilt image saved as {REBUILT_PATH}")
