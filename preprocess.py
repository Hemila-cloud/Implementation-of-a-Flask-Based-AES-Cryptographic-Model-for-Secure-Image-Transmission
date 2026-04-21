from PIL import Image
import os, base64
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

# ================= Helper Functions =================
def load_image(path):
    """Load an image from disk."""
    return Image.open(path)

def to_bytes(img):
    """Convert PIL Image to raw bytes + size + mode."""
    return img.tobytes(), img.size, img.mode

def from_bytes(byte_data, size, mode):
    """Rebuild a PIL Image from raw bytes."""
    return Image.frombytes(mode, size, byte_data)

def save_image(img, path):
    """Save an image to disk."""
    img.save(path)

def derive_key(password, salt):
    if isinstance(password, str):
        password = password.encode()
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password)


def generate_iv(size=16):
    """Generate a secure random IV."""
    return os.urandom(size)

# ===== Image Preprocessing Utilities =====
def resize_image(img, width, height):
    """Resize an image to the specified width/height using high-quality resampling."""
    return img.resize((width, height), Image.Resampling.LANCZOS)

def save_compressed(img, path, quality=85):
    """Save an image in JPEG format with compression."""
    img.save(path, format="JPEG", quality=quality, optimize=True)

# ================= Main Runner =================
if __name__ == "__main__":
    # Step 1: Load original image
    img = load_image("sample_images/test image.jpg")   # make sure input.jpg exists       
    print("Original size:", img.size)

    # Step 2: Resize (example: 300x300)
    resized_img = resize_image(img, 300, 300)
    save_image(resized_img, "resized.jpg")
    print("Resized image saved as resized.jpg")

    # Step 3: Save compressed (quality=60)
    save_compressed(resized_img, "compressed.jpg", quality=60)
    print("Compressed image saved as compressed.jpg")

    # Step 4: Convert to bytes + back
    byte_data, size, mode = to_bytes(resized_img)
    rebuilt_img = from_bytes(byte_data, size, mode)
    save_image(rebuilt_img, "rebuilt.jpg")
    print("Rebuilt image saved as rebuilt.jpg")

    # Step 5: Derive key + IV
    salt = os.urandom(16)
    key = derive_key("mypassword123", salt)
    iv = generate_iv()
    print("AES key length:", len(key))
    print("IV (hex):", iv.hex())
