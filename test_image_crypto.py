import pytest
from pathlib import Path
from preprocess import load_image, resize_image, to_bytes, from_bytes
from crypto import encrypt_with_password, decrypt_with_password

SAMPLE_IMAGE = Path("sample_images/test image.jpg")
RESIZE_DIM = (100, 100)  # smaller size for test
PASSWORD_CORRECT = "correct-pass"
PASSWORD_WRONG = "wrong-pass"

def test_image_encrypt_decrypt_roundtrip(tmp_path):
    """
    Full end-to-end test:
    load -> resize -> to bytes -> encrypt -> decrypt -> rebuild image
    """
    # Step 1: Load and resize
    img = load_image(SAMPLE_IMAGE)
    resized = resize_image(img, *RESIZE_DIM)

    # Step 2: Convert to bytes
    byte_data, size, mode = to_bytes(resized)

    # Step 3: Encrypt using user-provided password
    package = encrypt_with_password(PASSWORD_CORRECT, byte_data)
    assert len(package) > 0

    # Step 4: Decrypt with correct password
    decrypted_bytes = decrypt_with_password(PASSWORD_CORRECT, package)
    assert decrypted_bytes == byte_data  # decrypted bytes match original bytes

    # Step 5: Rebuild image and save to temp path
    rebuilt_img = from_bytes(decrypted_bytes, size, mode)
    rebuilt_path = tmp_path / "rebuilt_test_image.jpg"
    rebuilt_img.save(rebuilt_path)
    assert rebuilt_path.exists()

def test_image_decrypt_wrong_password_fails(tmp_path):
    """
    Decryption with wrong password must fail with ValueError (HMAC mismatch)
    """
    img = load_image(SAMPLE_IMAGE)
    resized = resize_image(img, *RESIZE_DIM)
    byte_data, size, mode = to_bytes(resized)
    package = encrypt_with_password(PASSWORD_CORRECT, byte_data)

    with pytest.raises(ValueError):
        _ = decrypt_with_password(PASSWORD_WRONG, package)
