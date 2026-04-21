# test_app.py - Integration Tests
import pytest
import os
import io
from PIL import Image
from pathlib import Path

def test_flask_app_running(client):
    """Test that Flask app is running"""
    response = client.get('/')
    assert response.status_code == 200
    assert b"Secure Image Encryption" in response.data

def test_encryption_integration(client, tmp_path):
    """Test complete encryption flow"""
    # Create a test image
    img = Image.new('RGB', (100, 100), color='red')
    img_bytes = io.BytesIO()
    img.save(img_bytes, format='JPEG')
    img_bytes.seek(0)
    
    # Test encryption
    response = client.post('/encrypt', data={
        'file': (img_bytes, 'test_image.jpg'),
        'password': 'testpassword123'
    })
    
    assert response.status_code == 200
    assert 'encrypted' in response.headers.get('Content-Disposition', '')

def test_decryption_integration(client, tmp_path):
    """Test complete decryption flow"""
    # First encrypt an image
    img = Image.new('RGB', (100, 100), color='blue')
    img_bytes = io.BytesIO()
    img.save(img_bytes, format='JPEG')
    img_bytes.seek(0)
    
    # Encrypt
    from preprocess import to_bytes
    from crypto import encrypt_with_password
    
    byte_data, size, mode = to_bytes(img)
    encrypted_data = encrypt_with_password('testpassword123', byte_data)
    
    # Test decryption
    encrypted_bytes = io.BytesIO(encrypted_data)
    encrypted_bytes.seek(0)
    
    response = client.post('/decrypt', data={
        'file': (encrypted_bytes, 'test_encrypted.bin'),
        'password': 'testpassword123'
    })
    
    assert response.status_code == 200
    assert 'decrypted' in response.headers.get('Content-Disposition', '')

def test_wrong_password_fails(client):
    """Test that wrong password fails decryption"""
    img = Image.new('RGB', (100, 100), color='green')
    img_bytes = io.BytesIO()
    img.save(img_bytes, format='JPEG')
    img_bytes.seek(0)
    
    from preprocess import to_bytes
    from crypto import encrypt_with_password
    
    byte_data, size, mode = to_bytes(img)
    encrypted_data = encrypt_with_password('correctpassword', byte_data)
    
    encrypted_bytes = io.BytesIO(encrypted_data)
    encrypted_bytes.seek(0)
    
    response = client.post('/decrypt', data={
        'file': (encrypted_bytes, 'test_encrypted.bin'),
        'password': 'wrongpassword'
    })
    
    assert response.status_code == 302  # Redirect with error

def test_invalid_file_handling(client):
    """Test handling of invalid files"""
    # Test with non-image file
    text_file = io.BytesIO(b"This is not an image file")
    text_file.seek(0)
    
    response = client.post('/encrypt', data={
        'file': (text_file, 'test.txt'),
        'password': 'testpassword'
    })
    
    assert response.status_code == 302  # Should redirect with error

@pytest.fixture
def client():
    """Create test client"""
    from app import app
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client