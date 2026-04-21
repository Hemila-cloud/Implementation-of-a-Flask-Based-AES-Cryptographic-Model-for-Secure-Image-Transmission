# app.py - Enhanced Version with Metadata Handling
import os
import io
import sys
from flask import Flask, request, render_template, send_file, flash, redirect, url_for, jsonify
from preprocess import load_image, to_bytes, from_bytes, save_image
from crypto import encrypt_with_password, decrypt_with_password
from PIL import Image
import tempfile
from pathlib import Path

# Add current directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

app = Flask(__name__)
app.secret_key = "supersecretkey123"
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

def add_metadata_to_data(image_data, size, mode):
    """Add image metadata to the beginning of image data"""
    metadata = f"{size[0]},{size[1]},{mode}".encode('utf-8')
    metadata_length = len(metadata)
    # Format: [4 bytes: metadata length] + [metadata] + [image data]
    return metadata_length.to_bytes(4, 'big') + metadata + image_data

def extract_metadata_from_data(data):
    """Extract image metadata from the beginning of data"""
    metadata_length = int.from_bytes(data[:4], 'big')
    metadata = data[4:4+metadata_length].decode('utf-8')
    width, height, mode = metadata.split(',')
    image_data = data[4+metadata_length:]
    return image_data, (int(width), int(height)), mode

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/encrypt", methods=["POST"])
def encrypt_image():
    try:
        if 'file' not in request.files:
            flash("❌ No file selected")
            return redirect(url_for('index'))
        
        file = request.files['file']
        password = request.form.get('password', '').strip()
        
        if not file or file.filename == '':
            flash("❌ Please select a file")
            return redirect(url_for('index'))
        
        if not password:
            flash("❌ Password is required")
            return redirect(url_for('index'))
        
        # Validate image
        try:
            img = Image.open(file.stream)
            img.verify()  # Verify it's a valid image
            file.stream.seek(0)  # Reset stream
            img = Image.open(file.stream)  # Reopen for processing
        except Exception as e:
            flash("❌ Invalid image file")
            return redirect(url_for('index'))
        
        # Convert to bytes and get original dimensions
        byte_data, size, mode = to_bytes(img)
        print(f"Original image: size={size}, mode={mode}, data_length={len(byte_data)}")
        
        # Add metadata to image data before encryption
        data_with_metadata = add_metadata_to_data(byte_data, size, mode)
        
        # Encrypt the data WITH metadata
        encrypted_package = encrypt_with_password(password, data_with_metadata)
        
        # Create download
        filename = Path(file.filename).stem + "_encrypted.bin"
        temp_path = os.path.join(UPLOAD_FOLDER, filename)
        
        with open(temp_path, 'wb') as f:
            f.write(encrypted_package)
        
        flash("✅ Image encrypted successfully!")
        return send_file(temp_path, as_attachment=True, download_name=filename)
        
    except Exception as e:
        flash(f"❌ Encryption failed: {str(e)}")
        return redirect(url_for('index'))

@app.route("/decrypt", methods=["POST"])
def decrypt_image():
    try:
        if 'file' not in request.files:
            flash("❌ No file selected")
            return redirect(url_for('index'))
        
        file = request.files['file']
        password = request.form.get('password', '').strip()
        
        if not file or file.filename == '':
            flash("❌ Please select a file")
            return redirect(url_for('index'))
        
        if not password:
            flash("❌ Password is required")
            return redirect(url_for('index'))
        
        # Read encrypted file
        encrypted_data = file.read()
        
        if len(encrypted_data) == 0:
            flash("❌ Empty file")
            return redirect(url_for('index'))
        
        # Decrypt
        try:
            decrypted_data = decrypt_with_password(password, encrypted_data)
            print(f"Decrypted data length: {len(decrypted_data)}")
        except ValueError as e:
            flash("❌ Decryption failed: Wrong password or corrupted file")
            return redirect(url_for('index'))
        
        # Extract metadata and image data
        try:
            image_bytes, size, mode = extract_metadata_from_data(decrypted_data)
            print(f"Extracted metadata: size={size}, mode={mode}")
            
            # Rebuild image with correct dimensions
            rebuilt_img = from_bytes(image_bytes, size, mode)
            
        except Exception as e:
            print(f"Metadata extraction failed: {e}")
            flash("❌ Could not reconstruct image - metadata missing or corrupted")
            return redirect(url_for('index'))
        
        # Save and return
        filename = Path(file.filename).stem + "_decrypted.jpg"
        temp_path = os.path.join(UPLOAD_FOLDER, filename)
        save_image(rebuilt_img, temp_path)
        
        flash("✅ Image decrypted successfully!")
        return send_file(temp_path, as_attachment=True, download_name=filename)
        
    except Exception as e:
        flash(f"❌ Decryption failed: {str(e)}")
        return redirect(url_for('index'))

@app.route("/api/status")
def api_status():
    return jsonify({"status": "running", "message": "Image Crypto App is operational"})

if __name__ == "__main__":
    print("🚀 Starting Enhanced Image Encryption Application...")
    print("📝 Features: Metadata preservation for perfect image reconstruction")
    app.run(debug=True, host='0.0.0.0', port=5000)