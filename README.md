#  Secure Image Encryption Web App

A Flask-based web application for securely encrypting and decrypting images using AES-256 encryption.


##  Features

- **Military-grade Encryption**: AES-256-CBC with HMAC-SHA256  
- **Secure Key Derivation**: PBKDF2 with SHA-256  
- **Web Interface**: User-friendly Flask web app  
- **Image Support**: JPEG, PNG, BMP formats  
- **Integrity Protection**: HMAC verification prevents tampering  
- **Session Security**: No password storage  
- **Real-time Processing**: Fast encryption & decryption  
- **Operation Tracking**: Counts encryption/decryption usage  



##  System Architecture

### Image Preprocessing Layer
- Resize image to 512×512  
- Convert to RGB/Grayscale  
- Convert image into byte array  

### Encryption Layer
- AES-256 in CBC mode  
- PKCS7 padding  
- Random IV generation  
- HMAC integrity check  

### Web Interface (Flask)
- File upload & download  
- Encryption/Decryption routes  
- Session handling  


##  Workflow

###  Encryption
1. Upload image  
2. Preprocess image  
3. Generate key, salt, IV  
4. Encrypt using AES-256  
5. Attach metadata + HMAC  
6. Download encrypted file  

### Decryption
1. Upload encrypted file  
2. Verify HMAC  
3. Decrypt using key  
4. Remove padding  
5. Reconstruct original image  



## Cryptographic Details

- **Algorithm**: AES-256  
- **Mode**: CBC (Cipher Block Chaining)  
- **Key Derivation**: PBKDF2 + SHA-256  
- **IV Size**: 16 bytes  
- **Padding**: PKCS7  
- **Integrity**: HMAC-SHA256  



## Tech Stack

- Python  
- Flask  
- Pillow (PIL)  
- Cryptography Library  
- HTML / CSS  



##  Results

- High security against attacks  
- Strong randomness (high entropy)  
- Minimal processing time  
- Suitable for real-time applications  



## Advantages

- Secure image transmission  
- Lightweight and efficient  
- Easy-to-use interface  
- No sensitive data storage  
- Strong encryption standard  


##  Future Scope

- Hybrid encryption (AES + RSA/ECC)  
- Cloud-based deployment  
- Video & document encryption  
- IoT integration  




##  Installation

### 1. Clone Repository

git clone https://github.com/your-username/your-repo-name.git
cd your-repo-name


### 2. Install Dependencies

pip install -r requirements.txt


### 3. Run Application

python app.py


### 4. Open Browser

http://127.0.0.1:5000/




##  Usage

- Upload image  
- Enter passkey  
- Click Encrypt/Decrypt  
- Download result  



## Applications

- Secure image sharing  
- Medical image protection  
- Cloud storage security  
- Surveillance systems  
- IoT-based image security  

