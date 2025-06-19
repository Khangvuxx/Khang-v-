from flask import Flask, request, send_from_directory, jsonify
from flask_cors import CORS
import os
import hashlib
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

app = Flask(__name__)
CORS(app)

UPLOAD_FOLDER = 'uploads'
SIG_FOLDER = 'signatures'
KEY_FOLDER = 'keys'

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(SIG_FOLDER, exist_ok=True)
os.makedirs(KEY_FOLDER, exist_ok=True)

PRIVATE_KEY_FILE = os.path.join(KEY_FOLDER, 'private.pem')
PUBLIC_KEY_FILE = os.path.join(KEY_FOLDER, 'public.pem')

# 1. Tạo key nếu chưa có
def generate_keys():
    if not os.path.exists(PRIVATE_KEY_FILE) or not os.path.exists(PUBLIC_KEY_FILE):
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_key = private_key.public_key()
        with open(PRIVATE_KEY_FILE, "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))
        with open(PUBLIC_KEY_FILE, "wb") as f:
            f.write(public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))

def load_keys():
    with open(PRIVATE_KEY_FILE, "rb") as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None)
    with open(PUBLIC_KEY_FILE, "rb") as f:
        public_key = serialization.load_pem_public_key(f.read())
    return private_key, public_key

generate_keys()
private_key, public_key = load_keys()

# 2. Ký file khi upload
def sign_file(file_path):
    with open(file_path, "rb") as f:
        file_data = f.read()
    file_hash = hashlib.sha256(file_data).digest()
    signature = private_key.sign(
        file_hash,
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    return signature

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return jsonify({"error": "No file part"}), 400
    file = request.files['file']
    if file.filename == '':
        return jsonify({"error": "No selected file"}), 400

    save_path = os.path.join(UPLOAD_FOLDER, file.filename)
    file.save(save_path)

    # Ký số file
    signature = sign_file(save_path)
    sig_path = os.path.join(SIG_FOLDER, file.filename + ".sig")
    with open(sig_path, "wb") as f:
        f.write(signature)

    return jsonify({"message": "Tải file lên & ký số thành công!"})

@app.route('/files', methods=['GET'])
def list_files():
    files = os.listdir(UPLOAD_FOLDER)
    return jsonify(files)

@app.route('/download/<filename>', methods=['GET'])
def download_file(filename):
    # Tải file gốc
    return send_from_directory(UPLOAD_FOLDER, filename, as_attachment=True)

@app.route('/download_sig/<filename>', methods=['GET'])
def download_signature(filename):
    # Tải chữ ký số
    return send_from_directory(SIG_FOLDER, filename + ".sig", as_attachment=True)

@app.route('/download_public_key', methods=['GET'])
def download_public_key():
    # Tải public key
    return send_from_directory(KEY_FOLDER, "public.pem", as_attachment=True)

@app.route('/verify', methods=['POST'])
def verify_signature():
    file = request.files['file']
    signature = request.files['signature'].read()
    pubkey = request.files['public_key'].read()
    file_data = file.read()
    file_hash = hashlib.sha256(file_data).digest()
    # Load public key từ file
    public_key = serialization.load_pem_public_key(pubkey)
    try:
        public_key.verify(
            signature,
            file_hash,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        return jsonify({"result": "Hợp lệ. File không bị chỉnh sửa."})
    except Exception as e:
        return jsonify({"result": "Không hợp lệ hoặc đã bị chỉnh sửa!"})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
