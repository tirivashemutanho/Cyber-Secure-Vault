from flask import Flask, request, jsonify, send_file, send_from_directory
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from cryptography.fernet import Fernet
import os
import subprocess
import sqlite3
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.config['JWT_SECRET_KEY'] = 'super-secret-key-change-this'  # Change in production
jwt = JWTManager(app)

UPLOAD_FOLDER = './backend/uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Encryption key - generate once and save securely!
ENCRYPTION_KEY = Fernet.generate_key()
cipher_suite = Fernet(ENCRYPTION_KEY)

# Simple DB init
def init_db():
    with sqlite3.connect('backend/data.db') as conn:
        conn.execute('''CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT UNIQUE, password TEXT)''')
        conn.execute('''CREATE TABLE IF NOT EXISTS files (id INTEGER PRIMARY KEY, filename TEXT, owner TEXT)''')
init_db()

# Simple password hashing
import hashlib
def hash_password(pw):
    return hashlib.sha256(pw.encode()).hexdigest()

# User registration
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    if not username or not password:
        return jsonify({'msg': 'Missing username or password'}), 400
    pw_hash = hash_password(password)
    try:
        with sqlite3.connect('backend/data.db') as conn:
            conn.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, pw_hash))
        return jsonify({'msg': 'User created'}), 201
    except sqlite3.IntegrityError:
        return jsonify({'msg': 'Username already exists'}), 409

# User login
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    if not username or not password:
        return jsonify({'msg': 'Missing username or password'}), 400

    with sqlite3.connect('backend/data.db') as conn:
        cur = conn.execute('SELECT password FROM users WHERE username=?', (username,))
        row = cur.fetchone()
        if row and hash_password(password) == row[0]:
            access_token = create_access_token(identity=username)
            return jsonify(access_token=access_token), 200

    return jsonify({'msg': 'Bad username or password'}), 401

# Scan file using ClamAV
def scan_file(filepath):
    result = subprocess.run([r'C:\Program Files\clamav\clamscan.exe', filepath], stdout=subprocess.PIPE)
    output = result.stdout.decode()
    # If 'FOUND' is in the output, the file is infected
    return "FOUND" not in output

# Upload endpoint
@app.route('/upload', methods=['POST'])
@jwt_required()
def upload():
    try:
        if 'file' not in request.files:
            return jsonify({'msg': 'No file part'}), 400
        file = request.files['file']
        if file.filename == '':
            return jsonify({'msg': 'No selected file'}), 400

        filename = secure_filename(file.filename)
        raw_data = file.read()

        # Save temp file for scanning
        temp_path = os.path.join(UPLOAD_FOLDER, 'temp_' + filename)
        with open(temp_path, 'wb') as temp_file:
            temp_file.write(raw_data)

        if not scan_file(temp_path):
            os.remove(temp_path)
            return jsonify({'msg': 'Malware detected! Upload rejected.'}), 400

        os.remove(temp_path)

        # Encrypt data
        encrypted_data = cipher_suite.encrypt(raw_data)

        enc_path = os.path.join(UPLOAD_FOLDER, filename + '.enc')
        with open(enc_path, 'wb') as f:
            f.write(encrypted_data)

        # Save file record in DB
        current_user = get_jwt_identity()
        with sqlite3.connect('backend/data.db') as conn:
            conn.execute('INSERT INTO files (filename, owner) VALUES (?, ?)', (filename, current_user))

        return jsonify({'msg': 'File uploaded and scanned successfully'}), 200
    except Exception as e:
        import traceback
        return jsonify({'msg': 'Internal server error', 'error': str(e), 'trace': traceback.format_exc()}), 500

# List files for current user
@app.route('/files', methods=['GET'])
@jwt_required()
def list_files():
    current_user = get_jwt_identity()
    with sqlite3.connect('backend/data.db') as conn:
        cur = conn.execute('SELECT filename FROM files WHERE owner=?', (current_user,))
        files = [row[0] for row in cur.fetchall()]
    return jsonify(files)

# Download endpoint
@app.route('/download/<filename>', methods=['GET'])
@jwt_required()
def download(filename):
    try:
        current_user = get_jwt_identity()
        with sqlite3.connect('backend/data.db') as conn:
            cur = conn.execute('SELECT id FROM files WHERE filename=? AND owner=?', (filename, current_user))
            if not cur.fetchone():
                return jsonify({'msg': 'File not found or access denied'}), 404

        enc_path = os.path.join(UPLOAD_FOLDER, filename + '.enc')
        if not os.path.exists(enc_path):
            return jsonify({'msg': 'File missing'}), 404

        with open(enc_path, 'rb') as f:
            encrypted_data = f.read()

        try:
            decrypted_data = cipher_suite.decrypt(encrypted_data)
        except Exception as e:
            return jsonify({'msg': 'Decryption failed', 'error': str(e)}), 500

        return decrypted_data, 200, {
            'Content-Type': 'application/octet-stream',
            'Content-Disposition': f'attachment; filename="{filename}"'
        }
    except Exception as e:
        import traceback
        return jsonify({'msg': 'Internal server error', 'error': str(e), 'trace': traceback.format_exc()}), 500

# Serve frontend page
@app.route('/')
def index():
    return send_file('../frontend/login.html')

@app.route('/<path:filename>')
def static_files(filename):
    return send_from_directory('../frontend', filename)

if __name__ == '__main__':
    app.run(debug=True) 