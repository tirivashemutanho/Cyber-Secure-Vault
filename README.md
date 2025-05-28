# Secure File Transfer Web App

A browser-based secure file transfer system with:
- User authentication (JWT)
- File upload with malware scanning (ClamAV)
- File encryption at rest
- Secure download
- Per-user file access
- Simple HTML/JS frontend (no React)

## Project Structure

```
/secure-file-transfer
|-- backend/
|    |-- app.py                # Flask app
|    |-- requirements.txt      # Python dependencies
|    |-- uploads/              # Encrypted files storage
|    |-- data.db               # SQLite database (auto-created)
|-- frontend/
|    |-- index.html            # Main UI
|-- README.md
```

## Setup Instructions

### 1. Install Python dependencies
```
pip install -r backend/requirements.txt
```

### 2. Install ClamAV (for malware scanning)
- **Windows:** Download from [ClamAV.net](https://www.clamav.net/downloads)
- **Linux:**
```
sudo apt-get install clamav clamav-daemon
sudo freshclam
```

### 3. Run the backend
```
cd backend
python app.py
```

### 4. Open the frontend
- Open `frontend/index.html` in your browser, or
- Visit [http://localhost:5000](http://localhost:5000) if running Flask with static file serving.

## Usage
- Register a user (use a tool like curl or add a registration form)
- Login
- Upload files (scanned and encrypted)
- Download your files securely

## Notes
- Encryption key is generated at runtime (for demo only). Store securely in production!
- For HTTPS, use mkcert (dev) or Let's Encrypt (prod).
- Extend with audit logs, role-based access, expiring links, etc. 