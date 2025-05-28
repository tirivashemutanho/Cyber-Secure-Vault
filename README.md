# Cyber Secure Vault

**Cyber Secure Vault** is a browser-based file transfer system with end-to-end encryption, real-time malware scanning (ClamAV), JWT authentication, and a hacker-themed UI. Securely upload, download, and manage files with real-time threat detection and access control.

---

##  Problems This Project Solves

- **Unsafe File Sharing:** Traditional file transfer systems often lack malware scanning and encryption, exposing users to threats.
- **Data Breaches:** Files stored on the server are encrypted at rest, reducing the risk of data leaks if the server is compromised.
- **Unauthorized Access:** JWT authentication and per-user file access ensure only authorized users can view or download files.
- **Lack of Auditability:** All file actions are tied to authenticated users, making it easier to track activity.
- **Poor User Experience:** The modern, hacker-inspired UI makes secure file transfer engaging and easy to use.

---

##  Key Features

- **User Registration & Login:** Secure authentication using JWT tokens.
- **File Upload:** Upload files through a web interface.
- **Malware Scanning:** All uploads are scanned with ClamAV before being accepted.
- **End-to-End Encryption:** Files are encrypted with Fernet before being stored on the server.
- **Secure Download:** Only authenticated users can download their own files, which are decrypted on-the-fly.
- **Access Control:** Each user can only see and download their own files.
- **Hacker-Themed UI:** Neon green, red, and black cyberpunk design with video background.
- **Auditability:** All file actions are associated with user accounts.
- **Easy Deployment:** Simple setup with Python, Flask, and SQLite.

---

## How It Works

1. **User registers and logs in** via the web interface.
2. **User uploads a file:**  
   - The file is scanned for malware using ClamAV.
   - If clean, the file is encrypted and stored on the server.
   - The file is associated with the user in the database.
3. **User downloads a file:**  
   - The file is decrypted on-the-fly and sent to the user.
   - Only the owner can download their files.
4. **All actions require authentication** via JWT tokens.

---

##  Getting Started

### Prerequisites

- Python 3.8+
- pip
- ClamAV (for malware scanning)
- Node.js (optional, for frontend development)

### Installation

1. **Clone the repository:**
   ```sh
   git clone https://github.com/tirivashemutanho/Cyber-Secure-Vault.git
   cd Cyber-Secure-Vault
   ```

2. **Install Python dependencies:**
   ```sh
   pip install -r backend/requirements.txt
   ```

3. **Install ClamAV:**
   - **Windows:** Download from [ClamAV.net](https://www.clamav.net/downloads)
   - **Linux:**  
     ```sh
     sudo apt-get install clamav clamav-daemon
     sudo freshclam
     ```

4. **Run the backend:**
   ```sh
   python backend/app.py
   ```

5. **Open the frontend:**
   - Visit [http://localhost:5000/login.html](http://localhost:5000/login.html) in your browser.

---

## 🖥️ Usage

- **Register** a new account.
- **Login** with your credentials.
- **Upload** files (they are scanned and encrypted).
- **Download** your files securely.
- **Logout** when done.

---

## 📁 Project Structure

```
Cyber-Secure-Vault/
├── backend/
│   ├── app.py
│   ├── requirements.txt
│   └── uploads/
├── frontend/
│   ├── register.html
│   ├── login.html
│   ├── upload.html
│   ├── styles.css
│   ├── app.js
│   └── hacker-bg.mp4
├── .gitignore
└── README.md
```


##  Security Notes

- **Encryption key** is generated at runtime for demo purposes. In production, store it securely (e.g., in environment variables).
- **ClamAV** must be kept up to date for effective malware scanning.
- **JWT secret** should be changed and kept secret in production.
- **Uploads directory** is excluded from version control for privacy.

---

##  License

This project is licensed under the Apache-2.0 License.

---


---

## Contributing

Pull requests are welcome! For major changes, please open an issue first to discuss what you would like to change.

---

## 📣 Acknowledgements

- [ClamAV](https://www.clamav.net/)
- [Flask](https://flask.palletsprojects.com/)
- [cryptography](https://cryptography.io/)
- [JWT](https://jwt.io/)

---

For more, see the repository: [Cyber-Secure-Vault on GitHub](https://github.com/tirivashemutanho/Cyber-Secure-Vault)
