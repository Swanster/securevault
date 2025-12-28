# 🔐 SecureVault

A secure, cross-platform password manager with AES-256 encryption and cloud sync.

## Features

- 🔒 **AES-256-GCM Encryption** - Military-grade encryption
- ☁️ **Cross-Device Sync** - Sync passwords across all devices
- 🌐 **PWA** - Installable on Android, works offline
- 🔍 **Breach Check** - Check if passwords are leaked
- 📊 **Security Audit** - Dashboard showing password health
- 🔑 **Password Generator** - Create strong passwords
- 📋 **Categories & Search** - Organize and find passwords

## Quick Start

```bash
# Install dependencies
python -m venv venv
source venv/bin/activate
pip install fastapi uvicorn aiosqlite python-jose passlib[bcrypt] email-validator httpx

# Generate SSL certificate
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -sha256 -days 365 -nodes -subj "/CN=localhost"

# Run server
python server.py
```

Access at: **https://localhost:8443**

## Tech Stack

| Frontend | Backend |
|----------|---------|
| Vanilla JS | Python FastAPI |
| IndexedDB | SQLite |
| Web Crypto API | JWT Auth |

## Security

- Zero-knowledge architecture - server only stores encrypted data
- PBKDF2 key derivation (100,000 iterations)
- Auto-lock after 5 minutes
- Clipboard auto-clear after 30 seconds

## License

MIT
