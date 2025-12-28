# 🚀 SecureVault - Server Deployment Guide

Deploy SecureVault to your Ubuntu server at `10.10.10.66` with Mikrotik IP forwarding.

## Prerequisites

- Ubuntu Server 20.04+ with SSH access
- Python 3.10+
- Git installed
- Mikrotik port forwarding configured (port 8443)

---

## Step 1: SSH into your server

```bash
ssh user@10.10.10.66
```

---

## Step 2: Install dependencies

```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install Python and Git
sudo apt install python3 python3-pip python3-venv git -y
```

---

## Step 3: Clone the repository

```bash
cd ~
git clone https://github.com/Swanster/securevault.git
cd securevault
```

---

## Step 4: Setup Python environment

```bash
# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install fastapi uvicorn aiosqlite python-jose passlib[bcrypt] email-validator httpx
```

---

## Step 5: Generate SSL certificate

```bash
openssl req -x509 -newkey rsa:4096 \
  -keyout key.pem -out cert.pem \
  -sha256 -days 365 -nodes \
  -subj "/CN=securevault/O=SecureVault/C=US"
```

---

## Step 6: Create systemd service (auto-start)

```bash
sudo nano /etc/systemd/system/securevault.service
```

Paste this content:

```ini
[Unit]
Description=SecureVault Password Manager
After=network.target

[Service]
User=YOUR_USERNAME
WorkingDirectory=/home/YOUR_USERNAME/securevault
ExecStart=/home/YOUR_USERNAME/securevault/venv/bin/python server.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

> ⚠️ Replace `YOUR_USERNAME` with your actual username

---

## Step 7: Enable and start service

```bash
sudo systemctl daemon-reload
sudo systemctl enable securevault
sudo systemctl start securevault
```

---

## Step 8: Configure Mikrotik port forwarding

On your Mikrotik router, add this NAT rule:

```
/ip firewall nat add chain=dstnat dst-port=8443 protocol=tcp action=dst-nat to-addresses=10.10.10.66 to-ports=8443
```

---

## Step 9: Access your password manager

- **Local**: https://10.10.10.66:8443
- **External**: https://YOUR_PUBLIC_IP:8443

> Accept the self-signed certificate warning on first visit

---

## Useful Commands

```bash
# Check status
sudo systemctl status securevault

# View logs
sudo journalctl -u securevault -f

# Restart service
sudo systemctl restart securevault

# Stop service
sudo systemctl stop securevault
```

---

## Security Tips

1. **Firewall**: Only allow port 8443
   ```bash
   sudo ufw allow 8443
   sudo ufw enable
   ```

2. **Fail2ban** (optional): Protect against brute force
   ```bash
   sudo apt install fail2ban -y
   ```

3. **Let's Encrypt** (optional): For trusted SSL certificate
   - Requires a domain name pointing to your public IP

---

## Done! 🎉

Your SecureVault is now running 24/7 on your server.
