# Quick Start Guide - SSH Certificate Admin

## 🚀 Get Started in 5 Minutes

### Option 1: Local Installation (Recommended for Development)

#### Step 1: Setup
```bash
cd sshadmin
chmod +x setup.sh
./setup.sh
```

#### Step 2: Configure CA Keys
```bash
# Generate SSH CA keys (run once)
sudo ssh-keygen -t ed25519 -f /etc/ssh/ca_key -N ""
sudo ssh-keygen -y -f /etc/ssh/ca_key > /etc/ssh/ca_key.pub

# Make readable by your user
sudo chmod 644 /etc/ssh/ca_key.pub
sudo chmod 600 /etc/ssh/ca_key
sudo chown $(whoami):$(whoami) /etc/ssh/ca_key
```

#### Step 3: Run the Application
```bash
source venv/bin/activate
python3 sshadmin.py
```

#### Step 4: Access the Application
- Open browser: http://localhost:5000
- Register a new account
- Start managing certificates!

---

### Option 2: Docker Installation

#### Step 1: Build and Run
```bash
docker-compose up -d
```

#### Step 2: Set up CA Keys
```bash
# On the host system
sudo ssh-keygen -t ed25519 -f /etc/ssh/ca_key -N ""
sudo ssh-keygen -y -f /etc/ssh/ca_key > /etc/ssh/ca_key.pub
```

#### Step 3: Access the Application
- Open browser: http://localhost:5000
- Register a new account

---

## 📋 Common Tasks

### Adding Your First User

1. Log in to the application
2. Go to **SSH Users** → **Add User**
3. Enter your username
4. Paste your SSH public key (from `~/.ssh/id_rsa.pub` or `~/.ssh/id_ed25519.pub`)
5. Click **Add User**

### Adding a Host

1. Go to **Hosts** → **Add Host**
2. Enter hostname (e.g., `server.example.com`)
3. Paste the host's SSH public key:
   ```bash
   cat /etc/ssh/ssh_host_ed25519_key.pub
   ```
4. Click **Add Host**

### Issuing Your First Certificate

1. Go to **Certificates** → **Issue User Cert**
2. Select yourself as the user
3. Leave validity as 365 days
4. Click **Issue Certificate**

The certificate is now issued and stored in the database.

---

## 🔒 Production Deployment

### Before Going Live:

1. **Change SECRET_KEY** in `.env`:
   ```bash
   python3 -c "import secrets; print(secrets.token_hex(32))"
   ```

2. **Use PostgreSQL** instead of SQLite:
   ```bash
   DATABASE_URL=postgresql://user:password@localhost/sshadmin
   ```

3. **Set up HTTPS** using nginx/Apache reverse proxy

4. **Secure CA Keys**:
   - Use proper file permissions (0600)
   - Consider hardware key storage
   - Regular backups

5. **Enable Audit Logging** for compliance

---

## 🐛 Troubleshooting

### "CA key not found" error
- Ensure `/etc/ssh/ca_key` exists
- Check file permissions: `ls -la /etc/ssh/ca_key*`
- Verify path in `.env` matches

### "Database error" 
- Delete `sshadmin.db` to reset
- Re-run: `python3 -c "from sshadmin import app, db; app.app_context().push(); db.create_all()"`

### Port 5000 already in use
```bash
# Kill the process using port 5000
lsof -ti:5000 | xargs kill -9

# Or use a different port
python3 sshadmin.py --port 5001
```

### Certificate not working on host
1. Verify `sshd_config` includes:
   ```
   HostCertificate /etc/ssh/ssh_host_ed25519_key-cert.pub
   TrustedUserCAKeys /etc/ssh/ca_key.pub
   ```
2. Restart SSH: `sudo systemctl restart sshd`
3. Test certificate validity: `ssh-keygen -L -f cert_file`

---

## 📚 More Information

- Full documentation: See `README.md`
- SSH Certificates guide: https://man.openbsd.org/ssh-keygen
- Flask documentation: https://flask.palletsprojects.com

---

## 💡 Tips

- **Backup your CA keys regularly!** They control all certificate access.
- **Use short-lived certificates** (7-30 days) for better security
- **Set up audit logging** to track who issued what certificates
- **Monitor certificate expiry** and plan renewals
- **Test your setup** before rolling out to production

Enjoy managing your SSH certificates! 🎉
