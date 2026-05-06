# Deployment Guide - SSH Certificate Admin

## Production Deployment Checklist

### Pre-Deployment

- [ ] Read `README.md` and `QUICKSTART.md`
- [ ] Test locally with `./setup.sh`
- [ ] Set up SSH CA keys on target system
- [ ] Plan backup strategy for CA keys
- [ ] Choose deployment method (Docker or bare metal)

---

## 🐳 Docker Deployment (Recommended)

### Step 1: Prepare Environment

```bash
# On your production server
mkdir -p /opt/sshadmin
cd /opt/sshadmin

# Clone or copy project files
cp -r /path/to/sshadmin/* .

# Generate strong secret key
SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")
echo "SECRET_KEY=$SECRET_KEY" >> .env

# Set database to PostgreSQL
echo 'DATABASE_URL=postgresql://sshadmin:PASSWORD@localhost:5432/sshadmin' >> .env
```

### Step 2: Set Up SSH CA Keys

```bash
# Generate CA keys (one time only)
sudo ssh-keygen -t ed25519 -f /etc/ssh/ca_key -N ""

# Make keys accessible to Docker
sudo chmod 644 /etc/ssh/ca_key.pub
sudo chmod 600 /etc/ssh/ca_key

# Verify permissions
ls -la /etc/ssh/ca_key*
```

### Step 3: Configure Database

```bash
# Install PostgreSQL (if not already installed)
sudo apt-get install postgresql postgresql-contrib

# Create database and user
sudo -u postgres psql << EOF
CREATE USER sshadmin WITH PASSWORD 'choose_strong_password';
CREATE DATABASE sshadmin OWNER sshadmin;
GRANT ALL PRIVILEGES ON DATABASE sshadmin TO sshadmin;
EOF
```

### Step 4: Set Up Nginx Reverse Proxy

```bash
# Create nginx config at /etc/nginx/sites-available/sshadmin
cat > /etc/nginx/sites-available/sshadmin << 'EOF'
server {
    listen 80;
    server_name your.domain.com;
    
    # Redirect to HTTPS
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    server_name your.domain.com;
    
    # SSL certificates (use Let's Encrypt)
    ssl_certificate /etc/letsencrypt/live/your.domain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/your.domain.com/privkey.pem;
    
    # Security headers
    add_header Strict-Transport-Security "max-age=31536000" always;
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    
    location / {
        proxy_pass http://localhost:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
EOF

# Enable the site
sudo ln -s /etc/nginx/sites-available/sshadmin /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl restart nginx
```

### Step 5: Start Docker Containers

```bash
cd /opt/sshadmin
docker-compose up -d

# Check status
docker-compose ps
docker-compose logs -f sshadmin
```

---

## 🖥️ Bare Metal Deployment (Linux/Ubuntu)

### Step 1: Install Dependencies

```bash
# Update system
sudo apt-get update
sudo apt-get upgrade -y

# Install Python and dependencies
sudo apt-get install -y python3 python3-pip python3-venv \
    openssh-client postgresql postgresql-contrib nginx

# Install system dependencies for Flask
sudo apt-get install -y build-essential python3-dev
```

### Step 2: Set Up Application

```bash
# Create application user
sudo useradd -m -s /bin/bash sshadmin

# Copy application files
sudo -u sshadmin mkdir -p /opt/sshadmin
sudo cp -r /path/to/sshadmin/* /opt/sshadmin/

# Set up virtual environment
cd /opt/sshadmin
sudo -u sshadmin python3 -m venv venv
sudo -u sshadmin venv/bin/pip install -r requirements.txt
```

### Step 3: Configure Environment

```bash
# Set up .env file
sudo -u sshadmin cp .env.example .env
sudo -u sshadmin nano .env

# Edit with:
# - FLASK_ENV=production
# - SECRET_KEY=<generated_key>
# - DATABASE_URL=postgresql://...
```

### Step 4: Set Up Systemd Service

```bash
# Create systemd service file
sudo tee /etc/systemd/system/sshadmin.service << 'EOF'
[Unit]
Description=SSH Certificate Admin
After=network.target postgresql.service

[Service]
Type=notify
User=sshadmin
WorkingDirectory=/opt/sshadmin
Environment="PATH=/opt/sshadmin/venv/bin"
ExecStart=/opt/sshadmin/venv/bin/python3 sshadmin.py
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

# Enable and start service
sudo systemctl daemon-reload
sudo systemctl enable sshadmin
sudo systemctl start sshadmin
sudo systemctl status sshadmin
```

### Step 5: Configure Nginx

Same as Docker deployment (Step 4 above)

---

## 🔐 Security Hardening

### Firewall Rules

```bash
# UFW (Ubuntu)
sudo ufw allow 22/tcp     # SSH
sudo ufw allow 80/tcp     # HTTP
sudo ufw allow 443/tcp    # HTTPS
sudo ufw enable
```

### SSL/TLS Certificates

```bash
# Install Let's Encrypt
sudo apt-get install certbot python3-certbot-nginx

# Get certificate
sudo certbot certonly --nginx -d your.domain.com

# Auto-renewal
sudo systemctl enable certbot.timer
sudo systemctl start certbot.timer
```

### Backup Strategy

```bash
#!/bin/bash
# backup.sh - Backup CA keys and database

BACKUP_DIR="/backups/sshadmin"
DATE=$(date +%Y%m%d_%H%M%S)

mkdir -p $BACKUP_DIR

# Backup CA keys
sudo tar czf $BACKUP_DIR/ca_keys_$DATE.tar.gz /etc/ssh/ca_key*

# Backup database
pg_dump sshadmin | gzip > $BACKUP_DIR/db_$DATE.sql.gz

# Keep only last 30 days
find $BACKUP_DIR -type f -mtime +30 -delete

echo "Backup completed: $BACKUP_DIR"
```

### Monitoring

```bash
# Install and configure monitoring
sudo apt-get install prometheus-node-exporter

# Monitor application logs
sudo journalctl -u sshadmin -f

# Monitor PostgreSQL
sudo -u postgres psql << EOF
SELECT * FROM pg_stat_activity;
EOF
```

---

## 📋 Post-Deployment Setup

### 1. Verify Deployment

```bash
# Test the application
curl https://your.domain.com

# Check database
sudo -u postgres psql -d sshadmin -c "\dt"

# Check service status
sudo systemctl status sshadmin
```

### 2. Create Initial Admin User

Access the application at https://your.domain.com
- Register a new account
- Mark as admin in database (if needed):
  ```sql
  UPDATE "user" SET is_admin = true WHERE username = 'admin_user';
  ```

### 3. Configure Host CA Trust

On each host that will use certificates:

```bash
# Copy CA public key
echo "$(cat /etc/ssh/ca_key.pub)" >> /etc/ssh/sshd_config

# Add to sshd_config
sudo tee -a /etc/ssh/sshd_config << EOF
# SSH Certificate Authority
TrustedUserCAKeys /etc/ssh/ca_key.pub
HostCertificate /etc/ssh/ssh_host_ed25519_key-cert.pub
EOF

# Restart SSH
sudo systemctl restart sshd

# Verify
sudo sshd -T | grep -E "TrustedUserCAKeys|HostCertificate"
```

---

## 🔄 Upgrades and Maintenance

### Backup Before Upgrades

```bash
# Backup everything
sudo systemctl stop sshadmin
sudo tar czf /backups/sshadmin_full_$(date +%Y%m%d).tar.gz /opt/sshadmin
sudo systemctl start sshadmin
```

### Apply Updates

```bash
cd /opt/sshadmin
git pull origin main
pip install -r requirements.txt
sudo systemctl restart sshadmin
```

### Database Migrations

```bash
# Backup database first
pg_dump sshadmin | gzip > backup_$(date +%Y%m%d).sql.gz

# Run migrations (if using Alembic)
python3 -m flask db upgrade
```

---

## 🚨 Troubleshooting

### Application won't start

```bash
# Check logs
sudo journalctl -u sshadmin -n 50 --no-pager

# Check database connection
psql postgresql://user:password@localhost:5432/sshadmin

# Test Flask directly
cd /opt/sshadmin
venv/bin/python3 -c "from sshadmin import app; app.run()"
```

### Certificate generation fails

```bash
# Verify CA keys exist
ls -la /etc/ssh/ca_key*

# Verify permissions
stat /etc/ssh/ca_key
stat /etc/ssh/ca_key.pub

# Test ssh-keygen
ssh-keygen -L -f /etc/ssh/ca_key.pub
```

### Database issues

```bash
# Connect to database
psql sshadmin

# Check tables
\dt

# Check disk space
df -h
```

---

## 📊 Performance Tuning

### PostgreSQL Configuration

```bash
# Edit /etc/postgresql/12/main/postgresql.conf
shared_buffers = 256MB
effective_cache_size = 1GB
maintenance_work_mem = 64MB
checkpoint_completion_target = 0.9
wal_buffers = 16MB
max_wal_size = 4GB
random_page_cost = 1.1
```

### Nginx Configuration

```nginx
# Add to /etc/nginx/nginx.conf
worker_processes auto;
worker_connections 2048;
keepalive_timeout 65;
client_max_body_size 100M;
```

---

## 🔐 Disaster Recovery

### Restore from Backup

```bash
# Restore CA keys
sudo tar xzf ca_keys_YYYYMMDD_HHMMSS.tar.gz

# Restore database
gunzip -c db_YYYYMMDD_HHMMSS.sql.gz | psql sshadmin

# Restart service
sudo systemctl restart sshadmin
```

---

## 📞 Support and Updates

- Check GitHub for updates
- Monitor security advisories
- Keep dependencies updated
- Regular backups of CA keys
- Monitor certificate expiration

---

## Deployment Complete! ✅

Your SSH Certificate Admin application is now running in production.

**Remember:**
- 🔐 Secure your CA keys!
- 💾 Regular backups
- 📊 Monitor logs
- 🔄 Keep updated
- 🚀 Scale as needed
