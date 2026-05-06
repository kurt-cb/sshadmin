# API Reference - SSH Certificate Admin

## Authentication

All endpoints (except `/login` and `/register`) require authentication via Flask-Login session.

### Login
```
POST /login
Content-Type: application/x-www-form-urlencoded

username=user&password=pass
```

### Register
```
POST /register
Content-Type: application/x-www-form-urlencoded

username=user&email=user@example.com&password=pass&confirm=pass
```

### Logout
```
GET /logout
```

---

## Endpoints

### Dashboard

#### Get Dashboard
```
GET /dashboard
Response: HTML dashboard page with statistics
```

---

### Hosts

#### List All Hosts
```
GET /hosts
Response: HTML page with host table
```

#### Add New Host
```
GET /hosts/add
Response: HTML form to add host

POST /hosts/add
Content-Type: application/x-www-form-urlencoded

hostname=server.example.com&public_key=ssh-ed25519 AAAA...&description=Optional
Response: Redirect to /hosts on success
```

#### Delete Host
```
POST /hosts/<host_id>/delete
Response: Redirect to /hosts
```

---

### SSH Users

#### List All Users
```
GET /users
Response: HTML page with users table
```

#### Add New User
```
GET /users/add
Response: HTML form to add user

POST /users/add
Content-Type: application/x-www-form-urlencoded

username=john&public_key=ssh-ed25519 AAAA...&description=Optional
Response: Redirect to /users on success
```

#### Delete User
```
POST /users/<user_id>/delete
Response: Redirect to /users
```

---

### Certificates

#### List All Certificates
```
GET /certificates
Response: HTML page with certificates table
```

#### Issue User Certificate
```
GET /certificates/issue/user
Response: HTML form to issue user certificate

POST /certificates/issue/user
Content-Type: application/x-www-form-urlencoded

user_id=1&valid_days=365&principals=john,admin
Response: Redirect to /certificates on success

Parameters:
- user_id (required): ID of the SSH user
- valid_days (optional): Validity period in days (default: 365)
- principals (optional): Comma-separated roles (default: username)
```

#### Issue Host Certificate
```
GET /certificates/issue/host
Response: HTML form to issue host certificate

POST /certificates/issue/host
Content-Type: application/x-www-form-urlencoded

host_id=1&valid_days=365
Response: Redirect to /certificates on success

Parameters:
- host_id (required): ID of the host
- valid_days (optional): Validity period in days (default: 365)
```

#### Download Certificate
```
GET /certificates/<cert_id>/download
Response: Certificate file download (to be implemented)
```

---

### API Endpoints

#### Check CA Status
```
GET /api/ca-status
Response: JSON

{
  "ca_available": true
}
```

---

## Database Queries

### Get User by ID
```python
from sshadmin import User
user = User.query.get(1)
```

### Get All Certificates for User
```python
from sshadmin import Certificate, SSHUser
user = SSHUser.query.get(1)
certs = Certificate.query.filter_by(user_id=user.id).all()
```

### Get Expired Certificates
```python
from sshadmin import Certificate
from datetime import datetime

expired = Certificate.query.filter(
    Certificate.valid_until < datetime.utcnow()
).all()
```

### Get Certificates by Creator
```python
from sshadmin import Certificate
certs = Certificate.query.filter_by(created_by_id=1).all()
```

---

## Response Codes

| Code | Meaning |
|------|---------|
| 200 | OK - Request successful |
| 302 | Redirect - After form submission |
| 400 | Bad Request - Invalid parameters |
| 401 | Unauthorized - Login required |
| 404 | Not Found - Resource doesn't exist |
| 500 | Server Error - Something went wrong |

---

## Error Handling

All forms include CSRF protection. Errors are displayed via Flask flash messages:

```html
{% with messages = get_flashed_messages(with_categories=true) %}
    {% for category, message in messages %}
        <div class="alert alert-{{ category }}">
            {{ message }}
        </div>
    {% endfor %}
{% endwith %}
```

---

## Database Schema

### users table
```sql
CREATE TABLE users (
    id INTEGER PRIMARY KEY,
    username VARCHAR(80) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    email VARCHAR(120) UNIQUE NOT NULL,
    is_admin BOOLEAN DEFAULT FALSE,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
```

### hosts table
```sql
CREATE TABLE hosts (
    id INTEGER PRIMARY KEY,
    hostname VARCHAR(255) UNIQUE NOT NULL,
    description TEXT,
    public_key TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    created_by_id INTEGER FOREIGN KEY REFERENCES users(id)
);
```

### sshusers table
```sql
CREATE TABLE sshusers (
    id INTEGER PRIMARY KEY,
    username VARCHAR(255) NOT NULL,
    public_key TEXT NOT NULL,
    description TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    created_by_id INTEGER FOREIGN KEY REFERENCES users(id),
    UNIQUE(username, public_key)
);
```

### certificates table
```sql
CREATE TABLE certificates (
    id INTEGER PRIMARY KEY,
    cert_type VARCHAR(20) NOT NULL,  -- 'user' or 'host'
    user_id INTEGER FOREIGN KEY REFERENCES sshusers(id),
    host_id INTEGER FOREIGN KEY REFERENCES hosts(id),
    public_key TEXT NOT NULL,
    serial VARCHAR(255) UNIQUE NOT NULL,
    valid_from DATETIME NOT NULL,
    valid_until DATETIME NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    created_by_id INTEGER FOREIGN KEY REFERENCES users(id),
    certificate_data TEXT
);
```

---

## Example Usage

### Create User Programmatically
```python
from sshadmin import app, db, User

with app.app_context():
    user = User(username='john', email='john@example.com')
    user.set_password('password123')
    db.session.add(user)
    db.session.commit()
    print(f"User created with ID: {user.id}")
```

### Query Certificates
```python
from sshadmin import Certificate
from datetime import datetime

# Get all valid certificates
valid_certs = Certificate.query.filter(
    Certificate.valid_until > datetime.utcnow()
).all()

for cert in valid_certs:
    if cert.user:
        print(f"User cert for {cert.user.username}, expires {cert.valid_until}")
    else:
        print(f"Host cert for {cert.host.hostname}, expires {cert.valid_until}")
```

### Programmatic Certificate Issuance
```python
from sshadmin import app, db, Certificate, SSHUser, SSHCertificateGenerator
from datetime import datetime, timedelta
import tempfile
import os

cert_gen = SSHCertificateGenerator()

with app.app_context():
    user = SSHUser.query.get(1)
    
    # Create temp file with user's public key
    with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
        f.write(user.public_key)
        temp_key = f.name
    
    try:
        # Generate certificate
        cert_data, serial = cert_gen.generate_user_certificate(
            temp_key,
            user.username,
            valid_days=365
        )
        
        # Store in database
        cert = Certificate(
            cert_type='user',
            user_id=user.id,
            public_key=user.public_key,
            serial=serial,
            valid_from=datetime.utcnow(),
            valid_until=datetime.utcnow() + timedelta(days=365),
            created_by_id=1,  # Admin user ID
            certificate_data=cert_data
        )
        db.session.add(cert)
        db.session.commit()
        print(f"Certificate issued: {serial}")
    finally:
        os.unlink(temp_key)
```

---

## Rate Limiting (Recommended)

```python
# Add to requirements.txt
Flask-Limiter==3.3.1

# Add to sshadmin.py
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

# Apply to routes
@app.route('/certificates/issue/user', methods=['POST'])
@limiter.limit("5 per minute")
@login_required
def issue_user_cert():
    # ... implementation
```

---

## Webhooks (Extensible)

```python
# Add certificate issuance webhook
import requests

def notify_on_certificate_issue(cert):
    """Send webhook notification when certificate is issued"""
    webhook_url = os.environ.get('WEBHOOK_URL')
    if webhook_url:
        payload = {
            'event': 'certificate_issued',
            'cert_id': cert.id,
            'cert_type': cert.cert_type,
            'serial': cert.serial,
            'valid_until': cert.valid_until.isoformat(),
            'created_at': cert.created_at.isoformat()
        }
        try:
            requests.post(webhook_url, json=payload, timeout=5)
        except Exception as e:
            print(f"Webhook error: {e}")
```

---

## Integration Examples

### Ansible Integration
```yaml
- name: Add host to SSH Certificate Admin
  uri:
    url: "http://localhost:5000/api/hosts"
    method: POST
    body_format: json
    body:
      hostname: "{{ inventory_hostname }}"
      public_key: "{{ ssh_public_key }}"
```

### Terraform Integration
```hcl
resource "local_file" "issue_cert" {
  content  = "true"
  filename = "/tmp/trigger_cert_issue"

  provisioner "local-exec" {
    command = "curl -X POST http://localhost:5000/certificates/issue/host"
  }
}
```

---

## Monitoring and Metrics

```python
# Add Prometheus metrics
from prometheus_client import Counter, Histogram

cert_issued = Counter('certs_issued_total', 'Total certificates issued')
cert_issue_time = Histogram('cert_issue_seconds', 'Time to issue certificate')

@app.route('/metrics')
def metrics():
    return generate_latest()
```

---

Complete API documentation! Use these endpoints to integrate SSH Certificate Admin with your infrastructure.
