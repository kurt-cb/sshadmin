# SSH Certificate Admin

A web-based SSH certificate management system built with Flask and Bootstrap.

## Features

- **Web-based Interface**: Modern Bootstrap UI for easy certificate management
- **User Management**: Register and manage SSH users
- **Host Management**: Register and manage SSH hosts
- **Certificate Issuance**: Issue SSH certificates for users and hosts
- **User Authentication**: Secure login system with Flask-Login
- **Database Support**: SQLAlchemy ORM with SQLite (configurable)
- **SSH Cert Generation**: Automated SSH certificate generation using OpenSSH

## Prerequisites

- Python 3.8+
- OpenSSH (for `ssh-keygen` command)
- pip or conda for package management

## Installation

1. Clone or download the project:
```bash
cd sshadmin
```

2. Create a virtual environment:
```bash
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Set up environment configuration:
```bash
cp .env.example .env
# Edit .env with your configuration
```

5. Initialize the database:
```bash
python3 -c "from sshadmin import app, db; app.app_context().push(); db.create_all()"
```

## SSH CA Setup (Required for Certificate Issuance)

Before issuing certificates, you need to set up a Certificate Authority:

### Generate CA Keys (Run Once)

```bash
# Generate CA private key (keep this secure!)
ssh-keygen -t ed25519 -f /etc/ssh/ca_key -N ""

# Generate CA public key
ssh-keygen -y -f /etc/ssh/ca_key > /etc/ssh/ca_key.pub
```

**IMPORTANT**: 
- `/etc/ssh/ca_key` must be readable by the Flask application
- Consider using a dedicated key or running in a container
- Never share the private key

### Configure Hosts to Trust the CA

On each host, add the CA public key to `/etc/ssh/sshd_config`:

```bash
# Add to /etc/ssh/sshd_config
HostCertificate /etc/ssh/ssh_host_ed25519_key-cert.pub
TrustedUserCAKeys /etc/ssh/ca_key.pub
```

Then restart SSH:
```bash
sudo systemctl restart sshd
```

## Running the Application

```bash
python3 sshadmin.py
```

The application will be available at `http://localhost:5000`

### Default Access

1. Register a new account at `/register`
2. Log in with your credentials
3. Start managing SSH hosts and users

## Usage Guide

### Adding SSH Users

1. Navigate to "SSH Users" → "Add User"
2. Enter the username and paste the user's public key
3. Optionally add a description
4. Click "Add User"

### Adding Hosts

1. Navigate to "Hosts" → "Add Host"
2. Enter the hostname and paste the host's public key
3. Optionally add a description
4. Click "Add Host"

### Issuing User Certificates

1. Navigate to "Certificates" → "Issue User Cert"
2. Select an SSH user
3. Set certificate validity period (default: 365 days)
4. Optionally specify principals (roles the user can assume)
5. Click "Issue Certificate"

### Issuing Host Certificates

1. Navigate to "Certificates" → "Issue Host Cert"
2. Select a host
3. Set certificate validity period
4. Click "Issue Certificate"

## Project Structure

```
sshadmin/
├── sshadmin.py              # Main Flask application
├── requirements.txt         # Python dependencies
├── .env.example            # Environment variables template
├── README.md               # This file
└── templates/              # HTML templates
    ├── base.html           # Base template with navbar
    ├── login.html          # Login page
    ├── register.html       # Registration page
    ├── dashboard.html      # Main dashboard
    ├── hosts.html          # Host management
    ├── add_host.html       # Add host form
    ├── users.html          # User management
    ├── add_user.html       # Add user form
    ├── certificates.html   # Certificate listing
    ├── issue_user_cert.html    # Issue user certificate
    ├── issue_host_cert.html    # Issue host certificate
    ├── 404.html            # Not found page
    └── 500.html            # Server error page
```

## Database Models

### User
- Stores application users for authentication
- Tracks who created hosts, users, and certificates

### Host
- SSH hosts that can receive certificates
- Stores hostname and public key

### SSHUser
- SSH users who can receive certificates
- Stores username and public key

### Certificate
- Issued SSH certificates
- Tracks validity period, serial number, and certificate data

## API Endpoints

### Authentication
- `GET/POST /login` - User login
- `GET/POST /register` - User registration
- `GET /logout` - User logout

### Dashboard
- `GET /dashboard` - Main dashboard

### Hosts
- `GET /hosts` - List all hosts
- `GET/POST /hosts/add` - Add new host
- `POST /hosts/<id>/delete` - Delete host

### Users
- `GET /users` - List all users
- `GET/POST /users/add` - Add new SSH user
- `POST /users/<id>/delete` - Delete user

### Certificates
- `GET /certificates` - List all certificates
- `GET/POST /certificates/issue/user` - Issue user certificate
- `GET/POST /certificates/issue/host` - Issue host certificate
- `GET /certificates/<id>/download` - Download certificate

### API
- `GET /api/ca-status` - Check CA key availability

## Security Considerations

1. **Change SECRET_KEY**: Update in `.env` file for production
2. **HTTPS**: Use a reverse proxy (nginx/Apache) with SSL in production
3. **Database**: Use PostgreSQL for production instead of SQLite
4. **CA Key Protection**: Store CA keys securely, consider using a hardware HSM
5. **Access Control**: Implement role-based access control for admins
6. **Audit Logging**: Log all certificate issuance and deletions
7. **Rate Limiting**: Consider adding rate limiting to API endpoints
8. **Input Validation**: All user input is validated before processing

## Troubleshooting

### SSH Keygen Errors
If you see "CA key not found" errors:
1. Ensure `/etc/ssh/ca_key` and `/etc/ssh/ca_key.pub` exist
2. Check permissions: they should be readable by the Flask process
3. Verify paths in `.env` file match actual key locations

### Database Errors
If you see database errors:
1. Delete `sshadmin.db` to reset the database
2. Re-run database initialization
3. Check file permissions in the directory

### Certificate Not Working
1. Verify the host public key is correct
2. Ensure `sshd_config` is properly configured
3. Restart SSH service on the host
4. Test with `ssh -v` for debugging

## License

MIT License

## Contributing

Contributions are welcome! Please feel free to submit pull requests.

## Support

For issues and questions, please open an issue on GitHub.
