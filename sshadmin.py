"""
SSH Certificate Admin - Web-based SSH certificate management system
"""
from flask import Flask, render_template, request, jsonify, redirect, url_for, flash, session, Response
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from datetime import datetime, timedelta
import io
import os
import json
import secrets
from pathlib import Path
import subprocess
import tempfile

import pyotp
import qrcode
import qrcode.image.svg

ALLOWED_HOST_KEY_TYPE = 'ecdsa-sha2-nistp521'
ALLOWED_USER_KEY_TYPES = ('ecdsa-sha2-nistp521', 'ssh-ed25519', 'ecdsa-sha2-nistp384')
ENROLLMENT_TOKEN_TTL_HOURS = 24
CHALLENGE_TTL_MINUTES = 30
SSHSIG_NAMESPACE = 'sshadmin'
TOTP_ISSUER = 'sshadmin'

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///sshadmin.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize extensions
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# ==================== Database Models ====================

host_owners = db.Table(
    'host_owners',
    db.Column('host_id', db.Integer, db.ForeignKey('host.id', ondelete='CASCADE'), primary_key=True),
    db.Column('user_id', db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'), primary_key=True),
    db.Column('added_at', db.DateTime, default=datetime.utcnow),
)


class User(UserMixin, db.Model):
    """Application user model — auth via SSH-key challenge/response (no password)."""
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    public_key = db.Column(db.Text, nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    completed_at = db.Column(db.DateTime, nullable=True)

    # Optional TOTP as an alternate login method.
    totp_secret = db.Column(db.String(64), nullable=True)
    totp_enabled = db.Column(db.Boolean, default=False, nullable=False)

    owned_hosts = db.relationship('Host', secondary=host_owners, back_populates='owners')

    @property
    def is_active(self):
        # Flask-Login refuses to log in users where is_active is False.
        return self.completed_at is not None


class Challenge(db.Model):
    """One-time SSHSIG challenge for register-or-login flows."""
    id = db.Column(db.Integer, primary_key=True)
    token = db.Column(db.String(64), unique=True, nullable=False, index=True)
    nonce = db.Column(db.String(128), nullable=False)
    purpose = db.Column(db.String(20), nullable=False)  # 'register' or 'login'
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=False)
    consumed_at = db.Column(db.DateTime, nullable=True)

    user = db.relationship('User', backref='challenges')

    @property
    def is_active(self):
        return self.consumed_at is None and self.expires_at > datetime.utcnow()


class Host(db.Model):
    """SSH host model"""
    id = db.Column(db.Integer, primary_key=True)
    hostname = db.Column(db.String(255), unique=True, nullable=False)
    description = db.Column(db.Text)
    public_key = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    created_by_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    enrollment_token = db.Column(db.String(64), unique=True, nullable=True, index=True)
    enrollment_expires_at = db.Column(db.DateTime, nullable=True)
    enrolled_at = db.Column(db.DateTime, nullable=True)

    creator = db.relationship('User', backref='hosts', foreign_keys=[created_by_id])
    certificates = db.relationship('Certificate', backref='host', lazy=True, cascade='all, delete-orphan')
    owners = db.relationship('User', secondary=host_owners, back_populates='owned_hosts')

    @property
    def is_enrolled(self):
        return self.enrolled_at is not None and self.public_key

    def issue_enrollment_token(self):
        self.enrollment_token = secrets.token_urlsafe(32)
        self.enrollment_expires_at = datetime.utcnow() + timedelta(hours=ENROLLMENT_TOKEN_TTL_HOURS)
        self.enrolled_at = None
        self.public_key = None


class SSHUser(db.Model):
    """SSH user model"""
    __tablename__ = 'sshuser'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(255), nullable=False)
    public_key = db.Column(db.Text, nullable=False)
    description = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    created_by_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    
    creator = db.relationship('User', backref='ssh_users')
    certificates = db.relationship('Certificate', backref='user', lazy=True, cascade='all, delete-orphan')
    
    __table_args__ = (db.UniqueConstraint('username', 'public_key', name='_username_key_uc'),)


class Certificate(db.Model):
    """SSH certificate model"""
    id = db.Column(db.Integer, primary_key=True)
    cert_type = db.Column(db.String(20), nullable=False)  # 'user' or 'host'
    user_id = db.Column(db.Integer, db.ForeignKey('sshuser.id'), nullable=True)
    host_id = db.Column(db.Integer, db.ForeignKey('host.id'), nullable=True)
    public_key = db.Column(db.Text, nullable=False)
    serial = db.Column(db.String(255), nullable=False, unique=True)
    valid_from = db.Column(db.DateTime, nullable=False)
    valid_until = db.Column(db.DateTime, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    created_by_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    certificate_data = db.Column(db.Text)  # OpenSSH certificate format

    # One-time install token for the curl-based install one-liner.
    install_token = db.Column(db.String(64), unique=True, nullable=True, index=True)
    install_token_expires_at = db.Column(db.DateTime, nullable=True)

    creator = db.relationship('User', backref='issued_certificates')

    def issue_install_token(self, ttl_hours=2):
        self.install_token = secrets.token_urlsafe(32)
        self.install_token_expires_at = datetime.utcnow() + timedelta(hours=ttl_hours)


# ==================== Login Manager ====================

@login_manager.user_loader
def load_user(user_id):
    user = User.query.get(int(user_id))
    if user is None or user.completed_at is None:
        return None
    return user


def verify_sshsig(public_key, signature_armor, message, identity='user', namespace=SSHSIG_NAMESPACE):
    """Verify an SSHSIG-format signature using `ssh-keygen -Y verify`.

    Returns True on success, False otherwise.
    """
    parts = (public_key or '').strip().split()
    if len(parts) < 2:
        return False
    clean_pubkey = parts[0] + ' ' + parts[1]

    with tempfile.TemporaryDirectory() as tmp:
        allowed_signers = os.path.join(tmp, 'allowed_signers')
        sig_path = os.path.join(tmp, 'message.sig')
        with open(allowed_signers, 'w') as f:
            f.write(f'{identity} {clean_pubkey}\n')
        with open(sig_path, 'w') as f:
            f.write(signature_armor)
        try:
            result = subprocess.run(
                ['ssh-keygen', '-Y', 'verify',
                 '-f', allowed_signers,
                 '-I', identity,
                 '-n', namespace,
                 '-s', sig_path],
                input=message,
                capture_output=True, text=True,
                timeout=10,
            )
        except Exception:
            return False
        return result.returncode == 0


def _new_challenge(user, purpose):
    """Create + persist a fresh Challenge for a user; caller must commit."""
    challenge = Challenge(
        token=secrets.token_urlsafe(32),
        nonce=secrets.token_hex(32),
        purpose=purpose,
        user_id=user.id,
        expires_at=datetime.utcnow() + timedelta(minutes=CHALLENGE_TTL_MINUTES),
    )
    db.session.add(challenge)
    return challenge


from functools import wraps


def admin_required(view):
    @wraps(view)
    @login_required
    def wrapped(*args, **kwargs):
        if not getattr(current_user, 'is_admin', False):
            flash('Administrator access required.', 'danger')
            return redirect(url_for('dashboard'))
        return view(*args, **kwargs)
    return wrapped


# ==================== SSH Certificate Generation ====================

class SSHCertificateGenerator:
    """Generate SSH certificates using OpenSSH format"""

    def __init__(self):
        self.ca_key = os.environ.get('SSHADMIN_CA_KEY_PATH', '/etc/ssh/ca_key')
        self.ca_pubkey = self.ca_key + '.pub'

    def check_ca_keys(self):
        """Check if CA keys exist"""
        return os.path.exists(self.ca_key) and os.path.exists(self.ca_pubkey)

    def generate_ca(self, key_type='ecdsa', bits=521, comment='sshadmin CA'):
        """Generate a new CA keypair at self.ca_key. Refuses if it already exists."""
        if self.check_ca_keys():
            raise Exception('CA keys already exist')
        os.makedirs(os.path.dirname(self.ca_key) or '.', exist_ok=True)
        cmd = ['ssh-keygen', '-t', key_type, '-f', self.ca_key, '-N', '', '-C', comment]
        if key_type in ('ecdsa', 'rsa'):
            cmd.extend(['-b', str(bits)])
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            raise Exception(f'ssh-keygen failed: {result.stderr.strip() or result.stdout.strip()}')
        try:
            os.chmod(self.ca_key, 0o600)
            os.chmod(self.ca_pubkey, 0o644)
        except OSError:
            pass

    def read_ca_pubkey(self):
        if not os.path.exists(self.ca_pubkey):
            return None
        with open(self.ca_pubkey, 'r') as f:
            return f.read().strip()

    def ca_fingerprint(self):
        if not os.path.exists(self.ca_pubkey):
            return None
        try:
            result = subprocess.run(
                ['ssh-keygen', '-l', '-f', self.ca_pubkey],
                capture_output=True, text=True, check=True,
            )
            return result.stdout.strip()
        except Exception:
            return None
    
    def generate_user_certificate(self, public_key_path, username, valid_days=365, principals=None):
        """Generate SSH user certificate"""
        if principals is None:
            principals = [username]

        # ssh-keygen -V wants YYYYMMDDHHMMSS in the local timezone, not Unix epoch.
        now = datetime.utcnow()
        valid_after = now.strftime('%Y%m%d%H%M%S')
        valid_before = (now + timedelta(days=valid_days)).strftime('%Y%m%d%H%M%S')

        # Certificate serial (can be any unique number)
        serial = int(now.timestamp() * 1000)

        try:
            cmd = [
                'ssh-keygen',
                '-s', self.ca_key,
                '-I', f'{username}-{serial}',
                '-n', ','.join(principals),
                '-V', f'{valid_after}:{valid_before}',
                '-z', str(serial),
                public_key_path
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            # ssh-keygen writes the cert at `<input-without-.pub>-cert.pub`.
            base = public_key_path[:-4] if public_key_path.endswith('.pub') else public_key_path
            cert_path = f'{base}-cert.pub'
            
            if os.path.exists(cert_path):
                with open(cert_path, 'r') as f:
                    cert_data = f.read().strip()
                os.remove(cert_path)
                return cert_data, str(serial)
            
            raise Exception("Certificate generation failed")
        except subprocess.CalledProcessError as e:
            raise Exception(f"SSH keygen error: {e.stderr}")
    
    def generate_host_certificate(self, public_key_path, hostnames, valid_days=365):
        """Generate SSH host certificate"""
        if isinstance(hostnames, str):
            hostnames = [hostnames]

        now = datetime.utcnow()
        valid_after = now.strftime('%Y%m%d%H%M%S')
        valid_before = (now + timedelta(days=valid_days)).strftime('%Y%m%d%H%M%S')
        serial = int(now.timestamp() * 1000)
        
        try:
            cmd = [
                'ssh-keygen',
                '-s', self.ca_key,
                '-h',  # Host certificate
                '-I', f'host-{serial}',
                '-n', ','.join(hostnames),
                '-V', f'{valid_after}:{valid_before}',
                '-z', str(serial),
                public_key_path
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            # ssh-keygen writes the cert at `<input-without-.pub>-cert.pub`.
            base = public_key_path[:-4] if public_key_path.endswith('.pub') else public_key_path
            cert_path = f'{base}-cert.pub'
            
            if os.path.exists(cert_path):
                with open(cert_path, 'r') as f:
                    cert_data = f.read().strip()
                os.remove(cert_path)
                return cert_data, str(serial)
            
            raise Exception("Certificate generation failed")
        except subprocess.CalledProcessError as e:
            raise Exception(f"SSH keygen error: {e.stderr}")


cert_gen = SSHCertificateGenerator()


# ==================== Routes ====================

# Endpoints that must remain reachable even when CA is missing.
_CA_SETUP_ALLOWED_ENDPOINTS = {
    'login', 'logout', 'register', 'setup_ca', 'setup_totp', 'static',
    'auth_await',
    'api_ca_status', 'api_ca_pubkey',
    'api_auth_script', 'api_auth_status', 'api_challenge_response',
    'api_totp_response',
    'api_enroll_script', 'api_enroll_host',
    'api_cert_install_data', 'api_cert_install_script',
}


@app.before_request
def _redirect_admin_to_setup_when_ca_missing():
    """If the CA isn't configured yet, push admins to /setup/ca."""
    if cert_gen.check_ca_keys():
        return
    if not current_user.is_authenticated:
        return
    if request.endpoint in _CA_SETUP_ALLOWED_ENDPOINTS:
        return
    if not getattr(current_user, 'is_admin', False):
        return
    return redirect(url_for('setup_ca'))


@app.route('/')
def index():
    """Home page"""
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))


@app.route('/setup/ca', methods=['GET', 'POST'])
@admin_required
def setup_ca():
    """One-time CA generation form."""
    if cert_gen.check_ca_keys():
        flash('CA is already configured.', 'info')
        return redirect(url_for('server_config'))

    if request.method == 'POST':
        comment = (request.form.get('comment') or 'sshadmin CA').strip()
        key_type = (request.form.get('key_type') or 'ecdsa').strip()
        bits_raw = (request.form.get('bits') or '521').strip()

        try:
            bits = int(bits_raw)
        except ValueError:
            flash('Bits must be a number.', 'danger')
            return redirect(url_for('setup_ca'))

        valid_combos = {
            'ecdsa': {256, 384, 521},
            'rsa': {2048, 3072, 4096},
            'ed25519': {0},
        }
        if key_type not in valid_combos:
            flash(f'Unsupported key type: {key_type}', 'danger')
            return redirect(url_for('setup_ca'))
        if key_type != 'ed25519' and bits not in valid_combos[key_type]:
            flash(f'Invalid bit length for {key_type}.', 'danger')
            return redirect(url_for('setup_ca'))

        try:
            cert_gen.generate_ca(key_type=key_type, bits=bits, comment=comment)
        except Exception as exc:
            flash(f'CA generation failed: {exc}', 'danger')
            return redirect(url_for('setup_ca'))

        flash('CA generated successfully.', 'success')
        return redirect(url_for('server_config'))

    return render_template('setup_ca.html', ca_key_path=cert_gen.ca_key)


def _generate_totp_qr_svg(uri):
    """Render a TOTP otpauth:// URI as an inline SVG (no PIL dependency)."""
    img = qrcode.make(uri, image_factory=qrcode.image.svg.SvgPathImage)
    buf = io.BytesIO()
    img.save(buf)
    return buf.getvalue().decode()


@app.route('/setup/totp', methods=['GET', 'POST'])
@login_required
def setup_totp():
    """Optional TOTP setup. User can scan QR + verify, or skip."""
    if request.method == 'POST':
        action = (request.form.get('action') or 'verify').strip()

        if action == 'skip':
            session.pop('pending_totp_secret', None)
            flash('TOTP setup skipped — challenge/response is the only login method.', 'info')
            return redirect(url_for('dashboard'))

        secret = session.get('pending_totp_secret')
        code = (request.form.get('code') or '').strip()

        if not secret:
            flash('TOTP secret expired. Restarting setup.', 'warning')
            return redirect(url_for('setup_totp'))
        if not code:
            flash('Enter the 6-digit code from your authenticator app.', 'danger')
            return redirect(url_for('setup_totp'))

        totp = pyotp.TOTP(secret)
        if not totp.verify(code, valid_window=1):
            flash('Code did not match. Try again with a fresh code.', 'danger')
            return redirect(url_for('setup_totp'))

        current_user.totp_secret = secret
        current_user.totp_enabled = True
        db.session.commit()
        session.pop('pending_totp_secret', None)
        flash('TOTP enabled. You can now log in with either your SSH key or a TOTP code.', 'success')
        return redirect(url_for('dashboard'))

    if current_user.totp_enabled:
        flash('TOTP is already enabled. Disable it first to re-enroll.', 'info')
        return redirect(url_for('profile'))

    secret = session.get('pending_totp_secret')
    if not secret:
        secret = pyotp.random_base32()
        session['pending_totp_secret'] = secret

    uri = pyotp.totp.TOTP(secret).provisioning_uri(
        name=current_user.username,
        issuer_name=TOTP_ISSUER,
    )
    qr_svg = _generate_totp_qr_svg(uri)

    return render_template(
        'setup_totp.html',
        secret=secret,
        qr_svg=qr_svg,
        otpauth_uri=uri,
        issuer=TOTP_ISSUER,
    )


@app.route('/profile')
@login_required
def profile():
    return render_template('profile.html', user=current_user)


@app.route('/profile/totp/disable', methods=['POST'])
@login_required
def disable_totp():
    current_user.totp_secret = None
    current_user.totp_enabled = False
    db.session.commit()
    flash('TOTP disabled.', 'info')
    return redirect(url_for('profile'))


@app.route('/server-config')
@admin_required
def server_config():
    """Show the CA public key and other server-side settings."""
    ca_present = cert_gen.check_ca_keys()
    ca_pubkey = cert_gen.read_ca_pubkey() if ca_present else None
    fingerprint = cert_gen.ca_fingerprint() if ca_present else None
    ca_key_type = ca_pubkey.split()[0] if ca_pubkey else None

    counts = {
        'hosts': Host.query.count(),
        'enrolled_hosts': Host.query.filter(Host.enrolled_at.isnot(None)).count(),
        'ssh_users': SSHUser.query.count(),
        'certificates': Certificate.query.count(),
        'app_users': User.query.count(),
    }

    return render_template(
        'server_config.html',
        ca_present=ca_present,
        ca_pubkey=ca_pubkey,
        ca_fingerprint=fingerprint,
        ca_key_type=ca_key_type,
        ca_key_path=cert_gen.ca_key,
        ca_pubkey_path=cert_gen.ca_pubkey,
        server_url=request.url_root.rstrip('/'),
        counts=counts,
    )


@app.route('/register', methods=['GET', 'POST'])
def register():
    """User registration via SSH key challenge-response."""
    if request.method == 'POST':
        username = (request.form.get('username') or '').strip()
        public_key = (request.form.get('public_key') or '').strip()

        if not username or not public_key:
            flash('Username and SSH public key are required.', 'danger')
            return redirect(url_for('register'))

        parts = public_key.split()
        if len(parts) < 2 or parts[0] not in ALLOWED_USER_KEY_TYPES:
            flash(
                f'Public key must be one of: {", ".join(ALLOWED_USER_KEY_TYPES)}.',
                'danger',
            )
            return redirect(url_for('register'))

        existing = User.query.filter_by(username=username).first()
        if existing and existing.completed_at is not None:
            flash('Username already registered.', 'danger')
            return redirect(url_for('register'))

        if existing and existing.completed_at is None:
            # Reuse pending row (refresh public_key) so abandoned attempts can resume.
            existing.public_key = public_key
            user = existing
        else:
            user = User(username=username, public_key=public_key)
            db.session.add(user)
            db.session.flush()  # populate user.id for the Challenge FK

        challenge = _new_challenge(user, 'register')
        db.session.commit()

        session['pending_challenge_token'] = challenge.token
        return redirect(url_for('auth_await', token=challenge.token))

    return render_template('register.html', allowed_key_types=ALLOWED_USER_KEY_TYPES)


@app.route('/login', methods=['GET', 'POST'])
def login():
    """Login via SSH key challenge-response."""
    if request.method == 'POST':
        username = (request.form.get('username') or '').strip()
        if not username:
            flash('Username is required.', 'danger')
            return redirect(url_for('login'))

        user = User.query.filter_by(username=username).first()
        if not user or user.completed_at is None:
            # Same response whether the user exists or not (avoid enumeration).
            flash('No completed registration for that username.', 'danger')
            return redirect(url_for('login'))

        challenge = _new_challenge(user, 'login')
        db.session.commit()

        session['pending_challenge_token'] = challenge.token
        return redirect(url_for('auth_await', token=challenge.token))

    return render_template('login.html')


@app.route('/auth/await/<token>')
def auth_await(token):
    """Page that displays the curl one-liner and polls for completion."""
    challenge = Challenge.query.filter_by(token=token).first_or_404()

    server_url = request.url_root.rstrip('/')
    one_liner_url = f"{server_url}{url_for('api_auth_script')}?token={challenge.token}"
    if challenge.purpose == 'register':
        one_liner = f'curl -fsSL "{one_liner_url}" | sudo bash   # omit sudo to skip host enrollment'
    else:
        one_liner = f'curl -fsSL "{one_liner_url}" | bash'

    totp_available = challenge.purpose == 'login' and challenge.user.totp_enabled

    # Surface the SSH alt-auth path (port + host) so the page can render the
    # `ssh user@host` example. Host defaults to whatever the browser used to
    # reach us, with port stripped.
    ssh_host = os.environ.get('SSHADMIN_SSH_PUBLIC_HOST') or request.host.split(':')[0]
    ssh_port = int(os.environ.get('SSHADMIN_SSH_PORT', '2222'))
    ssh_available = os.environ.get('SSHADMIN_DISABLE_SSH_AUTH', '0') != '1'

    return render_template(
        'auth_await.html',
        challenge=challenge,
        one_liner=one_liner,
        one_liner_url=one_liner_url,
        purpose=challenge.purpose,
        username=challenge.user.username,
        totp_available=totp_available,
        ssh_available=ssh_available,
        ssh_host=ssh_host,
        ssh_port=ssh_port,
    )


@app.route('/logout')
@login_required
def logout():
    """User logout"""
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))


@app.route('/dashboard')
@login_required
def dashboard():
    """Main dashboard"""
    hosts_count = Host.query.count()
    users_count = SSHUser.query.count()
    certs_count = Certificate.query.count()
    recent_certs = Certificate.query.order_by(Certificate.created_at.desc()).limit(5).all()

    return render_template('dashboard.html',
                         hosts_count=hosts_count,
                         users_count=users_count,
                         certs_count=certs_count,
                         recent_certs=recent_certs,
                         ca_configured=cert_gen.check_ca_keys())


@app.route('/hosts')
@login_required
def hosts():
    """Manage hosts. Non-admins see only hosts they own."""
    if current_user.is_admin:
        host_list = Host.query.order_by(Host.hostname).all()
    else:
        host_list = list(current_user.owned_hosts)
        host_list.sort(key=lambda h: h.hostname)
    return render_template('hosts.html', hosts=host_list, viewing_as_admin=current_user.is_admin)


@app.route('/hosts/add', methods=['GET', 'POST'])
@login_required
def add_host():
    """Add new host (issues enrollment token; host self-registers via script)"""
    if request.method == 'POST':
        hostname = (request.form.get('hostname') or '').strip()
        description = request.form.get('description')

        if not hostname:
            flash('Hostname is required', 'danger')
            return redirect(url_for('add_host'))

        existing = Host.query.filter_by(hostname=hostname).first()
        if existing:
            if existing.is_enrolled:
                flash(f'Host {hostname} is already enrolled. Re-register or delete it from here.', 'info')
                return redirect(url_for('host_info', host_id=existing.id))
            # Pending host — refresh metadata, reissue token, and resume enrollment.
            if description:
                existing.description = description
            existing.issue_enrollment_token()
            if current_user not in existing.owners:
                existing.owners.append(current_user)
            db.session.commit()
            flash(f'Host {hostname} already had a pending enrollment; a new token was issued.', 'info')
            return redirect(url_for('enroll_host', host_id=existing.id))

        host = Host(
            hostname=hostname,
            description=description,
            created_by_id=current_user.id,
        )
        host.issue_enrollment_token()
        host.owners.append(current_user)
        db.session.add(host)
        db.session.commit()

        return redirect(url_for('enroll_host', host_id=host.id))

    return render_template('add_host.html')


def _can_view_host(host):
    return current_user.is_admin or current_user in host.owners


def _can_admin_host(host):
    return current_user.is_admin or current_user in host.owners


@app.route('/hosts/<int:host_id>')
@login_required
def host_info(host_id):
    """Show registration details for an enrolled host."""
    host = Host.query.get_or_404(host_id)
    if not _can_view_host(host):
        flash('You do not have access to this host.', 'danger')
        return redirect(url_for('hosts'))
    if not host.is_enrolled:
        return redirect(url_for('enroll_host', host_id=host.id))

    fingerprint = None
    key_type = None
    if host.public_key:
        parts = host.public_key.split()
        if parts:
            key_type = parts[0]
        try:
            with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.pub') as f:
                f.write(host.public_key)
                tmp = f.name
            try:
                result = subprocess.run(
                    ['ssh-keygen', '-l', '-f', tmp],
                    capture_output=True, text=True, check=True,
                )
                fingerprint = result.stdout.strip()
            finally:
                os.unlink(tmp)
        except Exception:
            fingerprint = None

    active_certs = [c for c in host.certificates if c.valid_until > datetime.utcnow()]
    owner_ids = {o.id for o in host.owners}
    candidates = (
        User.query
        .filter(User.completed_at.isnot(None))
        .filter(~User.id.in_(owner_ids) if owner_ids else True)
        .order_by(User.username)
        .all()
    )
    return render_template(
        'host_info.html',
        host=host,
        fingerprint=fingerprint,
        key_type=key_type,
        active_certs=active_certs,
        share_candidates=candidates,
        can_admin=_can_admin_host(host),
    )


@app.route('/hosts/<int:host_id>/re-register', methods=['POST'])
@login_required
def re_register_host(host_id):
    """Invalidate an enrolled host's registration and issue a fresh enrollment token."""
    host = Host.query.get_or_404(host_id)
    if not _can_admin_host(host):
        flash('Only an owner or admin can re-register this host.', 'danger')
        return redirect(url_for('hosts'))
    host.issue_enrollment_token()
    db.session.commit()
    flash(f'Host {host.hostname} registration cleared. Run the new script on the host to re-enroll.', 'warning')
    return redirect(url_for('enroll_host', host_id=host.id))


@app.route('/hosts/<int:host_id>/share', methods=['POST'])
@login_required
def share_host(host_id):
    """Add another registered user as a co-owner of this host."""
    host = Host.query.get_or_404(host_id)
    if not _can_admin_host(host):
        flash('Only an owner or admin can share this host.', 'danger')
        return redirect(url_for('hosts'))

    target_user_id = request.form.get('user_id', type=int)
    if not target_user_id:
        flash('Pick a user to add as an owner.', 'danger')
        return redirect(url_for('host_info', host_id=host.id))

    target = db.session.get(User, target_user_id)
    if not target or target.completed_at is None:
        flash('Target user not found or has not completed registration.', 'danger')
        return redirect(url_for('host_info', host_id=host.id))

    if target in host.owners:
        flash(f'{target.username} is already an owner.', 'info')
    else:
        host.owners.append(target)
        db.session.commit()
        flash(f'{target.username} added as co-owner of {host.hostname}.', 'success')
    return redirect(url_for('host_info', host_id=host.id))


@app.route('/hosts/<int:host_id>/unshare/<int:user_id>', methods=['POST'])
@login_required
def unshare_host(host_id, user_id):
    """Remove a co-owner. Admin can remove anyone; an owner can only remove themselves."""
    host = Host.query.get_or_404(host_id)
    target = User.query.get_or_404(user_id)

    if not (current_user.is_admin or current_user.id == target.id):
        flash('You may only remove yourself as an owner; ask an admin for other changes.', 'danger')
        return redirect(url_for('host_info', host_id=host.id))

    if target not in host.owners:
        flash(f'{target.username} is not an owner of this host.', 'info')
        return redirect(url_for('host_info', host_id=host.id))

    host.owners.remove(target)
    if not host.owners:
        hostname = host.hostname
        db.session.delete(host)
        db.session.commit()
        flash(f'{hostname} had no remaining owners and was deleted.', 'info')
        return redirect(url_for('hosts'))
    db.session.commit()
    flash(f'{target.username} removed from {host.hostname} owners.', 'info')
    if target.id == current_user.id:
        return redirect(url_for('hosts'))
    return redirect(url_for('host_info', host_id=host.id))


@app.route('/hosts/<int:host_id>/enroll')
@login_required
def enroll_host(host_id):
    """Show the bash enrollment script for a pending host."""
    host = Host.query.get_or_404(host_id)

    if host.is_enrolled:
        flash(f'Host {host.hostname} is already enrolled.', 'info')
        return redirect(url_for('hosts'))

    if not host.enrollment_token or host.enrollment_expires_at < datetime.utcnow():
        host.issue_enrollment_token()
        db.session.commit()
        flash('Enrollment token expired; a new one was issued.', 'info')

    server_url = request.url_root.rstrip('/')
    script = render_template(
        'enrollment_script.sh',
        server_url=server_url,
        token=host.enrollment_token,
        hostname=host.hostname,
        key_type=ALLOWED_HOST_KEY_TYPE,
    )
    one_liner_url = (
        f"{server_url}{url_for('api_enroll_script')}"
        f"?token={host.enrollment_token}&host_id={host.id}"
    )
    one_liner = f'curl -fsSL "{one_liner_url}" | sudo bash'

    return render_template(
        'enroll_host.html',
        host=host,
        script=script,
        one_liner=one_liner,
        expires_at=host.enrollment_expires_at,
    )


@app.route('/hosts/<int:host_id>/enroll/script')
@login_required
def enroll_host_script(host_id):
    """Download the enrollment script as a .sh file."""
    host = Host.query.get_or_404(host_id)
    if host.is_enrolled or not host.enrollment_token:
        flash('No active enrollment for this host.', 'danger')
        return redirect(url_for('hosts'))

    server_url = request.url_root.rstrip('/')
    script = render_template(
        'enrollment_script.sh',
        server_url=server_url,
        token=host.enrollment_token,
        hostname=host.hostname,
        key_type=ALLOWED_HOST_KEY_TYPE,
    )
    from flask import Response
    return Response(
        script,
        mimetype='text/x-shellscript',
        headers={'Content-Disposition': f'attachment; filename=enroll-{host.hostname}.sh'},
    )


@app.route('/hosts/<int:host_id>/enroll/regenerate', methods=['POST'])
@login_required
def regenerate_enrollment(host_id):
    """Issue a fresh enrollment token for a pending host."""
    host = Host.query.get_or_404(host_id)
    if host.is_enrolled:
        flash('Host is already enrolled; cannot regenerate token.', 'danger')
        return redirect(url_for('hosts'))
    host.issue_enrollment_token()
    db.session.commit()
    flash('New enrollment token issued.', 'success')
    return redirect(url_for('enroll_host', host_id=host.id))


@app.route('/hosts/<int:host_id>/delete', methods=['POST'])
@login_required
def delete_host(host_id):
    """Delete host.

    - Admin: wipes the host (and certs) outright.
    - Non-admin owner: removes only their ownership row; the host itself is
      deleted only when the last remaining owner removes themselves.
    """
    host = Host.query.get_or_404(host_id)
    hostname = host.hostname

    if current_user.is_admin:
        db.session.delete(host)
        db.session.commit()
        flash(f'Host {hostname} deleted (admin wipe).', 'info')
        return redirect(url_for('hosts'))

    if current_user not in host.owners:
        flash('You are not an owner of this host.', 'danger')
        return redirect(url_for('hosts'))

    host.owners.remove(current_user)
    if not host.owners:
        db.session.delete(host)
        db.session.commit()
        flash(f'{hostname} had no other owners; it was removed entirely.', 'info')
    else:
        db.session.commit()
        flash(
            f'You no longer own {hostname}. {len(host.owners)} other owner(s) still have access.',
            'info',
        )
    return redirect(url_for('hosts'))


@app.route('/users')
@login_required
def users():
    """Manage SSH users. Non-admins see only ones they created."""
    if current_user.is_admin:
        ssh_users = SSHUser.query.order_by(SSHUser.username).all()
    else:
        ssh_users = (
            SSHUser.query.filter_by(created_by_id=current_user.id)
            .order_by(SSHUser.username)
            .all()
        )
    return render_template('users.html', users=ssh_users, viewing_as_admin=current_user.is_admin)


@app.route('/users/add', methods=['GET', 'POST'])
@login_required
def add_user():
    """Add new SSH user"""
    if request.method == 'POST':
        username = request.form.get('username')
        description = request.form.get('description')
        public_key = request.form.get('public_key')
        
        if not username or not public_key:
            flash('Username and public key are required', 'danger')
            return redirect(url_for('add_user'))
        
        existing = SSHUser.query.filter_by(username=username, public_key=public_key).first()
        if existing:
            flash('SSH user with this key already exists', 'danger')
            return redirect(url_for('add_user'))
        
        user = SSHUser(
            username=username,
            description=description,
            public_key=public_key,
            created_by_id=current_user.id
        )
        db.session.add(user)
        db.session.commit()
        
        flash(f'SSH user {username} added successfully', 'success')
        return redirect(url_for('users'))
    
    return render_template('add_user.html')


@app.route('/users/<int:user_id>/delete', methods=['POST'])
@login_required
def delete_user(user_id):
    """Delete SSH user — only the creator or an admin may delete."""
    user = SSHUser.query.get_or_404(user_id)
    if not (current_user.is_admin or user.created_by_id == current_user.id):
        flash('You can only delete SSH users you created.', 'danger')
        return redirect(url_for('users'))
    username = user.username
    db.session.delete(user)
    db.session.commit()
    flash(f'SSH user {username} deleted', 'info')
    return redirect(url_for('users'))


@app.route('/certificates')
@login_required
def certificates():
    """View certificates. Non-admins see only ones they created."""
    q = Certificate.query.order_by(Certificate.created_at.desc())
    if not current_user.is_admin:
        q = q.filter_by(created_by_id=current_user.id)
    return render_template('certificates.html', certificates=q.all(),
                           viewing_as_admin=current_user.is_admin)


@app.route('/certificates/issue/user', methods=['GET', 'POST'])
@login_required
def issue_user_cert():
    """Issue user certificate. Non-admins can only issue for SSHUsers they created."""
    if current_user.is_admin:
        ssh_users = SSHUser.query.order_by(SSHUser.username).all()
    else:
        ssh_users = (
            SSHUser.query.filter_by(created_by_id=current_user.id)
            .order_by(SSHUser.username)
            .all()
        )
    
    if request.method == 'POST':
        user_id = request.form.get('user_id')
        valid_days = int(request.form.get('valid_days', 365))
        principals = request.form.get('principals', '').strip().split(',')
        principals = [p.strip() for p in principals if p.strip()]
        
        ssh_user = SSHUser.query.get_or_404(user_id)
        
        if not principals:
            principals = [ssh_user.username]
        
        try:
            # Create temporary file with public key
            with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.pub') as f:
                f.write(ssh_user.public_key)
                temp_key = f.name
            
            try:
                cert_data, serial = cert_gen.generate_user_certificate(
                    temp_key,
                    ssh_user.username,
                    valid_days,
                    principals
                )
                
                cert = Certificate(
                    cert_type='user',
                    user_id=ssh_user.id,
                    public_key=ssh_user.public_key,
                    serial=serial,
                    valid_from=datetime.utcnow(),
                    valid_until=datetime.utcnow() + timedelta(days=valid_days),
                    created_by_id=current_user.id,
                    certificate_data=cert_data
                )
                cert.issue_install_token()
                db.session.add(cert)
                db.session.commit()

                flash(f'User certificate issued for {ssh_user.username}', 'success')
                return redirect(url_for('cert_install', cert_id=cert.id))
            finally:
                os.unlink(temp_key)
        except Exception as e:
            flash(f'Error issuing certificate: {str(e)}', 'danger')
    
    return render_template('issue_user_cert.html', users=ssh_users)


@app.route('/certificates/issue/host', methods=['GET', 'POST'])
@login_required
def issue_host_cert():
    """Issue host certificate. Non-admins limited to hosts they own."""
    if current_user.is_admin:
        hosts = [h for h in Host.query.all() if h.is_enrolled]
    else:
        hosts = [h for h in current_user.owned_hosts if h.is_enrolled]

    if request.method == 'POST':
        host_id = request.form.get('host_id')
        valid_days = int(request.form.get('valid_days', 365))

        host = Host.query.get_or_404(host_id)

        if not host.is_enrolled:
            flash(f'Host {host.hostname} has not completed enrollment.', 'danger')
            return redirect(url_for('issue_host_cert'))

        if not _can_admin_host(host):
            flash('You can only issue certificates for hosts you own.', 'danger')
            return redirect(url_for('issue_host_cert'))
        
        try:
            with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.pub') as f:
                f.write(host.public_key)
                temp_key = f.name
            
            try:
                cert_data, serial = cert_gen.generate_host_certificate(
                    temp_key,
                    host.hostname,
                    valid_days
                )
                
                cert = Certificate(
                    cert_type='host',
                    host_id=host.id,
                    public_key=host.public_key,
                    serial=serial,
                    valid_from=datetime.utcnow(),
                    valid_until=datetime.utcnow() + timedelta(days=valid_days),
                    created_by_id=current_user.id,
                    certificate_data=cert_data
                )
                cert.issue_install_token()
                db.session.add(cert)
                db.session.commit()

                flash(f'Host certificate issued for {host.hostname}', 'success')
                return redirect(url_for('cert_install', cert_id=cert.id))
            finally:
                os.unlink(temp_key)
        except Exception as e:
            flash(f'Error issuing certificate: {str(e)}', 'danger')
    
    return render_template('issue_host_cert.html', hosts=hosts)


@app.route('/certificates/<int:cert_id>/download')
@login_required
def download_cert(cert_id):
    """Return the OpenSSH-format certificate as a file."""
    cert = Certificate.query.get_or_404(cert_id)
    if not (current_user.is_admin or cert.created_by_id == current_user.id):
        flash('You can only download certificates you issued.', 'danger')
        return redirect(url_for('certificates'))
    if not cert.certificate_data:
        flash('Certificate has no data on file.', 'danger')
        return redirect(url_for('certificates'))
    name = (cert.host.hostname if cert.cert_type == 'host' and cert.host
            else (cert.user.username if cert.user else cert.serial))
    filename = f'sshadmin-{cert.cert_type}-{name}-cert.pub'
    return Response(
        cert.certificate_data + '\n',
        mimetype='text/plain',
        headers={'Content-Disposition': f'attachment; filename={filename}'},
    )


@app.route('/certificates/<int:cert_id>/install')
@login_required
def cert_install(cert_id):
    """Show the install one-liner + manual instructions for a certificate."""
    cert = Certificate.query.get_or_404(cert_id)
    if not (current_user.is_admin or cert.created_by_id == current_user.id):
        flash('You can only install certificates you issued.', 'danger')
        return redirect(url_for('certificates'))

    if not cert.install_token or (
        cert.install_token_expires_at and cert.install_token_expires_at < datetime.utcnow()
    ):
        cert.issue_install_token()
        db.session.commit()
        flash('Install token expired; a fresh one was issued.', 'info')

    server_url = request.url_root.rstrip('/')
    install_url = (
        f"{server_url}{url_for('api_cert_install_script')}"
        f"?token={cert.install_token}"
    )
    if cert.cert_type == 'host':
        one_liner = f'curl -fsSL "{install_url}" | sudo bash'
    else:
        one_liner = f'curl -fsSL "{install_url}" | bash'

    fingerprint = None
    try:
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='-cert.pub') as f:
            f.write(cert.certificate_data or '')
            tmp = f.name
        try:
            r = subprocess.run(['ssh-keygen', '-L', '-f', tmp],
                               capture_output=True, text=True, check=True)
            fingerprint = r.stdout.strip()
        finally:
            os.unlink(tmp)
    except Exception:
        fingerprint = None

    target_name = (cert.host.hostname if cert.cert_type == 'host' and cert.host
                   else (cert.user.username if cert.user else 'unknown'))
    return render_template(
        'cert_install.html',
        cert=cert,
        one_liner=one_liner,
        install_url=install_url,
        target_name=target_name,
        fingerprint=fingerprint,
        ttl_hours=2,
    )


# ===== Public install endpoints (token-gated, no session required) =====

def _lookup_install_cert(token):
    """Returns (cert, error_response_or_None)."""
    if not token:
        return None, ('# token query parameter required\n', 400, {'Content-Type': 'text/plain'})
    cert = Certificate.query.filter_by(install_token=token).first()
    if cert is None:
        return None, ('# invalid install token\n', 404, {'Content-Type': 'text/plain'})
    if cert.install_token_expires_at and cert.install_token_expires_at < datetime.utcnow():
        return None, ('# install token expired\n', 410, {'Content-Type': 'text/plain'})
    return cert, None


@app.route('/api/cert/install/data')
def api_cert_install_data():
    """Return the certificate body in OpenSSH format. Token-gated; single-use lookup."""
    token = (request.args.get('token') or '').strip()
    cert, err = _lookup_install_cert(token)
    if err is not None:
        return err
    body = (cert.certificate_data or '').strip() + '\n'
    return Response(body, mimetype='text/plain; charset=utf-8')


@app.route('/api/cert/install/script')
def api_cert_install_script():
    """Return a bash script that installs the certificate at the right path."""
    token = (request.args.get('token') or '').strip()
    cert, err = _lookup_install_cert(token)
    if err is not None:
        return err

    target_name = (cert.host.hostname if cert.cert_type == 'host' and cert.host
                   else (cert.user.username if cert.user else 'unknown'))
    server_url = request.url_root.rstrip('/')
    script = render_template(
        'cert_install_script.sh',
        server_url=server_url,
        token=cert.install_token,
        cert_type=cert.cert_type,
        cert_pubkey_line=(cert.public_key or '').strip(),
        target_name=target_name,
    )
    return Response(script, mimetype='text/x-shellscript; charset=utf-8')


@app.route('/api/ca-status')
@login_required
def api_ca_status():
    """Check CA key status"""
    has_ca = cert_gen.check_ca_keys()
    return jsonify({'ca_available': has_ca})


# ==================== Auth (challenge/response) API ====================

@app.route('/api/auth/script')
def api_auth_script():
    """Public endpoint: returns the bash sign-and-submit script for an active challenge."""
    token = (request.args.get('token') or '').strip()
    if not token:
        return ('# token query parameter required\n', 400, {'Content-Type': 'text/plain'})

    challenge = Challenge.query.filter_by(token=token).first()
    if not challenge:
        return ('# unknown challenge token\n', 404, {'Content-Type': 'text/plain'})
    if challenge.consumed_at is not None:
        return ('# challenge already consumed\n', 409, {'Content-Type': 'text/plain'})
    if challenge.expires_at < datetime.utcnow():
        return ('# challenge expired\n', 410, {'Content-Type': 'text/plain'})

    server_url = request.url_root.rstrip('/')
    script = render_template(
        'auth_script.sh',
        server_url=server_url,
        token=challenge.token,
        nonce=challenge.nonce,
        username=challenge.user.username,
        purpose=challenge.purpose,
        public_key=challenge.user.public_key,
        sshsig_namespace=SSHSIG_NAMESPACE,
        host_key_type=ALLOWED_HOST_KEY_TYPE,
        include_host_enrollment=(challenge.purpose == 'register'),
    )
    return (script, 200, {'Content-Type': 'text/x-shellscript; charset=utf-8'})


@app.route('/api/challenge_response', methods=['POST'])
def api_challenge_response():
    """Accept a signature for an active challenge; optionally enroll host."""
    payload = request.get_json(silent=True) or request.form
    token = (payload.get('token') or '').strip()
    signature = (payload.get('signature') or '')
    hostname = (payload.get('hostname') or '').strip() or None
    host_pubkey = (payload.get('host_public_key') or '').strip() or None

    if not token or not signature:
        return jsonify({'ok': False, 'error': 'token and signature required'}), 400

    challenge = Challenge.query.filter_by(token=token).first()
    if not challenge:
        return jsonify({'ok': False, 'error': 'invalid token'}), 404
    if challenge.consumed_at is not None:
        return jsonify({'ok': False, 'error': 'challenge already used'}), 409
    if challenge.expires_at < datetime.utcnow():
        return jsonify({'ok': False, 'error': 'challenge expired'}), 410

    if not verify_sshsig(challenge.user.public_key, signature, challenge.nonce):
        return jsonify({'ok': False, 'error': 'signature verification failed'}), 403

    challenge.consumed_at = datetime.utcnow()

    _finalize_consumed_challenge(challenge)

    host_result = {'enrolled': False}
    if hostname and host_pubkey:
        host_result = _try_enroll_host_during_register(
            user=challenge.user,
            hostname=hostname,
            host_pubkey=host_pubkey,
        )

    db.session.commit()

    return jsonify({
        'ok': True,
        'purpose': challenge.purpose,
        'username': challenge.user.username,
        'host': host_result,
    })


def _pubkey_match(a, b):
    """Compare just the algorithm + base64 parts (ignore comments) of two SSH pubkeys."""
    pa = (a or '').split()
    pb = (b or '').split()
    return len(pa) >= 2 and len(pb) >= 2 and pa[0] == pb[0] and pa[1] == pb[1]


def _finalize_consumed_challenge(challenge):
    """Apply post-consume side effects of a registration challenge.

    Caller must have already set `challenge.consumed_at` and ensured the
    consumer was authorized. This function is a no-op for login challenges.
    Caller is responsible for db.session.commit().
    """
    if challenge.purpose != 'register':
        return
    if challenge.user.completed_at is not None:
        return

    # Promote the first completed user to admin.
    existing_admin = (
        User.query
        .filter(User.completed_at.isnot(None), User.is_admin == True)  # noqa: E712
        .first()
    )
    if existing_admin is None:
        challenge.user.is_admin = True
    challenge.user.completed_at = datetime.utcnow()

    # Auto-create an SSHUser identity from the registration data so the
    # new login user can immediately be issued certificates without a
    # separate /users/add step.
    already = SSHUser.query.filter_by(
        username=challenge.user.username,
        public_key=challenge.user.public_key,
    ).first()
    if already is None:
        db.session.add(SSHUser(
            username=challenge.user.username,
            public_key=challenge.user.public_key,
            description='Auto-created at registration',
            created_by_id=challenge.user.id,
        ))


def _try_enroll_host_during_register(user, hostname, host_pubkey):
    """Best-effort host enrollment as part of registration.

    - Same hostname + same pubkey → add `user` as co-owner (implicit share).
    - Same hostname + different pubkey → refuse (409-equivalent: enrolled=False).
    - Pending host → promote to enrolled and add `user` as owner.
    - New hostname → create + add `user` as owner.
    """
    if not host_pubkey.startswith(ALLOWED_HOST_KEY_TYPE + ' '):
        return {'enrolled': False, 'reason': f'host key must be {ALLOWED_HOST_KEY_TYPE}'}

    existing = Host.query.filter_by(hostname=hostname).first()
    if existing is not None:
        if existing.is_enrolled:
            if _pubkey_match(existing.public_key, host_pubkey):
                if user not in existing.owners:
                    existing.owners.append(user)
                    return {'enrolled': True, 'hostname': hostname, 'shared': True}
                return {'enrolled': True, 'hostname': hostname, 'already_owner': True}
            return {
                'enrolled': False,
                'reason': 'hostname already enrolled with a different public key',
            }
        existing.public_key = host_pubkey
        existing.enrolled_at = datetime.utcnow()
        existing.enrollment_token = None
        existing.enrollment_expires_at = None
        if user not in existing.owners:
            existing.owners.append(user)
        return {'enrolled': True, 'hostname': hostname, 'reused_pending': True}

    host = Host(
        hostname=hostname,
        public_key=host_pubkey,
        enrolled_at=datetime.utcnow(),
        created_by_id=user.id,
    )
    host.owners.append(user)
    db.session.add(host)
    return {'enrolled': True, 'hostname': hostname, 'reused_pending': False}


@app.route('/api/totp_response', methods=['POST'])
def api_totp_response():
    """Alternate path for login challenges: validate a TOTP code instead of a signature."""
    payload = request.get_json(silent=True) or request.form
    token = (payload.get('token') or '').strip()
    code = (payload.get('code') or '').strip()

    if not token or not code:
        return jsonify({'ok': False, 'error': 'token and code required'}), 400

    challenge = Challenge.query.filter_by(token=token).first()
    if not challenge:
        return jsonify({'ok': False, 'error': 'invalid token'}), 404
    if challenge.consumed_at is not None:
        return jsonify({'ok': False, 'error': 'challenge already used'}), 409
    if challenge.expires_at < datetime.utcnow():
        return jsonify({'ok': False, 'error': 'challenge expired'}), 410
    if challenge.purpose != 'login':
        # TOTP cannot be used to register — TOTP isn't enrolled until *after* registration.
        return jsonify({'ok': False, 'error': 'TOTP can only be used for login'}), 403

    user = challenge.user
    if not user.totp_enabled or not user.totp_secret:
        return jsonify({'ok': False, 'error': 'TOTP is not enabled for this user'}), 403

    totp = pyotp.TOTP(user.totp_secret)
    if not totp.verify(code, valid_window=1):
        return jsonify({'ok': False, 'error': 'invalid code'}), 403

    challenge.consumed_at = datetime.utcnow()
    db.session.commit()
    return jsonify({'ok': True, 'username': user.username})


@app.route('/api/auth_status/<token>')
def api_auth_status(token):
    """Polled by the await page in the browser. Logs the user in once verified."""
    challenge = Challenge.query.filter_by(token=token).first()
    if not challenge:
        return jsonify({'status': 'unknown'}), 404

    if challenge.expires_at < datetime.utcnow() and challenge.consumed_at is None:
        return jsonify({'status': 'expired'})

    if challenge.consumed_at is None:
        return jsonify({'status': 'pending'})

    # Consumed: only the originating browser session may convert it to a login.
    if session.get('pending_challenge_token') != token:
        return jsonify({'status': 'completed_other_session'})

    user = challenge.user
    if user.completed_at is None:
        return jsonify({'status': 'pending'})

    login_user(user)
    session.pop('pending_challenge_token', None)

    # Brand-new registration → offer TOTP setup. Existing users go to dashboard.
    if challenge.purpose == 'register' and not user.totp_enabled:
        redirect_target = url_for('setup_totp')
    else:
        redirect_target = url_for('dashboard')

    return jsonify({
        'status': 'completed',
        'redirect': redirect_target,
        'is_admin': bool(user.is_admin),
    })


@app.route('/api/enroll/script')
def api_enroll_script():
    """Public token-authenticated endpoint that returns the enrollment script.

    Designed so the host operator can run the bundled one-liner:
        curl -fsSL "<url>/api/enroll/script?token=...&host_id=..." | sudo bash
    """
    token = (request.args.get('token') or '').strip()
    host_id_raw = (request.args.get('host_id') or '').strip()

    if not token:
        return ('# enrollment token required\n', 403, {'Content-Type': 'text/plain'})

    host = Host.query.filter_by(enrollment_token=token).first()
    if not host:
        return ('# invalid enrollment token\n', 403, {'Content-Type': 'text/plain'})

    if host_id_raw:
        try:
            if int(host_id_raw) != host.id:
                return ('# token/host_id mismatch\n', 403, {'Content-Type': 'text/plain'})
        except ValueError:
            return ('# invalid host_id\n', 400, {'Content-Type': 'text/plain'})

    if host.enrolled_at is not None:
        return ('# token already used\n', 409, {'Content-Type': 'text/plain'})

    if host.enrollment_expires_at is None or host.enrollment_expires_at < datetime.utcnow():
        return ('# token expired\n', 403, {'Content-Type': 'text/plain'})

    server_url = request.url_root.rstrip('/')
    script = render_template(
        'enrollment_script.sh',
        server_url=server_url,
        token=host.enrollment_token,
        hostname=host.hostname,
        key_type=ALLOWED_HOST_KEY_TYPE,
    )
    return (script, 200, {'Content-Type': 'text/x-shellscript; charset=utf-8'})


@app.route('/api/ca-pubkey')
def api_ca_pubkey():
    """Public CA public key for client trust installation."""
    if not os.path.exists(cert_gen.ca_pubkey):
        return ('CA public key not configured', 503, {'Content-Type': 'text/plain'})
    with open(cert_gen.ca_pubkey, 'r') as f:
        data = f.read()
    return (data, 200, {'Content-Type': 'text/plain; charset=utf-8'})


@app.route('/api/enroll/host', methods=['POST'])
def api_enroll_host():
    """Token-authenticated host self-enrollment. Body: {token, public_key}."""
    payload = request.get_json(silent=True) or request.form
    token = (payload.get('token') or '').strip()
    public_key = (payload.get('public_key') or '').strip()

    if not token or not public_key:
        return jsonify({'ok': False, 'error': 'token and public_key required'}), 400

    host = Host.query.filter_by(enrollment_token=token).first()
    if not host:
        return jsonify({'ok': False, 'error': 'invalid token'}), 403

    if host.enrolled_at is not None:
        return jsonify({'ok': False, 'error': 'token already used'}), 409

    if host.enrollment_expires_at is None or host.enrollment_expires_at < datetime.utcnow():
        return jsonify({'ok': False, 'error': 'token expired'}), 403

    if not public_key.startswith(ALLOWED_HOST_KEY_TYPE + ' '):
        return jsonify({
            'ok': False,
            'error': f'host key must be {ALLOWED_HOST_KEY_TYPE}',
        }), 400

    host.public_key = public_key
    host.enrolled_at = datetime.utcnow()
    host.enrollment_token = None
    host.enrollment_expires_at = None
    db.session.commit()

    return jsonify({'ok': True, 'hostname': host.hostname})


@app.errorhandler(404)
def not_found(error):
    """Handle 404 errors"""
    return render_template('404.html'), 404


@app.errorhandler(500)
def server_error(error):
    """Handle 500 errors"""
    return render_template('500.html'), 500


def _log_startup_status():
    if cert_gen.check_ca_keys():
        print(f'[sshadmin] CA configured at {cert_gen.ca_key}', flush=True)
    else:
        print(
            f'[sshadmin] WARNING: CA key not found at {cert_gen.ca_key}. '
            f'Log in as the first registered user (auto-admin) and visit /setup/ca '
            f'to generate one. Override path via SSHADMIN_CA_KEY_PATH.',
            flush=True,
        )


def _start_ssh_auth_server_if_enabled():
    """Start the SSH-based alternative auth server if not disabled."""
    if os.environ.get('SSHADMIN_DISABLE_SSH_AUTH', '0') == '1':
        return None
    port = int(os.environ.get('SSHADMIN_SSH_PORT', '2222'))
    bind = os.environ.get('SSHADMIN_SSH_BIND', '0.0.0.0')
    public_host = os.environ.get('SSHADMIN_SSH_PUBLIC_HOST', '*')
    try:
        from ssh_auth_server import start_ssh_auth_server
        sock = start_ssh_auth_server(
            app=app, db=db,
            models={'User': User, 'Challenge': Challenge},
            host=bind, port=port,
            ca_key_path=cert_gen.ca_key if cert_gen.check_ca_keys() else None,
            host_principals=['sshadmin', public_host or '*'],
        )
        actual_port = sock.getsockname()[1]
        cert_note = ' (host key signed by CA)' if cert_gen.check_ca_keys() else ''
        print(f'[sshadmin] SSH auth server listening on {bind}:{actual_port}{cert_note}', flush=True)
        return sock
    except Exception as exc:  # pragma: no cover - best-effort startup notice
        print(f'[sshadmin] WARNING: SSH auth server not started: {exc}', flush=True)
        return None


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    _log_startup_status()
    _start_ssh_auth_server_if_enabled()
    app.run(debug=True, host='0.0.0.0', port=5000, use_reloader=False)
