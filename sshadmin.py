"""
SSH Certificate Admin - Web-based SSH certificate management system
"""
from flask import Flask, render_template, request, jsonify, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import os
import json
import secrets
from pathlib import Path
import subprocess
import tempfile

ALLOWED_HOST_KEY_TYPE = 'ecdsa-sha2-nistp521'
ENROLLMENT_TOKEN_TTL_HOURS = 24

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///sshadmin.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize extensions
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# ==================== Database Models ====================

class User(UserMixin, db.Model):
    """Application user model"""
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


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

    creator = db.relationship('User', backref='hosts')
    certificates = db.relationship('Certificate', backref='host', lazy=True, cascade='all, delete-orphan')

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
    
    creator = db.relationship('User', backref='issued_certificates')


# ==================== Login Manager ====================

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


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
        
        valid_after = int(datetime.utcnow().timestamp())
        valid_before = int((datetime.utcnow() + timedelta(days=valid_days)).timestamp())
        
        # Certificate serial (can be any unique number)
        serial = int(datetime.utcnow().timestamp() * 1000)
        
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
            cert_path = f'{public_key_path}-cert.pub'
            
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
        
        valid_after = int(datetime.utcnow().timestamp())
        valid_before = int((datetime.utcnow() + timedelta(days=valid_days)).timestamp())
        serial = int(datetime.utcnow().timestamp() * 1000)
        
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
            cert_path = f'{public_key_path}-cert.pub'
            
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
    'login', 'logout', 'register', 'setup_ca', 'static',
    'api_ca_status', 'api_ca_pubkey',
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
    """User registration"""
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm = request.form.get('confirm')
        
        if not username or not email or not password:
            flash('Missing required fields', 'danger')
            return redirect(url_for('register'))
        
        if password != confirm:
            flash('Passwords do not match', 'danger')
            return redirect(url_for('register'))
        
        if User.query.filter_by(username=username).first():
            flash('Username already exists', 'danger')
            return redirect(url_for('register'))

        if User.query.filter_by(email=email).first():
            flash('Email already registered', 'danger')
            return redirect(url_for('register'))

        is_first_user = User.query.count() == 0
        user = User(username=username, email=email, is_admin=is_first_user)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()

        if is_first_user:
            flash('Registration successful! As the first user you have admin rights. Please log in.', 'success')
        else:
            flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    """User login"""
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password):
            login_user(user)
            return redirect(url_for('dashboard'))
        
        flash('Invalid username or password', 'danger')
    
    return render_template('login.html')


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
    """Manage hosts"""
    hosts = Host.query.all()
    return render_template('hosts.html', hosts=hosts)


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
            db.session.commit()
            flash(f'Host {hostname} already had a pending enrollment; a new token was issued.', 'info')
            return redirect(url_for('enroll_host', host_id=existing.id))

        host = Host(
            hostname=hostname,
            description=description,
            created_by_id=current_user.id,
        )
        host.issue_enrollment_token()
        db.session.add(host)
        db.session.commit()

        return redirect(url_for('enroll_host', host_id=host.id))

    return render_template('add_host.html')


@app.route('/hosts/<int:host_id>')
@login_required
def host_info(host_id):
    """Show registration details for an enrolled host."""
    host = Host.query.get_or_404(host_id)
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
    return render_template(
        'host_info.html',
        host=host,
        fingerprint=fingerprint,
        key_type=key_type,
        active_certs=active_certs,
    )


@app.route('/hosts/<int:host_id>/re-register', methods=['POST'])
@login_required
def re_register_host(host_id):
    """Invalidate an enrolled host's registration and issue a fresh enrollment token."""
    host = Host.query.get_or_404(host_id)
    host.issue_enrollment_token()
    db.session.commit()
    flash(f'Host {host.hostname} registration cleared. Run the new script on the host to re-enroll.', 'warning')
    return redirect(url_for('enroll_host', host_id=host.id))


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
    """Delete host"""
    host = Host.query.get_or_404(host_id)
    hostname = host.hostname
    db.session.delete(host)
    db.session.commit()
    
    flash(f'Host {hostname} deleted', 'info')
    return redirect(url_for('hosts'))


@app.route('/users')
@login_required
def users():
    """Manage SSH users"""
    ssh_users = SSHUser.query.all()
    return render_template('users.html', users=ssh_users)


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
    """Delete SSH user"""
    user = SSHUser.query.get_or_404(user_id)
    username = user.username
    db.session.delete(user)
    db.session.commit()
    
    flash(f'SSH user {username} deleted', 'info')
    return redirect(url_for('users'))


@app.route('/certificates')
@login_required
def certificates():
    """View all certificates"""
    certs = Certificate.query.order_by(Certificate.created_at.desc()).all()
    return render_template('certificates.html', certificates=certs)


@app.route('/certificates/issue/user', methods=['GET', 'POST'])
@login_required
def issue_user_cert():
    """Issue user certificate"""
    ssh_users = SSHUser.query.all()
    
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
                db.session.add(cert)
                db.session.commit()
                
                flash(f'User certificate issued for {ssh_user.username}', 'success')
                return redirect(url_for('certificates'))
            finally:
                os.unlink(temp_key)
        except Exception as e:
            flash(f'Error issuing certificate: {str(e)}', 'danger')
    
    return render_template('issue_user_cert.html', users=ssh_users)


@app.route('/certificates/issue/host', methods=['GET', 'POST'])
@login_required
def issue_host_cert():
    """Issue host certificate"""
    hosts = [h for h in Host.query.all() if h.is_enrolled]

    if request.method == 'POST':
        host_id = request.form.get('host_id')
        valid_days = int(request.form.get('valid_days', 365))

        host = Host.query.get_or_404(host_id)

        if not host.is_enrolled:
            flash(f'Host {host.hostname} has not completed enrollment.', 'danger')
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
                db.session.add(cert)
                db.session.commit()
                
                flash(f'Host certificate issued for {host.hostname}', 'success')
                return redirect(url_for('certificates'))
            finally:
                os.unlink(temp_key)
        except Exception as e:
            flash(f'Error issuing certificate: {str(e)}', 'danger')
    
    return render_template('issue_host_cert.html', hosts=hosts)


@app.route('/certificates/<int:cert_id>/download')
@login_required
def download_cert(cert_id):
    """Download certificate"""
    cert = Certificate.query.get_or_404(cert_id)
    # Implementation for actual file download would go here
    flash('Download functionality to be implemented', 'info')
    return redirect(url_for('certificates'))


@app.route('/api/ca-status')
@login_required
def api_ca_status():
    """Check CA key status"""
    has_ca = cert_gen.check_ca_keys()
    return jsonify({'ca_available': has_ca})


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


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    _log_startup_status()
    app.run(debug=True, host='0.0.0.0', port=5000)
