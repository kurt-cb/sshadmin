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
from pathlib import Path
import subprocess
import tempfile

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
    
    certificates = db.relationship('Certificate', backref='creator', lazy=True)
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


class Host(db.Model):
    """SSH host model"""
    id = db.Column(db.Integer, primary_key=True)
    hostname = db.Column(db.String(255), unique=True, nullable=False)
    description = db.Column(db.Text)
    public_key = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    created_by_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    
    creator = db.relationship('User', backref='hosts')
    certificates = db.relationship('Certificate', backref='host', lazy=True, cascade='all, delete-orphan')


class SSHUser(db.Model):
    """SSH user model"""
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


# ==================== SSH Certificate Generation ====================

class SSHCertificateGenerator:
    """Generate SSH certificates using OpenSSH format"""
    
    def __init__(self):
        self.ca_key = '/etc/ssh/ca_key'
        self.ca_pubkey = '/etc/ssh/ca_key.pub'
    
    def check_ca_keys(self):
        """Check if CA keys exist"""
        return os.path.exists(self.ca_key) and os.path.exists(self.ca_pubkey)
    
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

@app.route('/')
def index():
    """Home page"""
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))


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
        
        user = User(username=username, email=email)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        
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
                         recent_certs=recent_certs)


@app.route('/hosts')
@login_required
def hosts():
    """Manage hosts"""
    hosts = Host.query.all()
    return render_template('hosts.html', hosts=hosts)


@app.route('/hosts/add', methods=['GET', 'POST'])
@login_required
def add_host():
    """Add new host"""
    if request.method == 'POST':
        hostname = request.form.get('hostname')
        description = request.form.get('description')
        public_key = request.form.get('public_key')
        
        if not hostname or not public_key:
            flash('Hostname and public key are required', 'danger')
            return redirect(url_for('add_host'))
        
        if Host.query.filter_by(hostname=hostname).first():
            flash('Host already exists', 'danger')
            return redirect(url_for('add_host'))
        
        host = Host(
            hostname=hostname,
            description=description,
            public_key=public_key,
            created_by_id=current_user.id
        )
        db.session.add(host)
        db.session.commit()
        
        flash(f'Host {hostname} added successfully', 'success')
        return redirect(url_for('hosts'))
    
    return render_template('add_host.html')


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
    hosts = Host.query.all()
    
    if request.method == 'POST':
        host_id = request.form.get('host_id')
        valid_days = int(request.form.get('valid_days', 365))
        
        host = Host.query.get_or_404(host_id)
        
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


@app.errorhandler(404)
def not_found(error):
    """Handle 404 errors"""
    return render_template('404.html'), 404


@app.errorhandler(500)
def server_error(error):
    """Handle 500 errors"""
    return render_template('500.html'), 500


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True, host='0.0.0.0', port=5000)
