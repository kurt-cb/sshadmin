"""
SSH Certificate Admin - Web-based SSH certificate management system
"""
__version__ = '0.0.9'
from flask import Flask, render_template, request, jsonify, redirect, url_for, flash, session, Response
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from datetime import datetime, timedelta
import base64
import hashlib
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

# Default (secure) key types.  Additional types can be enabled via admin settings.
_DEFAULT_USER_KEY_TYPES = ('ecdsa-sha2-nistp521', 'ssh-ed25519', 'ecdsa-sha2-nistp384')

# All types the UI can offer as opt-in choices.
ALL_USER_KEY_TYPE_OPTIONS = [
    # (identifier,           display_label,                      secure_default)
    ('ecdsa-sha2-nistp521',  'ECDSA P-521 (recommended)',        True),
    ('ssh-ed25519',          'Ed25519 (recommended)',             True),
    ('ecdsa-sha2-nistp384',  'ECDSA P-384',                      True),
    ('ecdsa-sha2-nistp256',  'ECDSA P-256 (less secure)',         False),
    ('rsa-sha2-512',         'RSA 4096 / SHA-512',               False),
    ('rsa-sha2-256',         'RSA 2048–4096 / SHA-256',          False),
    ('ssh-rsa',              'RSA legacy (SHA-1, not recommended)', False),
]

ENROLLMENT_TOKEN_TTL_HOURS = 24
CHALLENGE_TTL_MINUTES = 30
SSHSIG_NAMESPACE = 'sshadmin'
TOTP_ISSUER = 'sshadmin'

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///sshadmin.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'


# ==================== Database Models ====================

class SSHKey(db.Model):
    """Canonical SSH public key record — both host and user keys live here."""
    __tablename__ = 'ssh_key'
    id = db.Column(db.Integer, primary_key=True)
    key_hash = db.Column(db.String(128), unique=True, nullable=False, index=True)
    key_type = db.Column(db.String(10), nullable=False)   # 'host' or 'user'
    public_key = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    certificates = db.relationship('Certificate', back_populates='ssh_key',
                                   cascade='all, delete-orphan')


class Host(db.Model):
    """SSH host managed by sshadmin."""
    id = db.Column(db.Integer, primary_key=True)
    hostname = db.Column(db.String(255), unique=True, nullable=False)
    description = db.Column(db.Text)
    host_type = db.Column(db.String(20), nullable=False, default='linux')  # 'linux' or 'windows'
    host_key_id = db.Column(db.Integer, db.ForeignKey('ssh_key.id'), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    created_by_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    enrollment_token = db.Column(db.String(64), unique=True, nullable=True, index=True)
    enrollment_expires_at = db.Column(db.DateTime, nullable=True)
    enrolled_at = db.Column(db.DateTime, nullable=True)

    host_key = db.relationship('SSHKey', foreign_keys=[host_key_id])
    creator = db.relationship('User', backref='hosts', foreign_keys=[created_by_id])
    host_users = db.relationship('HostUsers', back_populates='host',
                                 cascade='all, delete-orphan')
    aliases = db.relationship('HostAlias', back_populates='host',
                              cascade='all, delete-orphan', order_by='HostAlias.created_at')
    group_memberships = db.relationship('HostGroupMembership', back_populates='host',
                                        cascade='all, delete-orphan')

    @property
    def is_enrolled(self):
        return self.enrolled_at is not None and self.host_key_id is not None

    @property
    def public_key(self):
        return self.host_key.public_key if self.host_key else None

    @property
    def owners(self):
        return [hu.user for hu in self.host_users if hu.role == 'owner']

    @property
    def users(self):
        return [hu.user for hu in self.host_users]

    def issue_enrollment_token(self):
        self.enrollment_token = secrets.token_urlsafe(32)
        self.enrollment_expires_at = datetime.utcnow() + timedelta(hours=ENROLLMENT_TOKEN_TTL_HOURS)
        self.enrolled_at = None
        self.host_key_id = None

    @property
    def all_principals(self) -> list:
        """Hostname plus all registered aliases — used for strict-mode host certs."""
        return [self.hostname] + [a.alias for a in self.aliases]

    @property
    def active_cert(self):
        if self.host_key_id is None:
            return None
        return _latest_valid_cert_for_key(self.host_key_id)


class HostAlias(db.Model):
    """Additional hostnames/IPs for a Host, included in host cert principals (strict mode)."""
    __tablename__ = 'host_alias'
    id = db.Column(db.Integer, primary_key=True)
    host_id = db.Column(db.Integer, db.ForeignKey('host.id', ondelete='CASCADE'), nullable=False)
    alias = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    __table_args__ = (db.UniqueConstraint('host_id', 'alias', name='_host_alias_uc'),)
    host = db.relationship('Host', back_populates='aliases')


class HostUsers(db.Model):
    """Association between an sshadmin User and a Host, with an access role."""
    __tablename__ = 'host_users'
    id = db.Column(db.Integer, primary_key=True)
    host_id = db.Column(db.Integer, db.ForeignKey('host.id', ondelete='CASCADE'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'), nullable=False)
    role = db.Column(db.String(10), nullable=False, default='user')  # 'owner' or 'user'
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    __table_args__ = (db.UniqueConstraint('host_id', 'user_id', name='_host_user_uc'),)

    host = db.relationship('Host', back_populates='host_users')
    user = db.relationship('User', back_populates='host_roles')
    credentials = db.relationship('UserCredential', back_populates='host_user',
                                  cascade='all, delete-orphan')


class User(UserMixin, db.Model):
    """sshadmin account — identity proven by any registered SSH user key."""
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    completed_at = db.Column(db.DateTime, nullable=True)
    totp_secret = db.Column(db.String(64), nullable=True)
    totp_enabled = db.Column(db.Boolean, default=False, nullable=False)

    credentials = db.relationship('UserCredential', back_populates='user',
                                  cascade='all, delete-orphan')
    host_roles = db.relationship('HostUsers', back_populates='user')
    group_memberships = db.relationship('UserGroupMembership', back_populates='user',
                                        foreign_keys='UserGroupMembership.user_id',
                                        cascade='all, delete-orphan')

    @property
    def is_active(self):
        return self.completed_at is not None

    @property
    def owned_hosts(self):
        return [hu.host for hu in self.host_roles if hu.role == 'owner']


class UserCredential(db.Model):
    """An SSH user key on a specific host, owned by one sshadmin User.

    This is the unit of certificate issuance: each credential gets its own
    user certificate, valid for `unix_username` as the principal.  The private
    key lives on the host; duplicating it across machines is discouraged and
    detected at enrolment time.
    """
    __tablename__ = 'user_credential'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'), nullable=False)
    user_key_id = db.Column(db.Integer, db.ForeignKey('ssh_key.id'), nullable=False)
    host_user_id = db.Column(db.Integer,
                             db.ForeignKey('host_users.id', ondelete='CASCADE'), nullable=False)
    unix_username = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship('User', back_populates='credentials')
    user_key = db.relationship('SSHKey', foreign_keys=[user_key_id])
    host_user = db.relationship('HostUsers', back_populates='credentials')

    @property
    def host(self):
        return self.host_user.host

    @property
    def role(self):
        return self.host_user.role

    @property
    def active_cert(self):
        return _latest_valid_cert_for_key(self.user_key_id)


class Certificate(db.Model):
    """Issued SSH certificate (user or host); cert_type derived from ssh_key.key_type."""
    id = db.Column(db.Integer, primary_key=True)
    ssh_key_id = db.Column(db.Integer, db.ForeignKey('ssh_key.id'), nullable=False)
    serial = db.Column(db.String(255), nullable=False, unique=True)
    valid_from = db.Column(db.DateTime, nullable=False)
    valid_until = db.Column(db.DateTime, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    created_by_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    certificate_data = db.Column(db.Text)
    install_token = db.Column(db.String(64), unique=True, nullable=True, index=True)
    install_token_expires_at = db.Column(db.DateTime, nullable=True)

    ssh_key = db.relationship('SSHKey', back_populates='certificates')
    creator = db.relationship('User', backref='issued_certificates')

    @property
    def cert_type(self):
        return self.ssh_key.key_type if self.ssh_key else None

    @property
    def host(self):
        if self.ssh_key and self.ssh_key.key_type == 'host':
            return Host.query.filter_by(host_key_id=self.ssh_key_id).first()
        return None

    @property
    def credential(self):
        if self.ssh_key and self.ssh_key.key_type == 'user':
            return UserCredential.query.filter_by(user_key_id=self.ssh_key_id).first()
        return None

    @property
    def public_key(self):
        return self.ssh_key.public_key if self.ssh_key else None

    def issue_install_token(self, ttl_hours=2):
        self.install_token = secrets.token_urlsafe(32)
        self.install_token_expires_at = datetime.utcnow() + timedelta(hours=ttl_hours)


class Challenge(db.Model):
    """One-time challenge for register-or-login flows."""
    id = db.Column(db.Integer, primary_key=True)
    token = db.Column(db.String(64), unique=True, nullable=False, index=True)
    nonce = db.Column(db.String(128), nullable=False)
    purpose = db.Column(db.String(20), nullable=False)   # 'register' or 'login'
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    # Registration-only fields (null for login challenges)
    expected_key = db.Column(db.Text, nullable=True)     # public key to verify the signature
    unix_username = db.Column(db.String(255), nullable=True)  # OS username on the host
    # Set after successful verification to record which credential was used
    credential_id = db.Column(db.Integer, db.ForeignKey('user_credential.id'), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=False)
    consumed_at = db.Column(db.DateTime, nullable=True)

    user = db.relationship('User', backref='challenges')
    credential = db.relationship('UserCredential')

    @property
    def is_active(self):
        return self.consumed_at is None and self.expires_at > datetime.utcnow()


class CAGroup(db.Model):
    """A named CA group.  Machines in the group trust this group's CA for user certs.
    In simple mode (multi_group_enabled=False) only the 'default' group exists and
    all users/hosts belong to it automatically — behaviour is identical to pre-group
    operation.  In multi-group mode each group has its own CA keypair so a user cert
    from Group A is cryptographically rejected by a machine that only trusts Group B.
    """
    __tablename__ = 'ca_group'
    id            = db.Column(db.Integer, primary_key=True)
    name          = db.Column(db.String(80), unique=True, nullable=False)
    description   = db.Column(db.Text, nullable=True)
    # Path to the group's private CA key.  None → use the main site CA key.
    ca_key_path   = db.Column(db.String(255), nullable=True)
    created_at    = db.Column(db.DateTime, default=datetime.utcnow)
    created_by_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)

    created_by      = db.relationship('User', foreign_keys=[created_by_id])
    host_memberships = db.relationship('HostGroupMembership', back_populates='group',
                                       cascade='all, delete-orphan')
    user_memberships = db.relationship('UserGroupMembership', back_populates='group',
                                       cascade='all, delete-orphan')

    @property
    def is_default(self):
        return self.name == 'default'

    @property
    def effective_ca_key(self):
        """Private key path used to sign certs for this group."""
        return self.ca_key_path or os.environ.get('SSH_CA_KEY', '/etc/ssh/ca_key')

    @property
    def ca_pubkey_data(self):
        pub = self.effective_ca_key + '.pub'
        if os.path.exists(pub):
            with open(pub) as f:
                return f.read().strip()
        return None

    @property
    def active_user_count(self):
        return sum(1 for m in self.user_memberships if m.status == 'active')

    @property
    def active_host_count(self):
        return sum(1 for m in self.host_memberships if m.status == 'active')

    @property
    def pending_user_count(self):
        return sum(1 for m in self.user_memberships if m.status == 'pending')

    @property
    def pending_host_count(self):
        return sum(1 for m in self.host_memberships if m.status == 'pending')


class HostGroupMembership(db.Model):
    """A host's participation in a CA group.
    Active membership means the host's sshd TrustedUserCAKeys includes this group's CA.
    """
    __tablename__ = 'host_group_membership'
    id            = db.Column(db.Integer, primary_key=True)
    host_id       = db.Column(db.Integer, db.ForeignKey('host.id',     ondelete='CASCADE'), nullable=False)
    group_id      = db.Column(db.Integer, db.ForeignKey('ca_group.id', ondelete='CASCADE'), nullable=False)
    status        = db.Column(db.String(20), nullable=False, default='active')  # 'pending' | 'active'
    created_at    = db.Column(db.DateTime, default=datetime.utcnow)
    approved_by_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)

    __table_args__ = (db.UniqueConstraint('host_id', 'group_id', name='_host_group_uc'),)

    host        = db.relationship('Host',    back_populates='group_memberships')
    group       = db.relationship('CAGroup', back_populates='host_memberships')
    approved_by = db.relationship('User',    foreign_keys=[approved_by_id])


class UserGroupMembership(db.Model):
    """A user's membership in a CA group, with an approval workflow.
    When active, the user can obtain a cert signed by the group's CA, granting
    access to all machines in that group (subject to unix_principals restrictions).
    """
    __tablename__ = 'user_group_membership'
    id              = db.Column(db.Integer, primary_key=True)
    user_id         = db.Column(db.Integer, db.ForeignKey('user.id',     ondelete='CASCADE'), nullable=False)
    group_id        = db.Column(db.Integer, db.ForeignKey('ca_group.id', ondelete='CASCADE'), nullable=False)
    status          = db.Column(db.String(20), nullable=False, default='pending')  # 'pending'|'active'|'rejected'
    # Comma-separated unix account names this cert may be used for.
    # Empty / None → use the sshadmin username only.
    unix_principals = db.Column(db.Text, nullable=True)
    requested_at    = db.Column(db.DateTime, default=datetime.utcnow)
    approved_at     = db.Column(db.DateTime, nullable=True)
    approved_by_id  = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)

    __table_args__ = (db.UniqueConstraint('user_id', 'group_id', name='_user_group_uc'),)

    user        = db.relationship('User',    back_populates='group_memberships', foreign_keys=[user_id])
    group       = db.relationship('CAGroup', back_populates='user_memberships')
    approved_by = db.relationship('User',    foreign_keys=[approved_by_id])

    @property
    def principals_list(self):
        if not self.unix_principals:
            return [self.user.username]
        return [p.strip() for p in self.unix_principals.split(',') if p.strip()]


class SiteConfig(db.Model):
    """Persistent key-value store for admin-configurable site settings."""
    __tablename__ = 'site_config'
    key   = db.Column(db.String(64), primary_key=True)
    value = db.Column(db.Text, nullable=False, default='')


# ==================== Login Manager ====================

@login_manager.user_loader
def load_user(user_id):
    user = User.query.get(int(user_id))
    if user is None or user.completed_at is None:
        return None
    return user


# ==================== Helpers ====================

def get_allowed_user_key_types() -> tuple:
    """Return the tuple of currently-allowed SSH user key type identifiers.

    Reads from SiteConfig; falls back to the secure defaults if not configured.
    """
    try:
        cfg = db.session.get(SiteConfig, 'allowed_user_key_types')
        if cfg and cfg.value.strip():
            return tuple(t.strip() for t in cfg.value.split(',') if t.strip())
    except Exception:
        pass
    return _DEFAULT_USER_KEY_TYPES


def get_strict_host_principals() -> bool:
    """Return True when host certs must list all registered aliases as principals.

    When False (default), host certs are issued without a -n flag, making them
    valid for any hostname (wildcard). The CA key remains the security boundary.
    """
    try:
        cfg = db.session.get(SiteConfig, 'strict_host_principals')
        return cfg is not None and cfg.value == '1'
    except Exception:
        return False


def get_multi_group_enabled() -> bool:
    """Return True when multi-CA-group mode is enabled by the admin."""
    try:
        cfg = db.session.get(SiteConfig, 'multi_group_enabled')
        return cfg is not None and cfg.value == '1'
    except Exception:
        return False


def _ensure_default_group():
    """Idempotently create the 'default' CA group and enrol all existing users/hosts."""
    try:
        with app.app_context():
            existing = CAGroup.query.filter_by(name='default').first()
            if not existing:
                group = CAGroup(
                    name='default',
                    description=(
                        'Default group — all users and hosts are members automatically. '
                        'Certs are signed by the main site CA.'
                    ),
                )
                db.session.add(group)
                db.session.flush()

            default_group = CAGroup.query.filter_by(name='default').first()
            if default_group:
                for u in User.query.filter(User.completed_at.isnot(None)).all():
                    _ensure_user_in_group(u.id, default_group.id, auto_approve=True)
                for h in Host.query.filter(Host.enrolled_at.isnot(None)).all():
                    _ensure_host_in_group(h.id, default_group.id)
                db.session.commit()
    except Exception as exc:
        app.logger.warning('_ensure_default_group: %s', exc)


def _ensure_user_in_group(user_id: int, group_id: int, auto_approve: bool = False):
    """Add user to group if not already a member; return the membership row."""
    m = UserGroupMembership.query.filter_by(user_id=user_id, group_id=group_id).first()
    if not m:
        m = UserGroupMembership(
            user_id=user_id, group_id=group_id,
            status='active' if auto_approve else 'pending',
            approved_at=datetime.utcnow() if auto_approve else None,
        )
        db.session.add(m)
    return m


def _ensure_host_in_group(host_id: int, group_id: int):
    """Add host to group if not already a member; return the membership row."""
    m = HostGroupMembership.query.filter_by(host_id=host_id, group_id=group_id).first()
    if not m:
        m = HostGroupMembership(host_id=host_id, group_id=group_id, status='active')
        db.session.add(m)
    return m


def _get_user_cert_ca_key(user_id: int) -> str:
    """Return the CA key path to use when signing a user cert.

    Simple mode  → always the main site CA.
    Multi-group  → the CA key of the user's first active group membership.
                   Falls back to the main CA if the user somehow has none.
    """
    if not get_multi_group_enabled():
        return cert_gen.ca_key
    m = (UserGroupMembership.query
         .filter_by(user_id=user_id, status='active')
         .join(CAGroup)
         .first())
    if m:
        return m.group.effective_ca_key
    return cert_gen.ca_key


def _pending_group_request_count() -> int:
    """Total pending user-group membership requests visible to current user."""
    if not current_user.is_authenticated:
        return 0
    try:
        if current_user.is_admin:
            return UserGroupMembership.query.filter_by(status='pending').count()
        # Group owners see pending requests for groups they created
        owned = CAGroup.query.filter_by(created_by_id=current_user.id).all()
        total = 0
        for g in owned:
            total += sum(1 for m in g.user_memberships if m.status == 'pending')
            total += sum(1 for m in g.host_memberships if m.status == 'pending')
        return total
    except Exception:
        return 0


def _get_or_create_host_alias(host_id: int, alias: str) -> 'HostAlias':
    """Add alias to host if not already present; returns the HostAlias row."""
    alias = alias.strip()
    existing = HostAlias.query.filter_by(host_id=host_id, alias=alias).first()
    if existing:
        return existing
    ha = HostAlias(host_id=host_id, alias=alias)
    db.session.add(ha)
    return ha


def _pubkey_hash(pubkey: str) -> str:
    """SHA-256 fingerprint of an SSH public key (matches ssh-keygen -l -E sha256 format)."""
    parts = (pubkey or '').strip().split()
    if len(parts) < 2:
        return ''
    try:
        key_bytes = base64.b64decode(parts[1])
        digest = hashlib.sha256(key_bytes).digest()
        return 'SHA256:' + base64.b64encode(digest).decode().rstrip('=')
    except Exception:
        return ''


def _pubkey_match(a: str, b: str) -> bool:
    """Compare just the algorithm + base64 parts of two SSH public keys."""
    pa = (a or '').split()
    pb = (b or '').split()
    return len(pa) >= 2 and len(pb) >= 2 and pa[0] == pb[0] and pa[1] == pb[1]


def _normalize_pubkey(pubkey: str) -> str:
    """Return 'algorithm base64' (drop comment)."""
    parts = (pubkey or '').split()
    return ' '.join(parts[:2]) if len(parts) >= 2 else ''


def _get_or_create_ssh_key(pubkey: str, key_type: str) -> 'SSHKey':
    """Return existing SSHKey by fingerprint or create one. Does not flush/commit."""
    norm = _normalize_pubkey(pubkey)
    h = _pubkey_hash(norm)
    key = SSHKey.query.filter_by(key_hash=h).first()
    if key is None:
        key = SSHKey(key_hash=h, key_type=key_type, public_key=norm)
        db.session.add(key)
    return key


def _get_or_create_host_user(host_id: int, user_id: int, role: str) -> 'HostUsers':
    """Return existing HostUsers row or create one. Upgrades 'user' → 'owner' if needed."""
    hu = HostUsers.query.filter_by(host_id=host_id, user_id=user_id).first()
    if hu is None:
        hu = HostUsers(host_id=host_id, user_id=user_id, role=role)
        db.session.add(hu)
    elif role == 'owner' and hu.role != 'owner':
        hu.role = 'owner'
    return hu


def _latest_valid_cert_for_key(ssh_key_id: int) -> 'Certificate | None':
    """Most recent still-valid certificate for the given SSHKey id."""
    return (Certificate.query
            .filter_by(ssh_key_id=ssh_key_id)
            .filter(Certificate.valid_until > datetime.utcnow())
            .order_by(Certificate.created_at.desc())
            .first())


def verify_sshsig(public_key, signature_armor, message,
                  identity='user', namespace=SSHSIG_NAMESPACE):
    """Verify an SSHSIG-format signature using `ssh-keygen -Y verify`."""
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
                 '-f', allowed_signers, '-I', identity,
                 '-n', namespace, '-s', sig_path],
                input=message, capture_output=True, text=True, timeout=10,
            )
        except Exception:
            return False
        return result.returncode == 0


def _new_challenge(user, purpose, expected_key=None, unix_username=None):
    """Create + persist a fresh Challenge. Caller must commit."""
    challenge = Challenge(
        token=secrets.token_urlsafe(32),
        nonce=secrets.token_hex(32),
        purpose=purpose,
        user_id=user.id,
        expected_key=expected_key,
        unix_username=unix_username,
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
    """Generate SSH certificates using OpenSSH format."""

    def __init__(self):
        self.ca_key = os.environ.get('SSH_CA_KEY', '/etc/ssh/ca_key')
        self.ca_pubkey = self.ca_key + '.pub'

    def check_ca_keys(self):
        return os.path.exists(self.ca_key) and os.path.exists(self.ca_pubkey)

    def generate_ca(self, key_type='ecdsa', bits=521, comment='sshadmin CA'):
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
        with open(self.ca_pubkey) as f:
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

    def generate_user_certificate(self, public_key_path, username, valid_days=365,
                                   principals=None, critical_options=None,
                                   ca_key_override=None):
        if principals is None:
            principals = [username]
        signing_key = ca_key_override or self.ca_key
        serial = int(datetime.now().timestamp() * 1000)
        cmd = [
            'ssh-keygen', '-s', signing_key,
            '-I', f'{username}-{serial}',
            '-n', ','.join(principals),
            '-V', f'always:+{valid_days}d',
            '-z', str(serial),
        ]
        if critical_options:
            src = critical_options.get('source-address', '').strip()
            cmd_opt = critical_options.get('force-command', '').strip()
            if src:
                cmd += ['-O', f'source-address={src}']
            if cmd_opt:
                cmd += ['-O', f'force-command={cmd_opt}']
        cmd.append(public_key_path)
        try:
            subprocess.run(cmd, capture_output=True, text=True, check=True)
            base = public_key_path[:-4] if public_key_path.endswith('.pub') else public_key_path
            cert_path = f'{base}-cert.pub'
            if os.path.exists(cert_path):
                with open(cert_path) as f:
                    cert_data = f.read().strip()
                os.remove(cert_path)
                return cert_data, str(serial)
            raise Exception('Certificate generation failed')
        except subprocess.CalledProcessError as e:
            raise Exception(f'ssh-keygen error: {e.stderr}')

    def generate_host_certificate(self, public_key_path, hostnames, valid_days=365):
        if isinstance(hostnames, str):
            hostnames = [hostnames]
        serial = int(datetime.now().timestamp() * 1000)
        cmd = [
            'ssh-keygen', '-s', self.ca_key, '-h',
            '-I', f'host-{serial}',
            '-V', f'always:+{valid_days}d',
            '-z', str(serial),
        ]
        if hostnames:
            cmd += ['-n', ','.join(hostnames)]
        cmd.append(public_key_path)
        try:
            subprocess.run(cmd, capture_output=True, text=True, check=True)
            base = public_key_path[:-4] if public_key_path.endswith('.pub') else public_key_path
            cert_path = f'{base}-cert.pub'
            if os.path.exists(cert_path):
                with open(cert_path) as f:
                    cert_data = f.read().strip()
                os.remove(cert_path)
                return cert_data, str(serial)
            raise Exception('Certificate generation failed')
        except subprocess.CalledProcessError as e:
            raise Exception(f'ssh-keygen error: {e.stderr}')


cert_gen = SSHCertificateGenerator()


# ==================== Routes ====================

_CA_SETUP_ALLOWED_ENDPOINTS = {
    'login', 'logout', 'register', 'setup_ca', 'setup_totp', 'static',
    'auth_await',
    'api_ca_status', 'api_ca_pubkey',
    'api_auth_script', 'api_auth_status', 'api_challenge_response',
    'api_totp_response',
    'api_enroll_script', 'api_enroll_ps1_script', 'api_enroll_host',
    'api_cert_install_data', 'api_cert_install_script',
    'api_cert_user', 'api_cert_host',
    'download_sshadmin_add', 'download_sshadmin_ps1',
    'help_index', 'help_key_concepts', 'help_security_model', 'help_groups',
    'initial_setup',
}


def _needs_initial_setup() -> bool:
    """True when CA is not yet configured and no user has completed registration.

    Both conditions together identify a genuine fresh install.  If the CA is
    missing *after* users exist, that is an operational error handled separately
    by _redirect_admin_to_setup_when_ca_missing.
    """
    if cert_gen.check_ca_keys():
        return False
    try:
        return db.session.query(User.id).filter(User.completed_at.isnot(None)).first() is None
    except Exception:
        return False


@app.before_request
def _redirect_to_initial_setup():
    """On a fresh install, redirect admin/dashboard traffic to the setup wizard.

    Registration and API endpoints are allowed through so that tests without
    a CA fixture and users who navigate directly to /register still work.
    The register.html template hides CA-pubkey commands when no CA is configured,
    so registration itself never fails due to a missing CA.
    """
    if request.endpoint in _CA_SETUP_ALLOWED_ENDPOINTS:
        return
    if _needs_initial_setup():
        return redirect(url_for('initial_setup'))


@app.before_request
def _redirect_admin_to_setup_when_ca_missing():
    if cert_gen.check_ca_keys():
        return
    if not current_user.is_authenticated:
        return
    if request.endpoint in _CA_SETUP_ALLOWED_ENDPOINTS:
        return
    if not getattr(current_user, 'is_admin', False):
        return
    return redirect(url_for('setup_ca'))


@app.context_processor
def inject_globals():
    return {
        'pending_group_requests': _pending_group_request_count(),
        'multi_group_enabled': get_multi_group_enabled(),
    }


@app.context_processor
def inject_version():
    return {'app_version': __version__}


@app.template_filter('reltime')
def reltime_filter(dt):
    """Render a future datetime as a human-readable relative duration (e.g. '3h', '45d', '1.2y')."""
    if dt is None:
        return '—'
    secs = (dt - datetime.utcnow()).total_seconds()
    if secs < 0:
        return 'expired'
    if secs < 3600:
        return f'{int(secs / 60)}m'
    if secs < 86400:
        return f'{int(secs / 3600)}h'
    if secs < 365.25 * 86400:
        return f'{int(secs / 86400)}d'
    return f'{secs / (365.25 * 86400):.1f}y'


@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))


@app.route('/setup', methods=['GET', 'POST'])
def initial_setup():
    """First-time setup wizard: configure the CA before any user can register."""
    if not _needs_initial_setup():
        return redirect(url_for('register'))
    if request.method == 'POST':
        comment = (request.form.get('comment') or 'sshadmin CA').strip()
        key_type = (request.form.get('key_type') or 'ecdsa').strip()
        bits_raw = (request.form.get('bits') or '521').strip()
        try:
            bits = int(bits_raw)
        except ValueError:
            flash('Bits must be a number.', 'danger')
            return redirect(url_for('initial_setup'))
        valid_combos = {'ecdsa': {256, 384, 521}, 'rsa': {2048, 3072, 4096}, 'ed25519': {0}}
        if key_type not in valid_combos:
            flash(f'Unsupported key type: {key_type}', 'danger')
            return redirect(url_for('initial_setup'))
        if key_type != 'ed25519' and bits not in valid_combos[key_type]:
            flash(f'Invalid bit length for {key_type}.', 'danger')
            return redirect(url_for('initial_setup'))
        try:
            cert_gen.generate_ca(key_type=key_type, bits=bits, comment=comment)
        except Exception as exc:
            flash(f'CA generation failed: {exc}', 'danger')
            return redirect(url_for('initial_setup'))
        flash('CA configured. Register your administrator account below.', 'success')
        return redirect(url_for('register'))
    return render_template('initial_setup.html', ca_key_path=cert_gen.ca_key)


@app.route('/setup/ca', methods=['GET', 'POST'])
@admin_required
def setup_ca():
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
        valid_combos = {'ecdsa': {256, 384, 521}, 'rsa': {2048, 3072, 4096}, 'ed25519': {0}}
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
    img = qrcode.make(uri, image_factory=qrcode.image.svg.SvgPathImage)
    buf = io.BytesIO()
    img.save(buf)
    return buf.getvalue().decode()


@app.route('/setup/totp', methods=['GET', 'POST'])
@login_required
def setup_totp():
    if request.method == 'POST':
        action = (request.form.get('action') or 'verify').strip()
        if action == 'skip':
            session.pop('pending_totp_secret', None)
            flash('TOTP setup skipped.', 'info')
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
            flash('Code did not match. Try again.', 'danger')
            return redirect(url_for('setup_totp'))
        current_user.totp_secret = secret
        current_user.totp_enabled = True
        db.session.commit()
        session.pop('pending_totp_secret', None)
        flash('TOTP enabled.', 'success')
        return redirect(url_for('dashboard'))
    if current_user.totp_enabled:
        flash('TOTP is already enabled. Disable it first to re-enroll.', 'info')
        return redirect(url_for('profile'))
    secret = session.get('pending_totp_secret')
    if not secret:
        secret = pyotp.random_base32()
        session['pending_totp_secret'] = secret
    uri = pyotp.totp.TOTP(secret).provisioning_uri(
        name=current_user.username, issuer_name=TOTP_ISSUER)
    return render_template('setup_totp.html', secret=secret,
                           qr_svg=_generate_totp_qr_svg(uri),
                           otpauth_uri=uri, issuer=TOTP_ISSUER)


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
    ca_present = cert_gen.check_ca_keys()
    ca_pubkey = cert_gen.read_ca_pubkey() if ca_present else None
    fingerprint = cert_gen.ca_fingerprint() if ca_present else None
    ca_key_type = ca_pubkey.split()[0] if ca_pubkey else None
    counts = {
        'hosts': Host.query.count(),
        'enrolled_hosts': Host.query.filter(Host.enrolled_at.isnot(None)).count(),
        'credentials': UserCredential.query.count(),
        'certificates': Certificate.query.count(),
        'app_users': User.query.count(),
    }
    return render_template(
        'server_config.html',
        ca_present=ca_present, ca_pubkey=ca_pubkey,
        ca_fingerprint=fingerprint, ca_key_type=ca_key_type,
        ca_key_path=cert_gen.ca_key, ca_pubkey_path=cert_gen.ca_pubkey,
        server_url=request.url_root.rstrip('/'), counts=counts,
    )


@app.route('/register', methods=['GET', 'POST'])
def register():
    """User registration.

    Collects: sshadmin username, Unix username (OS user on their machine),
    and SSH public key.  The Unix username is the login name that will appear
    in the user certificate principal — it is distinct from the sshadmin
    account name.
    """
    if request.method == 'POST':
        username = (request.form.get('username') or '').strip()
        unix_username = (request.form.get('unix_username') or '').strip()
        public_key = (request.form.get('public_key') or '').strip()

        if not username or not unix_username or not public_key:
            flash('Account name, Unix username, and SSH public key are all required.', 'danger')
            return redirect(url_for('register'))

        allowed = get_allowed_user_key_types()
        parts = public_key.split()
        if len(parts) < 2 or parts[0] not in allowed:
            flash(
                f'Public key must be one of: {", ".join(allowed)}.',
                'danger',
            )
            return redirect(url_for('register'))

        existing = User.query.filter_by(username=username).first()
        if existing and existing.completed_at is not None:
            flash('Username already registered.', 'danger')
            return redirect(url_for('register'))

        if existing and existing.completed_at is None:
            user = existing
        else:
            user = User(username=username)
            db.session.add(user)
            db.session.flush()

        challenge = _new_challenge(user, 'register',
                                   expected_key=public_key,
                                   unix_username=unix_username)
        db.session.commit()
        session['pending_challenge_token'] = challenge.token
        return redirect(url_for('auth_await', token=challenge.token))

    allowed = get_allowed_user_key_types()
    ssh_port = app.config.get('SSHADMIN_SSH_PORT', os.environ.get('SSHADMIN_SSH_PORT', '2222'))
    ssh_host = request.host.split(':')[0]
    return render_template('register.html', allowed_key_types=allowed,
                           all_key_type_options=ALL_USER_KEY_TYPE_OPTIONS,
                           ssh_port=ssh_port, sshadmin_host=ssh_host,
                           ca_configured=cert_gen.check_ca_keys())


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = (request.form.get('username') or '').strip()
        if not username:
            flash('Username is required.', 'danger')
            return redirect(url_for('login'))
        user = User.query.filter_by(username=username).first()
        if not user or user.completed_at is None:
            flash('No completed registration for that username.', 'danger')
            return redirect(url_for('login'))
        challenge = _new_challenge(user, 'login')
        db.session.commit()
        session['pending_challenge_token'] = challenge.token
        return redirect(url_for('auth_await', token=challenge.token))
    return render_template('login.html')


@app.route('/auth/await/<token>')
def auth_await(token):
    challenge = Challenge.query.filter_by(token=token).first_or_404()
    server_url = request.url_root.rstrip('/')
    one_liner_url = f"{server_url}{url_for('api_auth_script')}?token={challenge.token}"
    if challenge.purpose == 'register':
        one_liner = f'curl -fsSL "{one_liner_url}" | sudo bash'
    else:
        one_liner = f'curl -fsSL "{one_liner_url}" | bash'
    totp_available = challenge.purpose == 'login' and challenge.user.totp_enabled
    ssh_host = os.environ.get('SSHADMIN_SSH_PUBLIC_HOST') or request.host.split(':')[0]
    ssh_port = int(os.environ.get('SSHADMIN_SSH_PORT', '2222'))
    ssh_available = os.environ.get('SSHADMIN_DISABLE_SSH_AUTH', '0') != '1'
    return render_template(
        'auth_await.html',
        challenge=challenge, one_liner=one_liner, one_liner_url=one_liner_url,
        purpose=challenge.purpose, username=challenge.user.username,
        totp_available=totp_available,
        ssh_available=ssh_available, ssh_host=ssh_host, ssh_port=ssh_port,
    )


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))


@app.route('/dashboard')
@login_required
def dashboard():
    hosts_count = Host.query.count()
    creds_count = UserCredential.query.count()
    certs_count = Certificate.query.count()
    recent_certs = Certificate.query.order_by(Certificate.created_at.desc()).limit(5).all()
    return render_template('dashboard.html',
                           hosts_count=hosts_count,
                           credentials_count=creds_count,
                           certs_count=certs_count,
                           recent_certs=recent_certs,
                           ca_configured=cert_gen.check_ca_keys())


# ==================== Host routes ====================

def _can_view_host(host):
    if current_user.is_admin:
        return True
    return HostUsers.query.filter_by(
        host_id=host.id, user_id=current_user.id).first() is not None


def _can_admin_host(host):
    if current_user.is_admin:
        return True
    hu = HostUsers.query.filter_by(
        host_id=host.id, user_id=current_user.id).first()
    return hu is not None and hu.role == 'owner'


@app.route('/hosts')
@login_required
def hosts():
    if current_user.is_admin:
        host_list = Host.query.order_by(Host.hostname).all()
    else:
        owned_ids = [hu.host_id for hu in current_user.host_roles]
        host_list = Host.query.filter(Host.id.in_(owned_ids)).order_by(Host.hostname).all()
    return render_template('hosts.html', hosts=host_list,
                           viewing_as_admin=current_user.is_admin)


@app.route('/hosts/add', methods=['GET', 'POST'])
@login_required
def add_host():
    if request.method == 'POST':
        hostname = (request.form.get('hostname') or '').strip()
        description = request.form.get('description')
        if not hostname:
            flash('Hostname is required', 'danger')
            return redirect(url_for('add_host'))

        existing = Host.query.filter_by(hostname=hostname).first()
        if existing:
            if existing.is_enrolled:
                flash(f'Host {hostname} is already enrolled.', 'info')
                return redirect(url_for('host_info', host_id=existing.id))
            if description:
                existing.description = description
            existing.issue_enrollment_token()
            _get_or_create_host_user(existing.id, current_user.id, 'owner')
            db.session.commit()
            flash(f'Host {hostname} already pending; new token issued.', 'info')
            return redirect(url_for('enroll_host', host_id=existing.id))

        host_type = request.form.get('host_type', 'linux')
        if host_type not in ('linux', 'windows'):
            host_type = 'linux'
        host = Host(hostname=hostname, description=description,
                    host_type=host_type, created_by_id=current_user.id)
        host.issue_enrollment_token()
        db.session.add(host)
        db.session.flush()
        _get_or_create_host_user(host.id, current_user.id, 'owner')
        db.session.commit()
        return redirect(url_for('enroll_host', host_id=host.id))

    return render_template('add_host.html')


@app.route('/hosts/<int:host_id>')
@login_required
def host_info(host_id):
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
                result = subprocess.run(['ssh-keygen', '-l', '-f', tmp],
                                        capture_output=True, text=True, check=True)
                fingerprint = result.stdout.strip()
            finally:
                os.unlink(tmp)
        except Exception:
            fingerprint = None

    active_certs = []
    if host.host_key_id:
        active_certs = [c for c in Certificate.query.filter_by(ssh_key_id=host.host_key_id).all()
                        if c.valid_until > datetime.utcnow()]

    current_hu = HostUsers.query.filter_by(host_id=host.id,
                                            user_id=current_user.id).first()
    existing_user_ids = {hu.user_id for hu in host.host_users}
    candidates = (
        User.query
        .filter(User.completed_at.isnot(None))
        .filter(~User.id.in_(existing_user_ids) if existing_user_ids else True)
        .order_by(User.username)
        .all()
    )
    return render_template(
        'host_info.html',
        host=host, fingerprint=fingerprint, key_type=key_type,
        active_certs=active_certs, share_candidates=candidates,
        can_admin=_can_admin_host(host),
        current_host_user=current_hu,
    )


@app.route('/hosts/<int:host_id>/re-register', methods=['POST'])
@login_required
def re_register_host(host_id):
    host = Host.query.get_or_404(host_id)
    if not _can_admin_host(host):
        flash('Only an owner or admin can re-register this host.', 'danger')
        return redirect(url_for('hosts'))
    host.issue_enrollment_token()
    db.session.commit()
    flash(f'Host {host.hostname} registration cleared.', 'warning')
    return redirect(url_for('enroll_host', host_id=host.id))


@app.route('/hosts/<int:host_id>/share', methods=['POST'])
@login_required
def share_host(host_id):
    host = Host.query.get_or_404(host_id)
    if not _can_admin_host(host):
        flash('Only an owner or admin can share this host.', 'danger')
        return redirect(url_for('hosts'))
    target_user_id = request.form.get('user_id', type=int)
    role = request.form.get('role', 'user')
    if role not in ('owner', 'user'):
        role = 'user'
    if not target_user_id:
        flash('Pick a user to add.', 'danger')
        return redirect(url_for('host_info', host_id=host.id))
    target = db.session.get(User, target_user_id)
    if not target or target.completed_at is None:
        flash('Target user not found or registration incomplete.', 'danger')
        return redirect(url_for('host_info', host_id=host.id))
    _get_or_create_host_user(host.id, target.id, role)
    db.session.commit()
    flash(f'{target.username} added as {role} of {host.hostname}.', 'success')
    return redirect(url_for('host_info', host_id=host.id))


@app.route('/hosts/<int:host_id>/unshare/<int:user_id>', methods=['POST'])
@login_required
def unshare_host(host_id, user_id):
    host = Host.query.get_or_404(host_id)
    target = User.query.get_or_404(user_id)
    if not (current_user.is_admin or current_user.id == target.id):
        flash('You may only remove yourself; ask an admin for other changes.', 'danger')
        return redirect(url_for('host_info', host_id=host.id))
    hu = HostUsers.query.filter_by(host_id=host.id, user_id=target.id).first()
    if not hu:
        flash(f'{target.username} has no access to this host.', 'info')
        return redirect(url_for('host_info', host_id=host.id))
    db.session.delete(hu)
    remaining = HostUsers.query.filter_by(host_id=host.id).count()
    if remaining == 0:
        hostname = host.hostname
        db.session.delete(host)
        db.session.commit()
        flash(f'{hostname} had no remaining users and was deleted.', 'info')
        return redirect(url_for('hosts'))
    db.session.commit()
    flash(f'{target.username} removed from {host.hostname}.', 'info')
    if target.id == current_user.id:
        return redirect(url_for('hosts'))
    return redirect(url_for('host_info', host_id=host.id))


@app.route('/hosts/<int:host_id>/enroll')
@login_required
def enroll_host(host_id):
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
        server_url=server_url, token=host.enrollment_token,
        hostname=host.hostname, key_type=ALLOWED_HOST_KEY_TYPE,
    )
    ps1_script = render_template(
        'enrollment_script.ps1',
        server_url=server_url, token=host.enrollment_token,
        hostname=host.hostname, expires_hours=ENROLLMENT_TOKEN_TTL_HOURS,
    )
    one_liner_url = (f"{server_url}{url_for('api_enroll_script')}"
                     f"?token={host.enrollment_token}&host_id={host.id}")
    ps1_url = (f"{server_url}{url_for('api_enroll_ps1_script')}"
               f"?token={host.enrollment_token}&host_id={host.id}")
    return render_template(
        'enroll_host.html', host=host, script=script, ps1_script=ps1_script,
        one_liner=f'curl -fsSL "{one_liner_url}" | sudo bash',
        ps1_one_liner=(
            f'Invoke-Expression (Invoke-WebRequest -Uri "{ps1_url}" '
            f'-UseBasicParsing).Content'
        ),
        expires_at=host.enrollment_expires_at,
    )


@app.route('/hosts/<int:host_id>/enroll/regenerate', methods=['POST'])
@login_required
def regenerate_enrollment(host_id):
    host = Host.query.get_or_404(host_id)
    if host.is_enrolled:
        flash('Host is already enrolled.', 'danger')
        return redirect(url_for('hosts'))
    host.issue_enrollment_token()
    db.session.commit()
    flash('New enrollment token issued.', 'success')
    return redirect(url_for('enroll_host', host_id=host.id))


@app.route('/hosts/<int:host_id>/delete', methods=['POST'])
@login_required
def delete_host(host_id):
    host = Host.query.get_or_404(host_id)
    hostname = host.hostname
    if current_user.is_admin:
        db.session.delete(host)
        db.session.commit()
        flash(f'Host {hostname} deleted.', 'info')
        return redirect(url_for('hosts'))
    hu = HostUsers.query.filter_by(host_id=host.id, user_id=current_user.id).first()
    if not hu:
        flash('You are not associated with this host.', 'danger')
        return redirect(url_for('hosts'))
    db.session.delete(hu)
    remaining = HostUsers.query.filter_by(host_id=host.id).count()
    if remaining == 0:
        db.session.delete(host)
        db.session.commit()
        flash(f'{hostname} had no other users; it was removed.', 'info')
    else:
        db.session.commit()
        flash(f'You no longer have access to {hostname}.', 'info')
    return redirect(url_for('hosts'))


# ==================== Credential routes (replaces SSH User routes) ====================

@app.route('/credentials')
@login_required
def credentials():
    """List SSH User Keys (credentials). Non-admins see only their own."""
    if current_user.is_admin:
        cred_list = UserCredential.query.order_by(UserCredential.created_at.desc()).all()
    else:
        cred_list = current_user.credentials
    return render_template('credentials.html', credentials=cred_list,
                           viewing_as_admin=current_user.is_admin)


@app.route('/credentials/add', methods=['GET', 'POST'])
@login_required
def add_credential():
    """Manually add an SSH User Key credential (admin or owner of the selected host)."""
    enrolled_hosts = [h for h in Host.query.all() if h.is_enrolled]
    if not current_user.is_admin:
        enrolled_hosts = [h for h in enrolled_hosts if _can_admin_host(h)]

    if request.method == 'POST':
        host_id = request.form.get('host_id', type=int)
        unix_username = (request.form.get('unix_username') or '').strip()
        public_key = (request.form.get('public_key') or '').strip()

        if not host_id or not unix_username or not public_key:
            flash('Host, Unix username, and public key are required.', 'danger')
            return redirect(url_for('add_credential'))

        allowed = get_allowed_user_key_types()
        key_parts = public_key.split()
        if len(key_parts) < 2 or key_parts[0] not in allowed:
            flash(f'Key type must be one of: {", ".join(allowed)}', 'danger')
            return redirect(url_for('add_credential'))

        host = Host.query.get_or_404(host_id)
        if not _can_admin_host(host):
            flash('You must be an owner of the selected host.', 'danger')
            return redirect(url_for('add_credential'))

        # Duplicate key detection
        user_ssh_key = _get_or_create_ssh_key(public_key, 'user')
        db.session.flush()
        existing_cred = UserCredential.query.filter_by(user_key_id=user_ssh_key.id).first()
        if existing_cred and existing_cred.user_id != current_user.id:
            flash('This public key is already registered to another account.', 'danger')
            return redirect(url_for('add_credential'))
        if existing_cred:
            flash('This key is already registered as a credential.', 'info')
            return redirect(url_for('credentials'))

        hu = _get_or_create_host_user(host.id, current_user.id, 'user')
        db.session.flush()
        cred = UserCredential(
            user_id=current_user.id,
            user_key_id=user_ssh_key.id,
            host_user_id=hu.id,
            unix_username=unix_username,
        )
        db.session.add(cred)
        db.session.commit()
        flash(f'SSH User Key added for {unix_username}@{host.hostname}.', 'success')
        return redirect(url_for('credentials'))

    return render_template('add_credential.html', hosts=enrolled_hosts,
                           allowed_key_types=get_allowed_user_key_types())


@app.route('/credentials/<int:cred_id>/delete', methods=['POST'])
@login_required
def delete_credential(cred_id):
    cred = UserCredential.query.get_or_404(cred_id)
    if not (current_user.is_admin or cred.user_id == current_user.id):
        flash('You can only delete your own credentials.', 'danger')
        return redirect(url_for('credentials'))
    db.session.delete(cred)
    db.session.commit()
    flash('SSH User Key deleted.', 'info')
    return redirect(url_for('credentials'))


@app.route('/hosts/batch_renew', methods=['POST'])
@login_required
def batch_renew_hosts():
    """Issue new host certificates for a selected set of enrolled hosts."""
    if not os.path.exists(cert_gen.ca_key):
        flash('CA is not configured — cannot issue certificates.', 'danger')
        return redirect(url_for('hosts'))
    host_ids = request.form.getlist('host_ids', type=int)
    if not host_ids:
        flash('No hosts selected.', 'warning')
        return redirect(url_for('hosts'))
    ok, skipped = 0, 0
    for host_id in host_ids:
        host = Host.query.get(host_id)
        if not host or not host.is_enrolled:
            skipped += 1
            continue
        if not (current_user.is_admin or _can_admin_host(host)):
            skipped += 1
            continue
        try:
            _do_issue_host_cert(host, current_user.id)
            ok += 1
        except Exception:
            skipped += 1
    db.session.commit()
    if ok:
        flash(f'{ok} host certificate(s) issued.', 'success')
    if skipped:
        flash(f'{skipped} host(s) skipped (not enrolled, no access, or CA error).', 'warning')
    return redirect(url_for('certificates'))


@app.route('/credentials/batch_renew', methods=['POST'])
@login_required
def batch_renew_credentials():
    """Issue new user certificates for a selected set of credentials."""
    if not os.path.exists(cert_gen.ca_key):
        flash('CA is not configured — cannot issue certificates.', 'danger')
        return redirect(url_for('credentials'))
    cred_ids = request.form.getlist('cred_ids', type=int)
    if not cred_ids:
        flash('No credentials selected.', 'warning')
        return redirect(url_for('credentials'))
    ok, skipped = 0, 0
    for cred_id in cred_ids:
        cred = UserCredential.query.get(cred_id)
        if not cred:
            skipped += 1
            continue
        if not (current_user.is_admin or cred.user_id == current_user.id
                or _can_admin_host(cred.host)):
            skipped += 1
            continue
        try:
            _do_issue_user_cert(cred, current_user.id)
            ok += 1
        except Exception:
            skipped += 1
    db.session.commit()
    if ok:
        flash(f'{ok} user certificate(s) issued.', 'success')
    if skipped:
        flash(f'{skipped} credential(s) skipped (no access or CA error).', 'warning')
    return redirect(url_for('certificates'))


# ==================== Certificate routes ====================

@app.route('/certificates')
@login_required
def certificates():
    q = Certificate.query.order_by(Certificate.created_at.desc())
    if not current_user.is_admin:
        my_key_ids = [c.user_key_id for c in current_user.credentials]
        my_host_key_ids = [hu.host.host_key_id for hu in current_user.host_roles
                           if hu.host.host_key_id and hu.role == 'owner']
        visible = my_key_ids + my_host_key_ids
        q = q.filter(Certificate.ssh_key_id.in_(visible)) if visible else q.filter(False)
    ssh_port = app.config.get('SSHADMIN_SSH_PORT',
                              int(os.environ.get('SSHADMIN_SSH_PORT', 2222)))
    return render_template('certificates.html', certificates=q.all(),
                           viewing_as_admin=current_user.is_admin,
                           now=datetime.utcnow(), ssh_port=ssh_port)


@app.route('/certificates/issue/user', methods=['GET', 'POST'])
@login_required
def issue_user_cert():
    """Issue a user certificate for a credential."""
    if current_user.is_admin:
        cred_list = UserCredential.query.order_by(UserCredential.unix_username).all()
    else:
        cred_list = current_user.credentials

    if request.method == 'POST':
        cred_id = request.form.get('credential_id', type=int)
        valid_days = int(request.form.get('valid_days', 365))
        principals_raw = request.form.get('principals', '').strip()
        source_address = request.form.get('source_address', '').strip()
        force_command = request.form.get('force_command', '').strip()

        cred = UserCredential.query.get_or_404(cred_id)
        if not current_user.is_admin and cred.user_id != current_user.id:
            flash('You can only issue certificates for your own credentials.', 'danger')
            return redirect(url_for('issue_user_cert'))

        principals = [p.strip() for p in principals_raw.split(',') if p.strip()]
        if not principals:
            principals = [cred.unix_username]

        critical_options = {}
        if source_address:
            critical_options['source-address'] = source_address
        if force_command:
            critical_options['force-command'] = force_command

        try:
            cert_data = _do_issue_user_cert(
                cred, current_user.id, principals, valid_days,
                critical_options or None)
            db.session.commit()
            flash(f'User certificate issued for {cred.unix_username}@{cred.host.hostname}', 'success')
            cert = Certificate.query.filter_by(
                ssh_key_id=cred.user_key_id
            ).order_by(Certificate.created_at.desc()).first()
            return redirect(url_for('cert_install', cert_id=cert.id))
        except Exception as e:
            flash(f'Error issuing certificate: {e}', 'danger')

    return render_template('issue_user_cert.html', credentials=cred_list)


@app.route('/certificates/issue/host', methods=['GET', 'POST'])
@login_required
def issue_host_cert():
    """Issue a host certificate."""
    if current_user.is_admin:
        host_list = [h for h in Host.query.all() if h.is_enrolled]
    else:
        host_list = [h for h in Host.query.all()
                     if h.is_enrolled and _can_admin_host(h)]

    if request.method == 'POST':
        host_id = request.form.get('host_id', type=int)
        valid_days = int(request.form.get('valid_days', 365))
        host = Host.query.get_or_404(host_id)
        if not host.is_enrolled:
            flash(f'Host {host.hostname} has not completed enrollment.', 'danger')
            return redirect(url_for('issue_host_cert'))
        if not _can_admin_host(host):
            flash('You can only issue certificates for hosts you own.', 'danger')
            return redirect(url_for('issue_host_cert'))
        try:
            _do_issue_host_cert(host, current_user.id, valid_days)
            db.session.commit()
            flash(f'Host certificate issued for {host.hostname}', 'success')
            cert = Certificate.query.filter_by(
                ssh_key_id=host.host_key_id
            ).order_by(Certificate.created_at.desc()).first()
            return redirect(url_for('cert_install', cert_id=cert.id))
        except Exception as e:
            flash(f'Error issuing certificate: {e}', 'danger')

    return render_template('issue_host_cert.html', hosts=host_list)


@app.route('/certificates/<int:cert_id>/download')
@login_required
def download_cert(cert_id):
    cert = Certificate.query.get_or_404(cert_id)
    if not cert.certificate_data:
        flash('Certificate has no data on file.', 'danger')
        return redirect(url_for('certificates'))
    if cert.cert_type == 'host':
        name = cert.host.hostname if cert.host else cert.serial
    else:
        cred = cert.credential
        name = f'{cred.unix_username}-{cred.host.hostname}' if cred else cert.serial
    filename = f'sshadmin-{cert.cert_type}-{name}-cert.pub'
    return Response(cert.certificate_data + '\n', mimetype='text/plain',
                    headers={'Content-Disposition': f'attachment; filename={filename}'})


@app.route('/certificates/<int:cert_id>/install')
@login_required
def cert_install(cert_id):
    cert = Certificate.query.get_or_404(cert_id)
    if not cert.install_token or (
        cert.install_token_expires_at and cert.install_token_expires_at < datetime.utcnow()
    ):
        cert.issue_install_token()
        db.session.commit()
        flash('Install token expired; a fresh one was issued.', 'info')
    server_url = request.url_root.rstrip('/')
    install_url = (f"{server_url}{url_for('api_cert_install_script')}"
                   f"?token={cert.install_token}")
    one_liner = (f'curl -fsSL "{install_url}" | sudo bash'
                 if cert.cert_type == 'host'
                 else f'curl -fsSL "{install_url}" | bash')
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
        pass
    if cert.cert_type == 'host':
        target_name = cert.host.hostname if cert.host else 'unknown'
    else:
        cred = cert.credential
        target_name = f'{cred.unix_username}@{cred.host.hostname}' if cred else 'unknown'
    return render_template(
        'cert_install.html', cert=cert, one_liner=one_liner,
        install_url=install_url, target_name=target_name,
        fingerprint=fingerprint, ttl_hours=2,
    )


# ==================== Public install endpoints ====================

def _lookup_install_cert(token):
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
    token = (request.args.get('token') or '').strip()
    cert, err = _lookup_install_cert(token)
    if err is not None:
        return err
    return Response((cert.certificate_data or '').strip() + '\n',
                    mimetype='text/plain; charset=utf-8')


@app.route('/api/cert/install/script')
def api_cert_install_script():
    token = (request.args.get('token') or '').strip()
    cert, err = _lookup_install_cert(token)
    if err is not None:
        return err
    if cert.cert_type == 'host':
        target_name = cert.host.hostname if cert.host else 'unknown'
    else:
        cred = cert.credential
        target_name = cred.unix_username if cred else 'unknown'
    server_url = request.url_root.rstrip('/')
    script = render_template(
        'cert_install_script.sh',
        server_url=server_url, token=cert.install_token,
        cert_type=cert.cert_type,
        cert_pubkey_line=(cert.public_key or '').strip(),
        target_name=target_name,
    )
    return Response(script, mimetype='text/x-shellscript; charset=utf-8')


@app.route('/api/cert/user/<unix_username>')
def api_cert_user(unix_username):
    """Public: latest valid user cert for a unix username."""
    cred = UserCredential.query.filter_by(unix_username=unix_username).first_or_404()
    cert = _latest_valid_cert_for_key(cred.user_key_id)
    if not cert or not cert.certificate_data:
        return Response('# no valid certificate\n', status=404, mimetype='text/plain')
    return Response(cert.certificate_data.strip() + '\n', mimetype='text/plain; charset=utf-8')


@app.route('/api/cert/host/<path:hostname>')
def api_cert_host(hostname):
    """Public: latest valid host cert for a hostname."""
    host = Host.query.filter_by(hostname=hostname).first_or_404()
    if not host.host_key_id:
        return Response('# host not enrolled\n', status=404, mimetype='text/plain')
    cert = _latest_valid_cert_for_key(host.host_key_id)
    if not cert or not cert.certificate_data:
        return Response('# no valid certificate\n', status=404, mimetype='text/plain')
    return Response(cert.certificate_data.strip() + '\n', mimetype='text/plain; charset=utf-8')


@app.route('/download/sshadmin_add')
@app.route('/download/sshadmin')
def download_sshadmin_add():
    ssh_host = request.host.split(':')[0]
    ssh_port = app.config.get('SSHADMIN_SSH_PORT',
                              int(os.environ.get('SSHADMIN_SSH_PORT', 2222)))
    script = render_template('sshadmin.sh', ssh_host=ssh_host, ssh_port=ssh_port)
    return Response(script, mimetype='text/x-shellscript; charset=utf-8',
                    headers={'Content-Disposition': 'attachment; filename=sshadmin'})


@app.route('/download/sshadmin.ps1')
def download_sshadmin_ps1():
    server_url = request.host_url.rstrip('/')
    ssh_host = request.host.split(':')[0]
    ssh_port = app.config.get('SSHADMIN_SSH_PORT',
                              int(os.environ.get('SSHADMIN_SSH_PORT', 2222)))
    script = render_template('sshadmin.ps1', server_url=server_url,
                             ssh_host=ssh_host, ssh_port=ssh_port)
    return Response(script, mimetype='text/plain; charset=utf-8',
                    headers={'Content-Disposition': 'attachment; filename=sshadmin.ps1'})


# ==================== Auth (challenge/response) API ====================

@app.route('/api/ca-status')
@login_required
def api_ca_status():
    return jsonify({'ca_available': cert_gen.check_ca_keys()})


@app.route('/api/auth/script')
def api_auth_script():
    """Return the bash sign-and-submit script for an active challenge."""
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

    # Build the list of acceptable public keys for this challenge.
    if challenge.purpose == 'register':
        pubkeys = [challenge.expected_key] if challenge.expected_key else []
    else:
        pubkeys = [c.user_key.public_key for c in challenge.user.credentials]

    server_url = request.url_root.rstrip('/')
    script = render_template(
        'auth_script.sh',
        server_url=server_url,
        token=challenge.token,
        nonce=challenge.nonce,
        username=challenge.user.username,
        purpose=challenge.purpose,
        pubkeys=pubkeys,
        sshsig_namespace=SSHSIG_NAMESPACE,
        host_key_type=ALLOWED_HOST_KEY_TYPE,
    )
    return (script, 200, {'Content-Type': 'text/x-shellscript; charset=utf-8'})


@app.route('/api/challenge_response', methods=['POST'])
def api_challenge_response():
    """Accept a signature; for registration also expects hostname + host_public_key."""
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

    if challenge.purpose == 'register':
        # Registration: verify against the single declared key.
        if not challenge.expected_key:
            return jsonify({'ok': False, 'error': 'no expected key on challenge'}), 500
        if not verify_sshsig(challenge.expected_key, signature, challenge.nonce):
            return jsonify({'ok': False, 'error': 'signature verification failed'}), 403
        if not hostname or not host_pubkey:
            return jsonify({
                'ok': False,
                'error': 'hostname and host_public_key required for registration; '
                         'run the full auth script (sudo bash) to enroll your host',
            }), 400
    else:
        # Login: try each credential key.
        verified_key = None
        verified_cred = None
        for cred in challenge.user.credentials:
            if verify_sshsig(cred.user_key.public_key, signature, challenge.nonce):
                verified_key = cred.user_key.public_key
                verified_cred = cred
                break
        if verified_cred is None:
            return jsonify({'ok': False, 'error': 'signature verification failed'}), 403
        challenge.credential_id = verified_cred.id

    challenge.consumed_at = datetime.utcnow()
    host_result = _finalize_consumed_challenge(challenge, hostname, host_pubkey)
    db.session.commit()

    return jsonify({
        'ok': True,
        'purpose': challenge.purpose,
        'username': challenge.user.username,
        'host': host_result,
    })


def _finalize_consumed_challenge(challenge, hostname=None, host_pubkey=None):
    """Side effects after a challenge is consumed.

    For login: no-op (just returns).
    For registration: creates SSHKey (host + user), Host, HostUsers, UserCredential,
    sets completed_at, promotes first user to admin.
    Caller must commit.
    """
    if challenge.purpose != 'register':
        return {'enrolled': False}
    if challenge.user.completed_at is not None:
        return {'enrolled': False, 'reason': 'already completed'}

    # Validate host key type
    if not host_pubkey or not host_pubkey.startswith(ALLOWED_HOST_KEY_TYPE + ' '):
        return {'enrolled': False,
                'reason': f'host key must be {ALLOWED_HOST_KEY_TYPE}'}

    # ── Host SSH key ──────────────────────────────────────────────────────────
    host_ssh_key = _get_or_create_ssh_key(host_pubkey, 'host')
    db.session.flush()

    # ── Host ─────────────────────────────────────────────────────────────────
    shared = False
    host = Host.query.filter_by(host_key_id=host_ssh_key.id).first()
    if host is not None:
        # Existing host with matching key: add this user as a co-user.
        shared = True
    else:
        if hostname:
            host = Host.query.filter_by(hostname=hostname).first()
        if host is not None and host.host_key_id is not None:
            # Same hostname but different key: registration completes but we
            # can't add this user to the host without an admin resolving it.
            challenge.user.completed_at = datetime.utcnow()
            if User.query.filter(User.completed_at.isnot(None),
                                 User.is_admin == True).first() is None:  # noqa: E712
                challenge.user.is_admin = True
            return {'enrolled': False,
                    'reason': (f'host {hostname!r} already enrolled with a different public key; '
                               'contact an owner or admin to add your key manually')}
        if host is None:
            host = Host(
                hostname=hostname or 'unknown',
                created_by_id=challenge.user.id,
                host_key_id=host_ssh_key.id,
                enrolled_at=datetime.utcnow(),
            )
            db.session.add(host)
        else:
            # Pending host (same name, no key yet): enroll it now.
            host.host_key_id = host_ssh_key.id
            host.enrolled_at = datetime.utcnow()
    db.session.flush()

    # ── HostUsers (role='user' — web registration doesn't prove ownership) ───
    hu = _get_or_create_host_user(host.id, challenge.user.id, 'user')
    db.session.flush()

    # ── User SSH key ──────────────────────────────────────────────────────────
    expected_key = challenge.expected_key
    user_ssh_key = _get_or_create_ssh_key(expected_key, 'user')
    db.session.flush()

    # Duplicate-key guard
    existing_cred = UserCredential.query.filter_by(user_key_id=user_ssh_key.id).first()
    if existing_cred and existing_cred.user_id != challenge.user.id:
        return {'enrolled': False,
                'reason': 'this SSH key is already registered to another account'}

    # ── UserCredential ────────────────────────────────────────────────────────
    if existing_cred is None:
        cred = UserCredential(
            user_id=challenge.user.id,
            user_key_id=user_ssh_key.id,
            host_user_id=hu.id,
            unix_username=challenge.unix_username or challenge.user.username,
        )
        db.session.add(cred)

    # ── Promote first user to admin, mark completed ───────────────────────────
    existing_admin = User.query.filter(
        User.completed_at.isnot(None), User.is_admin == True  # noqa: E712
    ).first()
    if existing_admin is None:
        challenge.user.is_admin = True
    challenge.user.completed_at = datetime.utcnow()

    result = {'enrolled': True, 'hostname': host.hostname}
    if shared:
        result['shared'] = True
    return result


@app.route('/api/totp_response', methods=['POST'])
def api_totp_response():
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
        return jsonify({'ok': False, 'error': 'TOTP can only be used for login'}), 403
    user = challenge.user
    if not user.totp_enabled or not user.totp_secret:
        return jsonify({'ok': False, 'error': 'TOTP is not enabled for this user'}), 403
    if not pyotp.TOTP(user.totp_secret).verify(code, valid_window=1):
        return jsonify({'ok': False, 'error': 'invalid code'}), 403
    challenge.consumed_at = datetime.utcnow()
    db.session.commit()
    return jsonify({'ok': True, 'username': user.username})


@app.route('/api/auth_status/<token>')
def api_auth_status(token):
    challenge = Challenge.query.filter_by(token=token).first()
    if not challenge:
        return jsonify({'status': 'unknown'}), 404
    if challenge.expires_at < datetime.utcnow() and challenge.consumed_at is None:
        return jsonify({'status': 'expired'})
    if challenge.consumed_at is None:
        return jsonify({'status': 'pending'})
    if session.get('pending_challenge_token') != token:
        return jsonify({'status': 'completed_other_session'})
    user = challenge.user
    if user.completed_at is None:
        return jsonify({'status': 'pending'})
    login_user(user)
    session.pop('pending_challenge_token', None)
    if challenge.purpose == 'register' and not user.totp_enabled:
        redirect_target = url_for('setup_totp')
    else:
        redirect_target = url_for('dashboard')
    return jsonify({'status': 'completed', 'redirect': redirect_target,
                    'is_admin': bool(user.is_admin)})


# ==================== Enrollment API ====================

@app.route('/api/enroll/script')
def api_enroll_script():
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
        server_url=server_url, token=host.enrollment_token,
        hostname=host.hostname, key_type=ALLOWED_HOST_KEY_TYPE,
    )
    return (script, 200, {'Content-Type': 'text/x-shellscript; charset=utf-8'})


@app.route('/api/enroll/script.ps1')
def api_enroll_ps1_script():
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
        'enrollment_script.ps1',
        server_url=server_url, token=host.enrollment_token,
        hostname=host.hostname, expires_hours=ENROLLMENT_TOKEN_TTL_HOURS,
    )
    return (script, 200, {
        'Content-Type': 'text/plain; charset=utf-8',
        'Content-Disposition': f'inline; filename="enroll-{host.hostname}.ps1"',
    })


@app.route('/api/ca-pubkey')
def api_ca_pubkey():
    if not os.path.exists(cert_gen.ca_pubkey):
        return ('CA public key not configured', 503, {'Content-Type': 'text/plain'})
    with open(cert_gen.ca_pubkey) as f:
        data = f.read()
    return (data, 200, {'Content-Type': 'text/plain; charset=utf-8'})


@app.route('/api/hosts/<int:host_id>/aliases', methods=['GET'])
@login_required
def api_host_aliases(host_id):
    host = Host.query.get_or_404(host_id)
    if not _can_view_host(host):
        return jsonify({'error': 'forbidden'}), 403
    return jsonify({'aliases': [a.alias for a in host.aliases]})


@app.route('/api/hosts/<int:host_id>/aliases', methods=['POST'])
@login_required
def api_add_host_alias(host_id):
    host = Host.query.get_or_404(host_id)
    if not _can_admin_host(host):
        return jsonify({'error': 'forbidden'}), 403
    alias = (request.form.get('alias') or (request.get_json(silent=True) or {}).get('alias') or '').strip()
    if not alias:
        return jsonify({'error': 'alias is required'}), 400
    _get_or_create_host_alias(host.id, alias)
    db.session.commit()
    return jsonify({'aliases': [a.alias for a in host.aliases]})


@app.route('/api/hosts/<int:host_id>/aliases/<path:alias>', methods=['DELETE'])
@login_required
def api_delete_host_alias(host_id, alias):
    host = Host.query.get_or_404(host_id)
    if not _can_admin_host(host):
        return jsonify({'error': 'forbidden'}), 403
    ha = HostAlias.query.filter_by(host_id=host.id, alias=alias).first()
    if ha:
        db.session.delete(ha)
        db.session.commit()
    return jsonify({'aliases': [a.alias for a in host.aliases]})


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
        return jsonify({'ok': False,
                        'error': f'host key must be {ALLOWED_HOST_KEY_TYPE}'}), 400

    host_ssh_key = _get_or_create_ssh_key(public_key, 'host')
    db.session.flush()
    host.host_key_id = host_ssh_key.id
    host.enrolled_at = datetime.utcnow()
    host.enrollment_token = None
    host.enrollment_expires_at = None
    db.session.commit()

    # Auto-issue a host certificate if the CA is configured.
    cert_data = None
    try:
        if os.path.exists(cert_gen.ca_key):
            cert_data = _do_issue_host_cert(host, host.created_by_id)
            db.session.commit()
    except Exception:
        pass  # enrollment still succeeds; admin can issue cert manually

    return jsonify({'ok': True, 'hostname': host.hostname, 'cert_data': cert_data})


# ==================== Internal cert helpers ====================

def _do_issue_host_cert(host, requester_id, valid_days=365):
    """Issue a host certificate. Caller is responsible for auth checks and commit.

    Strict mode (admin setting): principals = hostname + all registered aliases.
    Non-strict mode (default):   no -n flag → cert valid for any hostname.
    """
    if get_strict_host_principals():
        principals = list(host.all_principals)
    else:
        principals = []
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.pub') as f:
        f.write(host.host_key.public_key)
        tmp = f.name
    try:
        cert_data, serial = cert_gen.generate_host_certificate(tmp, principals, valid_days)
    finally:
        os.unlink(tmp)
    cert = Certificate(
        ssh_key_id=host.host_key_id,
        serial=serial,
        valid_from=datetime.utcnow(),
        valid_until=datetime.utcnow() + timedelta(days=valid_days),
        created_by_id=requester_id,
        certificate_data=cert_data,
    )
    cert.issue_install_token()
    db.session.add(cert)
    return cert_data


def _do_issue_user_cert(credential, requester_id, principals=None, valid_days=365,
                        critical_options=None, ca_key_override=None):
    """Issue a user certificate. Caller is responsible for auth checks and commit.

    ca_key_override lets the group machinery supply the correct group CA key.
    In simple mode (default) the main site CA is used.
    """
    if not principals:
        principals = [credential.unix_username]
    # Resolve which CA signs this cert: explicit override > group CA > site CA
    signing_key = ca_key_override or _get_user_cert_ca_key(credential.user_id)
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.pub') as f:
        f.write(credential.user_key.public_key)
        tmp = f.name
    try:
        cert_data, serial = cert_gen.generate_user_certificate(
            tmp, credential.unix_username, valid_days, principals, critical_options,
            ca_key_override=signing_key)
    finally:
        os.unlink(tmp)
    cert = Certificate(
        ssh_key_id=credential.user_key_id,
        serial=serial,
        valid_from=datetime.utcnow(),
        valid_until=datetime.utcnow() + timedelta(days=valid_days),
        created_by_id=requester_id,
        certificate_data=cert_data,
    )
    cert.issue_install_token()
    db.session.add(cert)
    return cert_data


def _ssh_add_machine(requester_user_id: int, data: dict) -> dict:
    """Process an add_machine request from the sshadmin_add script.

    Called after the requester's SSH key has already been verified by paramiko.
    Creates/updates SSHKey, Host, HostUsers (owner), and UserCredential rows,
    then issues host + user certificates.
    """
    with app.app_context():
        requester = User.query.get(requester_user_id)
        if not requester or requester.completed_at is None:
            return {'ok': False, 'error': 'valid registered account required'}

        hostname = (data.get('hostname') or '').strip()
        host_key = (data.get('host_key') or '').strip()
        username = (data.get('user') or '').strip()
        user_key = (data.get('user_key') or '').strip()
        connect_host = (data.get('connect_host') or '').strip()
        valid_days = max(1, min(int(data.get('valid_days', 365)), 3650))
        enroll_host = bool(host_key)  # host enrollment is optional

        if not username or not user_key or not hostname:
            return {'ok': False, 'error': 'hostname, user, and user_key are required'}

        if enroll_host and not host_key.startswith(ALLOWED_HOST_KEY_TYPE + ' '):
            return {'ok': False, 'error': f'host key must be {ALLOWED_HOST_KEY_TYPE}'}

        allowed_user_types = get_allowed_user_key_types()
        user_key_type = (user_key.split() or [''])[0]
        if user_key_type not in allowed_user_types:
            return {'ok': False,
                    'error': f'user key type {user_key_type!r} not allowed; '
                             f'accepted: {", ".join(allowed_user_types)}'}

        host = None
        hu = None
        host_cert_data = None

        if enroll_host:
            # ── Host SSH key ──────────────────────────────────────────────────
            host_ssh_key = _get_or_create_ssh_key(host_key, 'host')
            db.session.flush()

            # ── Host ─────────────────────────────────────────────────────────
            host = Host.query.filter_by(host_key_id=host_ssh_key.id).first()
            if host is None:
                host = Host.query.filter_by(hostname=hostname).first()

            if host is None:
                host = Host(
                    hostname=hostname,
                    description=f'Added via sshadmin_add by {requester.username}',
                    created_by_id=requester.id,
                    host_key_id=host_ssh_key.id,
                    enrolled_at=datetime.utcnow(),
                )
                db.session.add(host)
            else:
                # Host already exists. Presenting the host key proves root/sudo
                # access to the machine, so add the requester as co-owner rather
                # than rejecting. _get_or_create_host_user below handles this.
                host.host_key_id = host_ssh_key.id
                host.enrolled_at = datetime.utcnow()
                host.enrollment_token = None
                host.enrollment_expires_at = None
            db.session.flush()

            hu = _get_or_create_host_user(host.id, requester.id, 'owner')
            db.session.flush()
        else:
            # No host key supplied — look up or create a placeholder host record
            # so the user credential has somewhere to live.
            host = Host.query.filter_by(hostname=hostname).first()
            if host is None:
                host = Host(
                    hostname=hostname,
                    description=f'Added via sshadmin_add by {requester.username} (key pending)',
                    created_by_id=requester.id,
                )
                db.session.add(host)
                db.session.flush()
            hu = _get_or_create_host_user(host.id, requester.id, 'owner')
            db.session.flush()

        # ── User SSH key ──────────────────────────────────────────────────────
        norm_user_key = _normalize_pubkey(user_key)
        user_ssh_key = _get_or_create_ssh_key(norm_user_key, 'user')
        db.session.flush()

        existing_cred = UserCredential.query.filter_by(
            user_key_id=user_ssh_key.id).first()
        if existing_cred and existing_cred.user_id != requester.id:
            return {'ok': False,
                    'error': 'this SSH user key is already registered to another account'}
        if existing_cred and existing_cred.user_id == requester.id:
            other_host = existing_cred.host
            if other_host and other_host.id != host.id:
                print(f'[sshadmin] WARNING: user key {user_ssh_key.key_hash} '
                      f'already registered on {other_host.hostname}, '
                      f'now also on {hostname} — private key may have been copied',
                      flush=True)

        cred = UserCredential.query.filter_by(
            user_id=requester.id, user_key_id=user_ssh_key.id).first()
        if cred is None:
            cred = UserCredential(
                user_id=requester.id,
                user_key_id=user_ssh_key.id,
                host_user_id=hu.id,
                unix_username=username,
            )
            db.session.add(cred)
        db.session.flush()

        # ── Store connect_host as alias (auto-expands principals in strict mode) ─
        if enroll_host and connect_host and connect_host != hostname:
            _get_or_create_host_alias(host.id, connect_host)
            db.session.flush()

        # ── Ensure default group membership ───────────────────────────────────
        default_group = CAGroup.query.filter_by(name='default').first()
        if default_group:
            _ensure_user_in_group(requester.id, default_group.id, auto_approve=True)
            if enroll_host and host.is_enrolled:
                _ensure_host_in_group(host.id, default_group.id)
            db.session.flush()

        # ── Issue certs ───────────────────────────────────────────────────────
        try:
            if enroll_host and host.host_key_id and os.path.exists(cert_gen.ca_key):
                host_cert_data = _do_issue_host_cert(host, requester.id, valid_days)
            user_cert = _do_issue_user_cert(cred, requester.id, [username], valid_days)
            db.session.commit()
        except Exception as exc:
            db.session.rollback()
            return {'ok': False, 'error': str(exc)}

        ca_pubkey = ''
        if os.path.exists(cert_gen.ca_pubkey):
            with open(cert_gen.ca_pubkey) as fh:
                ca_pubkey = fh.read().strip()

        return {
            'ok': True,
            'host_cert': host_cert_data.strip() if host_cert_data else None,
            'user_cert': user_cert.strip(),
            'ca_pubkey': ca_pubkey,
            'host_enrolled': enroll_host,
        }


def _ssh_get_cert(subject: str):
    """Latest valid cert for subject: hostname checked first, then unix_username."""
    with app.app_context():
        host = Host.query.filter_by(hostname=subject).first()
        if host and host.host_key_id:
            cert = _latest_valid_cert_for_key(host.host_key_id)
            if cert and cert.certificate_data:
                return cert.certificate_data.strip() + '\n'
        cred = UserCredential.query.filter_by(unix_username=subject).first()
        if cred:
            cert = _latest_valid_cert_for_key(cred.user_key_id)
            if cert and cert.certificate_data:
                return cert.certificate_data.strip() + '\n'
    return None


def _ssh_renew_user_cert(requester_user_id: int, data: dict) -> dict:
    """Renew a user certificate.

    data keys:
      user       — unix username on the remote machine
      user_key   — SSH public key string
      valid_days — (optional) integer
    """
    with app.app_context():
        unix_username = (data.get('user') or '').strip()
        public_key = (data.get('user_key') or '').strip()
        valid_days = int(data.get('valid_days') or 365)

        if not unix_username or not public_key:
            return {'ok': False, 'error': 'user and user_key are required'}

        user_ssh_key = _get_or_create_ssh_key(public_key, 'user')
        db.session.flush()

        cred = UserCredential.query.filter_by(
            user_key_id=user_ssh_key.id, user_id=requester_user_id).first()
        if not cred:
            return {'ok': False, 'error': 'No matching credential found for this key and user'}

        if not cert_gen.check_ca_keys():
            return {'ok': False, 'error': 'CA not configured'}

        try:
            cert_data = _do_issue_user_cert(cred, requester_user_id, valid_days=valid_days)
            db.session.commit()
        except Exception as exc:
            db.session.rollback()
            return {'ok': False, 'error': str(exc)}

        ca_pubkey = None
        try:
            with open(cert_gen.ca_pub, 'r') as f:
                ca_pubkey = f.read().strip()
        except Exception:
            pass

        return {'ok': True, 'user_cert': cert_data, 'ca_pubkey': ca_pubkey}


def _ssh_renew_host_cert(requester_user_id: int, data: dict) -> dict:
    """Renew a host certificate.

    data keys:
      hostname   — FQDN of the host
      host_key   — SSH public key string
      valid_days — (optional) integer

    The requester must be an owner of the host.
    """
    with app.app_context():
        hostname = (data.get('hostname') or '').strip()
        public_key = (data.get('host_key') or '').strip()
        valid_days = int(data.get('valid_days') or 365)

        if not hostname or not public_key:
            return {'ok': False, 'error': 'hostname and host_key are required'}

        host = Host.query.filter_by(hostname=hostname).first()
        if not host or not host.is_enrolled:
            return {'ok': False, 'error': f'Host {hostname!r} not found or not enrolled'}

        hu = HostUsers.query.filter_by(host_id=host.id, user_id=requester_user_id).first()
        if not hu:
            return {'ok': False, 'error': 'You are not an owner of this host'}

        # Verify the supplied key matches the enrolled key
        supplied_parts = public_key.split()[:2]
        enrolled_parts = (host.public_key or '').split()[:2]
        if supplied_parts != enrolled_parts:
            return {'ok': False, 'error': 'Supplied host key does not match the enrolled key'}

        if not cert_gen.check_ca_keys():
            return {'ok': False, 'error': 'CA not configured'}

        try:
            cert_data = _do_issue_host_cert(host, requester_user_id, valid_days=valid_days)
            db.session.commit()
        except Exception as exc:
            db.session.rollback()
            return {'ok': False, 'error': str(exc)}

        ca_pubkey = None
        try:
            with open(cert_gen.ca_pub, 'r') as f:
                ca_pubkey = f.read().strip()
        except Exception:
            pass

        return {'ok': True, 'host_cert': cert_data, 'ca_pubkey': ca_pubkey}


def _ssh_add_alias(requester_user_id: int, data: dict) -> dict:
    """Add a hostname/IP alias to a host and re-issue the host certificate.

    data keys:
      hostname   — registered hostname of the host
      host_key   — SSH public key string (proves caller has root access)
      alias      — new alias to add (hostname, FQDN, or IP)
      valid_days — (optional) integer
    """
    with app.app_context():
        hostname = (data.get('hostname') or '').strip()
        host_key = (data.get('host_key') or '').strip()
        alias = (data.get('alias') or '').strip()
        valid_days = int(data.get('valid_days') or 365)

        if not hostname or not host_key or not alias:
            return {'ok': False, 'error': 'hostname, host_key, and alias are required'}

        # Find host by host key first (more reliable than hostname alone).
        norm_key = ' '.join(host_key.split()[:2])
        host_key_row = SSHKey.query.filter(
            SSHKey.public_key.like(norm_key + '%'),
            SSHKey.key_type == 'host',
        ).first()
        host = Host.query.filter_by(host_key_id=host_key_row.id).first() if host_key_row else None
        if host is None:
            host = Host.query.filter_by(hostname=hostname).first()
        if host is None or not host.is_enrolled:
            return {'ok': False, 'error': f'Host {hostname!r} not found or not enrolled'}

        # Verify key matches the enrolled host.
        supplied = host_key.split()[:2]
        enrolled = (host.public_key or '').split()[:2]
        if supplied != enrolled:
            return {'ok': False, 'error': 'Supplied host key does not match enrolled key'}

        hu = HostUsers.query.filter_by(host_id=host.id, user_id=requester_user_id).first()
        if not hu:
            return {'ok': False, 'error': 'You are not an owner of this host'}

        if not cert_gen.check_ca_keys():
            return {'ok': False, 'error': 'CA not configured'}

        _get_or_create_host_alias(host.id, alias)
        db.session.flush()

        try:
            cert_data = _do_issue_host_cert(host, requester_user_id, valid_days)
            db.session.commit()
        except Exception as exc:
            db.session.rollback()
            return {'ok': False, 'error': str(exc)}

        ca_pubkey = None
        try:
            with open(cert_gen.ca_pubkey) as f:
                ca_pubkey = f.read().strip()
        except Exception:
            pass

        return {
            'ok': True,
            'host_cert': cert_data,
            'ca_pubkey': ca_pubkey,
            'aliases': [a.alias for a in host.aliases],
        }


# ==================== CA Group Management ====================

@app.route('/groups')
@login_required
def groups():
    multi_enabled = get_multi_group_enabled()
    all_groups = CAGroup.query.order_by(CAGroup.name).all()
    # User's own memberships
    my_memberships = {m.group_id: m for m in current_user.group_memberships}
    return render_template('groups.html',
                           all_groups=all_groups,
                           my_memberships=my_memberships,
                           multi_enabled=multi_enabled)


@app.route('/groups/create', methods=['GET', 'POST'])
@login_required
def create_group():
    if not get_multi_group_enabled():
        flash('Multi-group mode is not enabled. Enable it in Admin Settings first.', 'warning')
        return redirect(url_for('groups'))
    if request.method == 'POST':
        name = request.form.get('name', '').strip().lower()
        description = request.form.get('description', '').strip()
        if not name or name == 'default':
            flash('Invalid group name.', 'error')
            return redirect(url_for('create_group'))
        if CAGroup.query.filter_by(name=name).first():
            flash(f'Group "{name}" already exists.', 'error')
            return redirect(url_for('create_group'))

        # Generate a dedicated CA keypair for this group
        ca_key_dir = os.path.dirname(cert_gen.ca_key)
        ca_key_path = os.path.join(ca_key_dir, f'ca_group_{name}_key')
        try:
            subprocess.run(
                ['ssh-keygen', '-t', 'ecdsa', '-b', '521',
                 '-f', ca_key_path, '-N', '', '-C', f'sshadmin-ca-group-{name}'],
                capture_output=True, text=True, check=True,
            )
            os.chmod(ca_key_path, 0o600)
            os.chmod(ca_key_path + '.pub', 0o644)
        except Exception as exc:
            flash(f'Failed to generate CA key for group: {exc}', 'error')
            return redirect(url_for('create_group'))

        group = CAGroup(
            name=name,
            description=description or f'Group {name}',
            ca_key_path=ca_key_path,
            created_by_id=current_user.id,
        )
        db.session.add(group)
        db.session.flush()
        # Creator automatically gets active membership
        _ensure_user_in_group(current_user.id, group.id, auto_approve=True)
        db.session.commit()
        flash(f'Group "{name}" created.', 'success')
        return redirect(url_for('group_detail', group_id=group.id))
    return render_template('group_create.html')


@app.route('/groups/<int:group_id>')
@login_required
def group_detail(group_id):
    group = CAGroup.query.get_or_404(group_id)
    is_owner = (current_user.is_admin or group.created_by_id == current_user.id)
    my_membership = UserGroupMembership.query.filter_by(
        user_id=current_user.id, group_id=group.id).first()
    all_users = User.query.filter(User.completed_at.isnot(None)).order_by(User.username).all()
    all_hosts = Host.query.order_by(Host.hostname).all()
    enrolled_host_ids = {m.host_id for m in group.host_memberships if m.status == 'active'}
    return render_template('group_detail.html',
                           group=group,
                           is_owner=is_owner,
                           my_membership=my_membership,
                           all_users=all_users,
                           all_hosts=all_hosts,
                           enrolled_host_ids=enrolled_host_ids)


@app.route('/groups/<int:group_id>/request-access', methods=['POST'])
@login_required
def group_request_access(group_id):
    group = CAGroup.query.get_or_404(group_id)
    principals = request.form.get('unix_principals', '').strip()
    m = UserGroupMembership.query.filter_by(
        user_id=current_user.id, group_id=group_id).first()
    if m and m.status == 'active':
        flash('You are already an active member of this group.', 'info')
        return redirect(url_for('group_detail', group_id=group_id))
    if m:
        m.status = 'pending'
        m.unix_principals = principals or None
        m.requested_at = datetime.utcnow()
        m.approved_at = None
    else:
        m = UserGroupMembership(
            user_id=current_user.id, group_id=group_id,
            status='pending', unix_principals=principals or None,
        )
        db.session.add(m)
    db.session.commit()
    flash(f'Access request submitted to group "{group.name}". '
          'The group owner will review it.', 'success')
    return redirect(url_for('groups'))


@app.route('/groups/<int:group_id>/approve-user/<int:membership_id>', methods=['POST'])
@login_required
def group_approve_user(group_id, membership_id):
    group = CAGroup.query.get_or_404(group_id)
    if not (current_user.is_admin or group.created_by_id == current_user.id):
        flash('Only the group owner or an admin can approve members.', 'error')
        return redirect(url_for('group_detail', group_id=group_id))
    m = UserGroupMembership.query.get_or_404(membership_id)
    principals_override = request.form.get('unix_principals', '').strip()
    if principals_override:
        m.unix_principals = principals_override
    m.status = 'active'
    m.approved_at = datetime.utcnow()
    m.approved_by_id = current_user.id
    db.session.commit()
    flash(f'User "{m.user.username}" approved for group "{group.name}".', 'success')
    return redirect(url_for('group_detail', group_id=group_id))


@app.route('/groups/<int:group_id>/reject-user/<int:membership_id>', methods=['POST'])
@login_required
def group_reject_user(group_id, membership_id):
    group = CAGroup.query.get_or_404(group_id)
    if not (current_user.is_admin or group.created_by_id == current_user.id):
        flash('Only the group owner or an admin can reject members.', 'error')
        return redirect(url_for('group_detail', group_id=group_id))
    m = UserGroupMembership.query.get_or_404(membership_id)
    m.status = 'rejected'
    db.session.commit()
    flash(f'Access request from "{m.user.username}" rejected.', 'warning')
    return redirect(url_for('group_detail', group_id=group_id))


@app.route('/groups/<int:group_id>/remove-user/<int:membership_id>', methods=['POST'])
@login_required
def group_remove_user(group_id, membership_id):
    group = CAGroup.query.get_or_404(group_id)
    if not (current_user.is_admin or group.created_by_id == current_user.id):
        flash('Only the group owner or an admin can remove members.', 'error')
        return redirect(url_for('group_detail', group_id=group_id))
    m = UserGroupMembership.query.get_or_404(membership_id)
    if group.is_default and not current_user.is_admin:
        flash('Cannot remove users from the default group.', 'error')
        return redirect(url_for('group_detail', group_id=group_id))
    db.session.delete(m)
    db.session.commit()
    flash(f'User removed from group "{group.name}".', 'success')
    return redirect(url_for('group_detail', group_id=group_id))


@app.route('/groups/<int:group_id>/add-host', methods=['POST'])
@login_required
def group_add_host(group_id):
    group = CAGroup.query.get_or_404(group_id)
    host_id = request.form.get('host_id', type=int)
    if not host_id:
        flash('No host selected.', 'error')
        return redirect(url_for('group_detail', group_id=group_id))
    host = Host.query.get_or_404(host_id)
    if not (_can_admin_host(host) or current_user.is_admin or group.created_by_id == current_user.id):
        flash('You must be the host owner or group owner to add a host.', 'error')
        return redirect(url_for('group_detail', group_id=group_id))
    _ensure_host_in_group(host.id, group.id)
    db.session.commit()
    flash(f'Host "{host.hostname}" added to group "{group.name}". '
          'Re-enroll the host to update its TrustedUserCAKeys.', 'success')
    return redirect(url_for('group_detail', group_id=group_id))


@app.route('/groups/<int:group_id>/remove-host/<int:membership_id>', methods=['POST'])
@login_required
def group_remove_host(group_id, membership_id):
    group = CAGroup.query.get_or_404(group_id)
    if not (current_user.is_admin or group.created_by_id == current_user.id):
        flash('Only the group owner or an admin can remove hosts.', 'error')
        return redirect(url_for('group_detail', group_id=group_id))
    m = HostGroupMembership.query.get_or_404(membership_id)
    if group.is_default and not current_user.is_admin:
        flash('Cannot remove hosts from the default group.', 'error')
        return redirect(url_for('group_detail', group_id=group_id))
    db.session.delete(m)
    db.session.commit()
    flash(f'Host removed from group "{group.name}".', 'success')
    return redirect(url_for('group_detail', group_id=group_id))


# ==================== Help / Documentation ====================

@app.route('/help')
def help_index():
    return render_template('help/index.html')


@app.route('/help/key-concepts')
def help_key_concepts():
    return render_template('help/key_concepts.html')


@app.route('/help/security-model')
def help_security_model():
    return render_template('help/security_model.html')


@app.route('/help/groups')
def help_groups():
    return render_template('help/groups.html')


# ==================== Admin Settings ====================

@app.route('/admin/settings', methods=['GET', 'POST'])
@admin_required
def admin_settings():
    if request.method == 'POST':
        chosen = request.form.getlist('user_key_types')
        valid_ids = {t[0] for t in ALL_USER_KEY_TYPE_OPTIONS}
        chosen = [t for t in chosen if t in valid_ids]
        if not chosen:
            chosen = list(_DEFAULT_USER_KEY_TYPES)
        cfg = db.session.get(SiteConfig, 'allowed_user_key_types')
        if cfg:
            cfg.value = ','.join(chosen)
        else:
            db.session.add(SiteConfig(key='allowed_user_key_types', value=','.join(chosen)))

        strict = '1' if request.form.get('strict_host_principals') else '0'
        cfg_strict = db.session.get(SiteConfig, 'strict_host_principals')
        if cfg_strict:
            cfg_strict.value = strict
        else:
            db.session.add(SiteConfig(key='strict_host_principals', value=strict))

        multi = '1' if request.form.get('multi_group_enabled') else '0'
        cfg_multi = db.session.get(SiteConfig, 'multi_group_enabled')
        if cfg_multi:
            cfg_multi.value = multi
        else:
            db.session.add(SiteConfig(key='multi_group_enabled', value=multi))

        db.session.commit()
        flash('Settings saved.', 'success')
        return redirect(url_for('admin_settings'))

    current_types = set(get_allowed_user_key_types())
    return render_template('admin_settings.html',
                           all_key_type_options=ALL_USER_KEY_TYPE_OPTIONS,
                           current_types=current_types,
                           strict_host_principals=get_strict_host_principals(),
                           multi_group_enabled=get_multi_group_enabled())


# ==================== Error handlers ====================

@app.errorhandler(404)
def not_found(error):
    return render_template('404.html'), 404


@app.errorhandler(500)
def server_error(error):
    return render_template('500.html'), 500


# ==================== Startup ====================

def _log_startup_status():
    if cert_gen.check_ca_keys():
        print(f'[sshadmin] CA configured at {cert_gen.ca_key}', flush=True)
    else:
        print(
            f'[sshadmin] WARNING: CA key not found at {cert_gen.ca_key}. '
            f'Log in as the first registered user (auto-admin) and visit /setup/ca.',
            flush=True,
        )


def _start_ssh_auth_server_if_enabled():
    if os.environ.get('SSHADMIN_DISABLE_SSH_AUTH', '0') == '1':
        return None
    port = int(os.environ.get('SSHADMIN_SSH_PORT', '2222'))
    bind = os.environ.get('SSHADMIN_SSH_BIND', '0.0.0.0')
    public_host = os.environ.get('SSHADMIN_SSH_PUBLIC_HOST', '*')
    try:
        from ssh_auth_server import start_ssh_auth_server
        sock = start_ssh_auth_server(
            app=app, db=db,
            models={
                'User': User,
                'Challenge': Challenge,
                'UserCredential': UserCredential,
                'SSHKey': SSHKey,
                'finalize_challenge': _finalize_consumed_challenge,
                'get_cert': _ssh_get_cert,
                'add_machine': _ssh_add_machine,
                'add_alias': _ssh_add_alias,
                'renew_user_cert': _ssh_renew_user_cert,
                'renew_host_cert': _ssh_renew_host_cert,
            },
            host=bind, port=port,
            ca_key_path=cert_gen.ca_key if cert_gen.check_ca_keys() else None,
            host_principals=['sshadmin', public_host or '*'],
        )
        actual_port = sock.getsockname()[1]
        app.config['SSHADMIN_SSH_PORT'] = actual_port
        cert_note = ' (host key signed by CA)' if cert_gen.check_ca_keys() else ''
        print(f'[sshadmin] SSH auth server listening on {bind}:{actual_port}{cert_note}',
              flush=True)
        return sock
    except Exception as exc:
        print(f'[sshadmin] WARNING: SSH auth server not started: {exc}', flush=True)
        return None


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        _ensure_default_group()
    _log_startup_status()
    _start_ssh_auth_server_if_enabled()
    app.run(debug=True, host='0.0.0.0', port=5000, use_reloader=False)
