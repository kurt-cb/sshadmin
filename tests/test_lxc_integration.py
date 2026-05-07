"""
LXC end-to-end integration tests.

Spins up two Ubuntu 22.04 LXC containers, creates three OS users (alice,
bob, carol) on each, drives the full sshadmin flows (user registration,
host enrollment, host + user cert issuance), deploys the CA and certs to
the containers, then verifies:

  • SSH from C1 → C2 succeeds for all three users using only certificates
    (no authorized_keys, no pre-known host fingerprints in known_hosts).
  • An expired user certificate is rejected by the SSH server.
  • An expired host certificate is rejected by the SSH client.

Run this file alone to avoid DB conflicts with the unit tests:
    pytest tests/test_lxc_integration.py -v
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import time
from datetime import datetime, timedelta
from pathlib import Path

import pytest

import sshadmin
from conftest import register_via_api


# ---------------------------------------------------------------------------
# Skip guard – whole module is skipped when LXC is not installed / accessible
# ---------------------------------------------------------------------------

def _lxc_available() -> bool:
    try:
        r = subprocess.run(['lxc', 'version'], capture_output=True, timeout=5)
        return r.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


pytestmark = [
    pytest.mark.lxc,
    pytest.mark.skipif(not _lxc_available(), reason='LXC not available'),
]

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

C1 = 'sshadmin-lxc-test-1'
C2 = 'sshadmin-lxc-test-2'
CONTAINERS = [C1, C2]
USERNAMES = ['alice', 'bob', 'carol']
UBUNTU_IMAGE = 'images:ubuntu/22.04'

# Force client to negotiate only the algorithm we issued a host cert for.
_HOST_KEY_ALGO = 'ecdsa-sha2-nistp521-cert-v01@openssh.com'

# ---------------------------------------------------------------------------
# LXC helpers
# ---------------------------------------------------------------------------

def _lxc(*args: str, timeout: int = 180) -> subprocess.CompletedProcess:
    return subprocess.run(
        ['lxc'] + list(args),
        check=True, capture_output=True, text=True, timeout=timeout,
    )


def _lxc_exec(container: str, *cmd: str, check: bool = True,
              timeout: int = 120) -> subprocess.CompletedProcess:
    return subprocess.run(
        ['lxc', 'exec', container, '--'] + list(cmd),
        check=check, capture_output=True, text=True, timeout=timeout,
    )


def _push_text(container: str, content: str, remote_path: str,
               mode: str | None = None, owner: str | None = None) -> None:
    with tempfile.NamedTemporaryFile(mode='w', suffix='.tmp', delete=False) as f:
        f.write(content)
        local = f.name
    try:
        subprocess.run(
            ['lxc', 'file', 'push', local, f'{container}{remote_path}'],
            check=True, capture_output=True,
        )
    finally:
        os.unlink(local)
    if mode:
        _lxc_exec(container, 'chmod', mode, remote_path)
    if owner:
        _lxc_exec(container, 'chown', owner, remote_path)


def _push_file(container: str, local_path: str | Path, remote_path: str,
               mode: str | None = None, owner: str | None = None) -> None:
    subprocess.run(
        ['lxc', 'file', 'push', str(local_path), f'{container}{remote_path}'],
        check=True, capture_output=True,
    )
    if mode:
        _lxc_exec(container, 'chmod', mode, remote_path)
    if owner:
        _lxc_exec(container, 'chown', owner, remote_path)


def _get_ip(container: str, max_wait: int = 120) -> str:
    """Poll until the container has an IPv4 address that is not loopback."""
    deadline = time.monotonic() + max_wait
    while time.monotonic() < deadline:
        r = subprocess.run(
            ['lxc', 'list', container, '--format', 'json'],
            capture_output=True, text=True,
        )
        data = json.loads(r.stdout)
        if data:
            network = (data[0].get('state') or {}).get('network', {})
            for iface in network.values():
                for addr in iface.get('addresses', []):
                    if addr['family'] == 'inet' and not addr['address'].startswith('127.'):
                        return addr['address']
        time.sleep(3)
    raise RuntimeError(f'{container} did not get an IPv4 address within {max_wait}s')


def _ssh_from(container: str, username: str, target_ip: str,
              identity: str | None = None,
              cmd: str = 'echo hello',
              timeout: int = 30) -> subprocess.CompletedProcess:
    """Run an SSH command from *container* as OS user *username* to *target_ip*.

    *identity* overrides the default key path (~/.ssh/id_ed25519).
    Forces ECDSA-521 host certificate negotiation and IdentitiesOnly so that
    only the explicitly supplied key is tried.  Returns the CompletedProcess
    (check=False); callers inspect returncode.
    """
    id_file = identity or f'/home/{username}/.ssh/id_ed25519'
    ssh_cmd = (
        f'ssh '
        f'-o BatchMode=yes '
        f'-o StrictHostKeyChecking=yes '
        f'-o ConnectTimeout=10 '
        f'-o IdentitiesOnly=yes '
        f'-o UserKnownHostsFile=/etc/ssh/ssh_known_hosts '
        f'-o HostKeyAlgorithms={_HOST_KEY_ALGO} '
        f'-i {id_file} '
        + f'{username}@{target_ip} \'{cmd}\''
    )
    return subprocess.run(
        ['lxc', 'exec', container, '--',
         'runuser', '-l', username, '-c', ssh_cmd],
        capture_output=True, text=True, timeout=timeout, check=False,
    )


# ---------------------------------------------------------------------------
# Expired-cert helpers (sign directly via cert_gen, bypassing the web layer)
# ---------------------------------------------------------------------------

def _sign_expired_user_cert(pub_key_path: str, username: str) -> str:
    """Return an already-expired user certificate for the given public key."""
    now = datetime.now()  # local time – ssh-keygen interprets timestamps as local
    after = (now - timedelta(days=3)).strftime('%Y%m%d%H%M%S')
    before = (now - timedelta(hours=24)).strftime('%Y%m%d%H%M%S')  # large margin beats tz skew
    serial = int(now.timestamp() * 1000) + 1
    with tempfile.TemporaryDirectory() as tmp:
        dest = os.path.join(tmp, 'key.pub')
        shutil.copy(pub_key_path, dest)
        subprocess.run([
            'ssh-keygen', '-s', sshadmin.cert_gen.ca_key,
            '-I', f'{username}-expired-{serial}',
            '-n', username,
            '-V', f'{after}:{before}',
            '-z', str(serial),
            dest,
        ], check=True, capture_output=True)
        return Path(dest[:-4] + '-cert.pub').read_text().strip()


def _sign_expired_host_cert(pub_key_path: str, hostname: str) -> str:
    """Return an already-expired host certificate for the given public key."""
    now = datetime.now()  # local time – ssh-keygen interprets timestamps as local
    after = (now - timedelta(days=3)).strftime('%Y%m%d%H%M%S')
    before = (now - timedelta(hours=24)).strftime('%Y%m%d%H%M%S')  # large margin beats tz skew
    serial = int(now.timestamp() * 1000) + 2
    with tempfile.TemporaryDirectory() as tmp:
        dest = os.path.join(tmp, 'key.pub')
        shutil.copy(pub_key_path, dest)
        subprocess.run([
            'ssh-keygen', '-s', sshadmin.cert_gen.ca_key,
            '-h',
            '-I', f'host-expired-{serial}',
            '-n', hostname,
            '-V', f'{after}:{before}',
            '-z', str(serial),
            dest,
        ], check=True, capture_output=True)
        return Path(dest[:-4] + '-cert.pub').read_text().strip()


# ---------------------------------------------------------------------------
# Sign helper used by register_via_api
# ---------------------------------------------------------------------------

def _make_sign_fn(priv_path: str):
    def _sign(nonce: str) -> str:
        with tempfile.TemporaryDirectory() as tmp:
            n = Path(tmp) / 'nonce'
            n.write_text(nonce)
            subprocess.run(
                ['ssh-keygen', '-Y', 'sign', '-f', priv_path,
                 '-n', sshadmin.SSHSIG_NAMESPACE, str(n)],
                check=True, capture_output=True,
            )
            return (Path(tmp) / 'nonce.sig').read_text()
    return _sign


# ---------------------------------------------------------------------------
# Session-scoped keypair fixture
# ---------------------------------------------------------------------------

@pytest.fixture(scope='session')
def user_keypairs(tmp_path_factory):
    """One Ed25519 keypair per test username."""
    d = tmp_path_factory.mktemp('lxc-user-keys')
    pairs: dict[str, dict] = {}
    for username in USERNAMES:
        priv = d / f'id_{username}'
        subprocess.run(
            ['ssh-keygen', '-t', 'ed25519', '-f', str(priv),
             '-N', '', '-C', f'{username}@lxc-test'],
            check=True, capture_output=True,
        )
        pairs[username] = {
            'private_path': str(priv),
            'public_path': str(priv) + '.pub',
            'public_key': (d / f'id_{username}.pub').read_text().strip(),
        }
    return pairs


# ---------------------------------------------------------------------------
# Main session fixture – containers + sshadmin setup + cert deployment
# ---------------------------------------------------------------------------

@pytest.fixture(scope='session')
def lxc_env(tmp_path_factory, user_keypairs):
    """
    Provision two LXC containers with three users and fully configured
    sshadmin certificate authentication.  Yields a state dict containing
    IPs, cert data, and DB IDs for use by the test functions.
    Tears down containers and restores sshadmin state on exit.
    """
    # ------------------------------------------------------------------ #
    # 1. Redirect cert_gen to a private CA so unit-test CA files are safe #
    # ------------------------------------------------------------------ #
    ca_dir = tmp_path_factory.mktemp('lxc-ca')
    _orig_ca_key = sshadmin.cert_gen.ca_key
    _orig_ca_pub = sshadmin.cert_gen.ca_pubkey
    sshadmin.cert_gen.ca_key = str(ca_dir / 'ca_key')
    sshadmin.cert_gen.ca_pubkey = str(ca_dir / 'ca_key.pub')

    # ------------------------------------------------------------------ #
    # 2. Fresh DB                                                         #
    # ------------------------------------------------------------------ #
    sshadmin.app.config['TESTING'] = True
    with sshadmin.app.app_context():
        sshadmin.db.drop_all()
        sshadmin.db.create_all()

    # ------------------------------------------------------------------ #
    # 3. Containers: create and wait for IPs                              #
    # ------------------------------------------------------------------ #
    for c in CONTAINERS:
        subprocess.run(['lxc', 'delete', '--force', c], capture_output=True)
    for c in CONTAINERS:
        _lxc('launch', UBUNTU_IMAGE, c,
             '--config', 'security.privileged=true', timeout=300)

    state: dict = {}
    try:
        ips = {c: _get_ip(c) for c in CONTAINERS}
        state['ips'] = ips

        # ------------------------------------------------------------------ #
        # 4. Install openssh-server, generate P-521 host key, create OS users #
        # ------------------------------------------------------------------ #
        for c in CONTAINERS:
            _lxc_exec(c, 'apt-get', 'update', '-q', timeout=120)
            _lxc_exec(c, 'apt-get', 'install', '-y', '-q', 'openssh-server', timeout=300)

            # Replace the default ECDSA key (P-256) with a P-521 one, which is
            # the only key type sshadmin's enrollment accepts.
            _lxc_exec(c, 'bash', '-c',
                      'rm -f /etc/ssh/ssh_host_ecdsa_key* && '
                      'ssh-keygen -t ecdsa -b 521 '
                      '-f /etc/ssh/ssh_host_ecdsa_key -N "" -C ""')

            for username in USERNAMES:
                _lxc_exec(c, 'useradd', '-m', '-s', '/bin/bash', username)
                _lxc_exec(c, 'bash', '-c',
                           f'mkdir -p /home/{username}/.ssh && '
                           f'chmod 700 /home/{username}/.ssh && '
                           f'chown -R {username}:{username} /home/{username}/.ssh')

        # ------------------------------------------------------------------ #
        # 5. Generate CA                                                      #
        # ------------------------------------------------------------------ #
        sshadmin.cert_gen.generate_ca(comment='lxc-integration-test CA')
        ca_pubkey = sshadmin.cert_gen.read_ca_pubkey()
        state['ca_pubkey'] = ca_pubkey

        # ------------------------------------------------------------------ #
        # 6. Register three users; alice (first) becomes admin               #
        # ------------------------------------------------------------------ #
        with sshadmin.app.test_client() as c_alice:
            register_via_api(c_alice,
                             _make_sign_fn(user_keypairs['alice']['private_path']),
                             user_keypairs['alice']['public_key'],
                             username='alice')

        for uname in ['bob', 'carol']:
            with sshadmin.app.test_client() as tmp_c:
                register_via_api(tmp_c,
                                 _make_sign_fn(user_keypairs[uname]['private_path']),
                                 user_keypairs[uname]['public_key'],
                                 username=uname)

        with sshadmin.app.app_context():
            alice = sshadmin.User.query.filter_by(username='alice').first()
            alice_id = alice.id
            state['app_user_ids'] = {
                u: sshadmin.User.query.filter_by(username=u).first().id
                for u in USERNAMES
            }
            state['ssh_user_ids'] = {
                u: sshadmin.SSHUser.query.filter_by(username=u).first().id
                for u in USERNAMES
            }

        # ------------------------------------------------------------------ #
        # 7. Enroll containers as hosts and issue host certificates           #
        # ------------------------------------------------------------------ #
        host_pub_keys: dict[str, str] = {}
        host_cert_data: dict[str, str] = {}
        host_ids: dict[str, int] = {}

        with sshadmin.app.test_client() as admin:
            # Inject alice's session so we can act as admin.
            with admin.session_transaction() as sess:
                sess['_user_id'] = str(alice_id)

            for c in CONTAINERS:
                ip = ips[c]

                # Create host record (hostname = the container's IP).
                r = admin.post('/hosts/add', data={'hostname': ip,
                                                    'description': f'LXC test {c}'})
                assert r.status_code == 302, r.data

                with sshadmin.app.app_context():
                    host = sshadmin.Host.query.filter_by(hostname=ip).first()
                    token = host.enrollment_token
                    host_ids[c] = host.id

                # Read the P-521 host public key from the container.
                result = _lxc_exec(c, 'cat', '/etc/ssh/ssh_host_ecdsa_key.pub')
                host_pub = result.stdout.strip()
                host_pub_keys[c] = host_pub

                # Enroll the host using the token-authenticated public API.
                r = admin.post('/api/enroll/host',
                               data={'token': token, 'public_key': host_pub})
                assert r.status_code == 200, r.data

                # Issue a host certificate (principal = container IP).
                r = admin.post('/certificates/issue/host',
                               data={'host_id': host_ids[c], 'valid_days': '365'},
                               follow_redirects=False)
                assert r.status_code == 302, r.data

                with sshadmin.app.app_context():
                    cert = (sshadmin.Certificate.query
                            .filter_by(host_id=host_ids[c], cert_type='host')
                            .order_by(sshadmin.Certificate.id.desc())
                            .first())
                    host_cert_data[c] = cert.certificate_data

            # ------------------------------------------------------------------ #
            # 8. Issue user certificates                                         #
            # ------------------------------------------------------------------ #
            user_certs: dict[str, str] = {}
            for username in USERNAMES:
                sid = state['ssh_user_ids'][username]
                r = admin.post('/certificates/issue/user',
                               data={'user_id': sid, 'valid_days': '365',
                                     'principals': username},
                               follow_redirects=False)
                assert r.status_code == 302, r.data

                with sshadmin.app.app_context():
                    cert = (sshadmin.Certificate.query
                            .filter_by(user_id=sid, cert_type='user')
                            .order_by(sshadmin.Certificate.id.desc())
                            .first())
                    user_certs[username] = cert.certificate_data

        state['host_pub_keys'] = host_pub_keys
        state['host_cert_data'] = host_cert_data
        state['host_ids'] = host_ids
        state['user_certs'] = user_certs

        # ------------------------------------------------------------------ #
        # 9. Deploy CA, host certs, and sshd config to both containers       #
        # ------------------------------------------------------------------ #
        sshd_drop_in = (
            'PasswordAuthentication no\n'
            'PubkeyAuthentication yes\n'
            'AuthorizedKeysFile none\n'
            'TrustedUserCAKeys /etc/ssh/sshadmin_ca.pub\n'
            'HostCertificate /etc/ssh/ssh_host_ecdsa_key-cert.pub\n'
        )
        for c in CONTAINERS:
            _push_text(c, ca_pubkey + '\n', '/etc/ssh/sshadmin_ca.pub', mode='644')
            _push_text(c, host_cert_data[c] + '\n',
                       '/etc/ssh/ssh_host_ecdsa_key-cert.pub', mode='644')
            _push_text(c, sshd_drop_in,
                       '/etc/ssh/sshd_config.d/sshadmin.conf', mode='644')
            _lxc_exec(c, 'systemctl', 'reload', 'ssh')

        # ------------------------------------------------------------------ #
        # 10. Deploy user keys + certs to C1; set system-wide known_hosts    #
        # ------------------------------------------------------------------ #
        # known_hosts entry that trusts any host presenting a cert signed by CA.
        _push_text(C1, f'@cert-authority * {ca_pubkey}\n',
                   '/etc/ssh/ssh_known_hosts', mode='644')

        for username in USERNAMES:
            priv = user_keypairs[username]['private_path']
            home_ssh = f'/home/{username}/.ssh'

            _push_file(C1, priv, f'{home_ssh}/id_ed25519',
                       mode='600', owner=f'{username}:{username}')
            _push_text(C1, user_certs[username] + '\n',
                       f'{home_ssh}/id_ed25519-cert.pub',
                       mode='644', owner=f'{username}:{username}')

        yield state

    finally:
        # ------------------------------------------------------------------ #
        # Teardown                                                            #
        # ------------------------------------------------------------------ #
        sshadmin.cert_gen.ca_key = _orig_ca_key
        sshadmin.cert_gen.ca_pubkey = _orig_ca_pub
        for c in CONTAINERS:
            subprocess.run(['lxc', 'delete', '--force', c], capture_output=True)
        with sshadmin.app.app_context():
            sshadmin.db.drop_all()


# ===========================================================================
# Registration / enrollment / issuance assertions
# ===========================================================================

def test_three_users_registered(lxc_env):
    """All three users must be fully registered (completed_at set)."""
    with sshadmin.app.app_context():
        for username in USERNAMES:
            user = sshadmin.User.query.filter_by(username=username).first()
            assert user is not None, f'{username} not found'
            assert user.completed_at is not None, f'{username} registration incomplete'
        alice = sshadmin.User.query.filter_by(username='alice').first()
        assert alice.is_admin, 'alice (first user) must be admin'


def test_each_user_has_ssh_identity(lxc_env):
    """Registration must auto-create an SSHUser for each login user."""
    with sshadmin.app.app_context():
        for username in USERNAMES:
            su = sshadmin.SSHUser.query.filter_by(username=username).first()
            assert su is not None, f'SSHUser for {username} not found'


def test_both_hosts_enrolled(lxc_env):
    """Both containers must be enrolled (have a public key and enrolled_at)."""
    ips = lxc_env['ips']
    with sshadmin.app.app_context():
        for c in CONTAINERS:
            host = sshadmin.Host.query.filter_by(hostname=ips[c]).first()
            assert host is not None, f'Host {c} ({ips[c]}) not found'
            assert host.is_enrolled, f'Host {c} not enrolled'
            assert host.public_key.startswith('ecdsa-sha2-nistp521 ')


def test_host_certs_issued(lxc_env):
    """A valid host certificate must exist in the DB for each container."""
    host_ids = lxc_env['host_ids']
    with sshadmin.app.app_context():
        for c in CONTAINERS:
            cert = (sshadmin.Certificate.query
                    .filter_by(host_id=host_ids[c], cert_type='host')
                    .first())
            assert cert is not None, f'No host cert for {c}'
            assert cert.certificate_data
            assert 'ecdsa-sha2-nistp521-cert-v01@openssh.com' in cert.certificate_data
            assert cert.valid_until > datetime.utcnow()


def test_user_certs_issued(lxc_env):
    """A valid user certificate must exist in the DB for each user."""
    ssh_ids = lxc_env['ssh_user_ids']
    with sshadmin.app.app_context():
        for username in USERNAMES:
            cert = (sshadmin.Certificate.query
                    .filter_by(user_id=ssh_ids[username], cert_type='user')
                    .first())
            assert cert is not None, f'No user cert for {username}'
            assert cert.certificate_data
            assert cert.valid_until > datetime.utcnow()


# ===========================================================================
# SSH connectivity tests
# ===========================================================================

@pytest.mark.parametrize('username', USERNAMES)
def test_ssh_succeeds_with_valid_certs(lxc_env, username):
    """Each user can SSH from C1 to C2 using only certificate authentication."""
    c2_ip = lxc_env['ips'][C2]
    result = _ssh_from(C1, username, c2_ip)
    assert result.returncode == 0, (
        f'SSH failed for {username}:\n'
        f'stdout: {result.stdout}\nstderr: {result.stderr}'
    )
    assert 'hello' in result.stdout


# ===========================================================================
# Expired certificate rejection tests
# ===========================================================================

def test_expired_user_cert_rejected(lxc_env, tmp_path, user_keypairs):
    """An expired user certificate must be refused by the SSH server."""
    c2_ip = lxc_env['ips'][C2]

    # Write alice's public key to a temp file so we can sign it.
    pub_path = tmp_path / 'alice.pub'
    pub_path.write_text(user_keypairs['alice']['public_key'] + '\n')

    expired_cert = _sign_expired_user_cert(str(pub_path), 'alice')

    # Push alice's private key under a different identity name on C1,
    # paired with the expired cert.  This avoids touching the valid cert.
    _push_file(C1, user_keypairs['alice']['private_path'],
               '/home/alice/.ssh/id_expired',
               mode='600', owner='alice:alice')
    _push_text(C1, expired_cert + '\n',
               '/home/alice/.ssh/id_expired-cert.pub',
               mode='644', owner='alice:alice')

    result = _ssh_from(C1, 'alice', c2_ip,
                       identity='/home/alice/.ssh/id_expired',
                       cmd='echo should-not-reach')
    assert result.returncode != 0, (
        'SSH should have been rejected with an expired user cert, '
        f'but it succeeded.\nstdout: {result.stdout}\nstderr: {result.stderr}'
    )


def test_expired_host_cert_rejected(lxc_env, tmp_path):
    """An expired host certificate must be refused by the SSH client."""
    c2_ip = lxc_env['ips'][C2]

    # Read C2's actual host public key so we can sign it with a past validity.
    result = _lxc_exec(C2, 'cat', '/etc/ssh/ssh_host_ecdsa_key.pub')
    host_pub = result.stdout.strip()

    pub_path = tmp_path / 'host.pub'
    pub_path.write_text(host_pub + '\n')

    expired_cert = _sign_expired_host_cert(str(pub_path), c2_ip)

    # Push expired host cert to C2 and reload sshd.
    valid_cert = lxc_env['host_cert_data'][C2]
    _push_text(C2, expired_cert + '\n',
               '/etc/ssh/ssh_host_ecdsa_key-cert.pub', mode='644')
    _lxc_exec(C2, 'systemctl', 'reload', 'ssh')
    time.sleep(1)  # brief settle after reload

    try:
        result = _ssh_from(C1, 'alice', c2_ip,
                           cmd='echo should-not-reach')
        assert result.returncode != 0, (
            'SSH should have been rejected when C2 presents an expired host cert, '
            f'but it succeeded.\nstdout: {result.stdout}\nstderr: {result.stderr}'
        )
    finally:
        # Restore valid host cert so other tests are not affected.
        _push_text(C2, valid_cert + '\n',
                   '/etc/ssh/ssh_host_ecdsa_key-cert.pub', mode='644')
        _lxc_exec(C2, 'systemctl', 'reload', 'ssh')
        time.sleep(1)
