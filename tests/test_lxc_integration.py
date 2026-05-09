"""
LXC end-to-end integration tests.

sshadmin runs as a real Flask server inside its own dedicated LXC container
(CAPP), fully isolating its database from the unit-test suite.  Two Ubuntu
containers (C1, C2) act as OpenSSH client/server nodes, and one Alpine
container (CALPINE) runs Dropbear to test cross-implementation
interoperability.

Run this file alone:
    pytest tests/test_lxc_integration.py -v
"""
from __future__ import annotations

import http.cookiejar
import json as _json
import os
import re
import shutil
import subprocess
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta
from pathlib import Path

import pytest


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

CAPP    = 'sshadmin-lxc-app'     # Flask server + CA  (isolated DB)
C1      = 'sshadmin-lxc-c1'      # Ubuntu OpenSSH – SSH origin for most tests
C2      = 'sshadmin-lxc-c2'      # Ubuntu OpenSSH – SSH target
CALPINE = 'sshadmin-lxc-alpine'  # Alpine + Dropbear server + OpenSSH client

# Additional containers for sshadmin_add enrollment tests
CENROLL_UBUNTU = 'sshadmin-lxc-enroll-ubuntu'
CENROLL_ALPINE = 'sshadmin-lxc-enroll-alpine'
ENROLL_CONTAINERS = [CENROLL_UBUNTU, CENROLL_ALPINE]

ALL_CONTAINERS  = [CAPP, C1, C2, CALPINE]
SSH_CONTAINERS  = [C1, C2]       # Ubuntu hosts enrolled with host certs

USERNAMES    = ['alice', 'bob', 'carol']
UBUNTU_IMAGE = 'images:ubuntu/22.04'
ALPINE_IMAGE = 'images:alpine/3.21'

SSHSIG_NAMESPACE = 'sshadmin'
APP_DB   = '/app/instance/sshadmin.db'
APP_PORT = 5000

# Algorithm expected when the server presents a CA-signed host cert (C1/C2).
_HOST_KEY_ALGO_CERT = 'ecdsa-sha2-nistp521-cert-v01@openssh.com'

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


def _pull_file(container: str, remote_path: str, local_path: str | Path) -> None:
    subprocess.run(
        ['lxc', 'file', 'pull', f'{container}{remote_path}', str(local_path)],
        check=True, capture_output=True,
    )


def _get_ip(container: str, max_wait: int = 120) -> str:
    """Poll until the container has a non-loopback IPv4 address."""
    deadline = time.monotonic() + max_wait
    while time.monotonic() < deadline:
        r = subprocess.run(
            ['lxc', 'list', container, '--format', 'json'],
            capture_output=True, text=True,
        )
        data = _json.loads(r.stdout)
        if data:
            network = (data[0].get('state') or {}).get('network', {})
            for iface in network.values():
                for addr in iface.get('addresses', []):
                    if addr['family'] == 'inet' and not addr['address'].startswith('127.'):
                        return addr['address']
        time.sleep(3)
    raise RuntimeError(f'{container} did not get an IPv4 address within {max_wait}s')


def _wait_for_port(container: str, port: int, max_wait: int = 90) -> None:
    """Block until an HTTP server at *port* inside *container* answers."""
    deadline = time.monotonic() + max_wait
    while time.monotonic() < deadline:
        r = _lxc_exec(
            container, 'python3', '-c',
            f"import urllib.request; urllib.request.urlopen('http://localhost:{port}/'); print('ok')",
            check=False,
        )
        if 'ok' in r.stdout:
            return
        time.sleep(2)
    log = _lxc_exec(container, 'cat', '/tmp/sshadmin.log', check=False).stdout
    raise RuntimeError(
        f'Port {port} on {container} not ready after {max_wait}s.\nLog (tail):\n{log[-3000:]}'
    )


def _wait_for_ssh_port(container: str, port: int = 22, max_wait: int = 30) -> None:
    """Block until an SSH server at *port* inside *container* accepts a TCP connection."""
    deadline = time.monotonic() + max_wait
    while time.monotonic() < deadline:
        r = _lxc_exec(
            container, 'python3', '-c',
            f'import socket; s=socket.socket(); s.settimeout(2); '
            f's.connect(("127.0.0.1", {port})); d=s.recv(64); s.close(); '
            f'print("ok" if b"SSH" in d else "")',
            check=False,
        )
        if 'ok' in r.stdout:
            return
        time.sleep(2)
    raise RuntimeError(f'SSH port {port} on {container} not ready after {max_wait}s')


# ---------------------------------------------------------------------------
# sshadmin app-container helpers
# ---------------------------------------------------------------------------

def _sqlite_value(query: str) -> str:
    """Run *query* against sshadmin's SQLite DB inside CAPP; return first column of first row."""
    r = _lxc_exec(CAPP, 'python3', '-c', f"""
import sqlite3
conn = sqlite3.connect({APP_DB!r})
row  = conn.execute({query!r}).fetchone()
print(row[0] if row else '', end='')
""")
    return r.stdout.strip()


def _push_sshadmin_source(container: str) -> None:
    """Bundle the sshadmin source tree and push it to /app inside *container*."""
    root = Path(__file__).resolve().parent.parent
    with tempfile.NamedTemporaryFile(suffix='.tar.gz', delete=False) as f:
        tar_path = f.name
    try:
        subprocess.run(
            ['tar', '-C', str(root), '-czf', tar_path,
             'sshadmin.py', 'ssh_auth_server.py', 'templates', 'requirements.txt'],
            check=True, capture_output=True,
        )
        _lxc_exec(container, 'mkdir', '-p', '/app')
        _push_file(container, tar_path, '/tmp/sshadmin.tar.gz')
        _lxc_exec(container, 'tar', '-xzf', '/tmp/sshadmin.tar.gz', '-C', '/app')
    finally:
        os.unlink(tar_path)


# ---------------------------------------------------------------------------
# HTTP session – drives the sshadmin web UI programmatically
# ---------------------------------------------------------------------------

class _AdminSession:
    """Cookie-jar-backed urllib session for the sshadmin web UI."""

    def __init__(self, base_url: str) -> None:
        self.base = base_url.rstrip('/')
        jar = http.cookiejar.CookieJar()
        self._opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(jar)
        )

    def _url(self, path: str) -> str:
        return self.base + path

    def get(self, path: str) -> str:
        with self._opener.open(self._url(path)) as resp:
            return resp.read().decode()

    def get_json(self, path: str) -> dict:
        return _json.loads(self.get(path))

    def post(self, path: str, data: dict) -> str:
        """POST form data; return final URL after any redirects."""
        body = urllib.parse.urlencode(data).encode()
        req  = urllib.request.Request(
            self._url(path), data=body,
            headers={'Content-Type': 'application/x-www-form-urlencoded'},
        )
        with self._opener.open(req) as resp:
            resp.read()            # consume body
            return resp.geturl()   # final URL after redirects

    def post_json(self, path: str, data: dict) -> dict:
        """POST form data expecting a JSON response."""
        body = urllib.parse.urlencode(data).encode()
        req  = urllib.request.Request(
            self._url(path), data=body,
            headers={'Content-Type': 'application/x-www-form-urlencoded'},
        )
        try:
            with self._opener.open(req) as resp:
                return _json.loads(resp.read().decode())
        except urllib.error.HTTPError as e:
            return _json.loads(e.read().decode())


def _http_register(session: _AdminSession, sign_fn, public_key: str,
                   username: str, unix_username: str = None,
                   host_public_key: str = None, hostname: str = None) -> None:
    """Drive the sshadmin registration flow via real HTTP, leaving the user logged in."""
    if unix_username is None:
        unix_username = username
    if hostname is None:
        hostname = f'fake-host-{username}'
    if host_public_key is None:
        with tempfile.TemporaryDirectory() as tmp:
            key_path = os.path.join(tmp, 'host_key')
            subprocess.run(
                ['ssh-keygen', '-t', 'ecdsa', '-b', '521',
                 '-f', key_path, '-N', '', '-C', ''],
                check=True, capture_output=True,
            )
            host_public_key = Path(key_path + '.pub').read_text().strip()

    # POST /register -> redirect to /auth/await/<token>
    final_url = session.post('/register', {
        'username': username,
        'unix_username': unix_username,
        'public_key': public_key,
    })
    token = final_url.rstrip('/').split('/')[-1]

    # Fetch the auth script which embeds the challenge nonce
    script = session.get(f'/api/auth/script?token={token}')
    m = re.search(r'^NONCE="([^"]+)"', script, re.MULTILINE)
    assert m, f'NONCE not found in auth script for {username}'
    nonce = m.group(1)

    # Sign and submit the challenge (registration requires hostname + host_public_key)
    sig = sign_fn(nonce)
    session.post('/api/challenge_response', {
        'token': token, 'signature': sig,
        'hostname': hostname, 'host_public_key': host_public_key,
    })

    # Poll auth status; this also calls login_user() server-side and sets
    # the Flask-Login session cookie in our jar for subsequent admin calls.
    status = session.get_json(f'/api/auth_status/{token}')
    assert status.get('status') == 'completed', \
        f'Registration of {username} did not complete: {status}'


# ---------------------------------------------------------------------------
# SSH helper
# ---------------------------------------------------------------------------

def _ssh_from(container: str, username: str, target_ip: str,
              identity: str | None = None,
              cmd: str = 'echo hello',
              timeout: int = 30,
              host_key_algo: str = _HOST_KEY_ALGO_CERT,
              strict: bool = True) -> subprocess.CompletedProcess:
    """Run SSH from *container* as OS user *username* to *target_ip*.

    host_key_algo controls -o HostKeyAlgorithms.  Use the default cert
    algorithm for Ubuntu/OpenSSH targets, or ``'ecdsa-sha2-nistp521'`` (no
    ``-cert-v01`` suffix) for Dropbear targets that serve a raw host key.

    strict=False disables StrictHostKeyChecking entirely (debugging only).
    """
    id_file = identity or f'/home/{username}/.ssh/id_ed25519'
    if strict:
        host_opts = (
            f'-o StrictHostKeyChecking=yes '
            f'-o UserKnownHostsFile=/etc/ssh/ssh_known_hosts '
            f'-o HostKeyAlgorithms={host_key_algo} '
        )
    else:
        host_opts = '-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null '

    ssh_cmd = (
        'ssh '
        '-o BatchMode=yes '
        '-o ConnectTimeout=10 '
        '-o IdentitiesOnly=yes '
        + host_opts
        + f'-i {id_file} '
        + f"{username}@{target_ip} '{cmd}'"
    )
    # 'su -' works on both Ubuntu (util-linux) and Alpine (busybox).
    return subprocess.run(
        ['lxc', 'exec', container, '--', 'su', '-', username, '-c', ssh_cmd],
        capture_output=True, text=True, timeout=timeout, check=False,
    )


# ---------------------------------------------------------------------------
# Signing helpers
# ---------------------------------------------------------------------------

def _make_sign_fn(priv_path: str):
    def _sign(nonce: str) -> str:
        with tempfile.TemporaryDirectory() as tmp:
            n = Path(tmp) / 'nonce'
            n.write_text(nonce)
            subprocess.run(
                ['ssh-keygen', '-Y', 'sign', '-f', priv_path,
                 '-n', SSHSIG_NAMESPACE, str(n)],
                check=True, capture_output=True,
            )
            return (Path(tmp) / 'nonce.sig').read_text()
    return _sign


def _sign_expired_user_cert(pub_key_path: str, username: str, ca_key: str) -> str:
    """Return an already-expired user certificate signed with *ca_key*."""
    now    = datetime.now()
    after  = (now - timedelta(days=3)).strftime('%Y%m%d%H%M%S')
    before = (now - timedelta(hours=24)).strftime('%Y%m%d%H%M%S')
    serial = int(now.timestamp() * 1000) + 1
    with tempfile.TemporaryDirectory() as tmp:
        dest = os.path.join(tmp, 'key.pub')
        shutil.copy(pub_key_path, dest)
        subprocess.run([
            'ssh-keygen', '-s', ca_key,
            '-I', f'{username}-expired-{serial}',
            '-n', username,
            '-V', f'{after}:{before}',
            '-z', str(serial),
            dest,
        ], check=True, capture_output=True)
        return Path(dest[:-4] + '-cert.pub').read_text().strip()


def _sign_expired_host_cert(pub_key_path: str, hostname: str, ca_key: str) -> str:
    """Return an already-expired host certificate signed with *ca_key*."""
    now    = datetime.now()
    after  = (now - timedelta(days=3)).strftime('%Y%m%d%H%M%S')
    before = (now - timedelta(hours=24)).strftime('%Y%m%d%H%M%S')
    serial = int(now.timestamp() * 1000) + 2
    with tempfile.TemporaryDirectory() as tmp:
        dest = os.path.join(tmp, 'key.pub')
        shutil.copy(pub_key_path, dest)
        subprocess.run([
            'ssh-keygen', '-s', ca_key,
            '-h',
            '-I', f'host-expired-{serial}',
            '-n', hostname,
            '-V', f'{after}:{before}',
            '-z', str(serial),
            dest,
        ], check=True, capture_output=True)
        return Path(dest[:-4] + '-cert.pub').read_text().strip()


# ---------------------------------------------------------------------------
# Session-scoped keypair fixture
# ---------------------------------------------------------------------------

@pytest.fixture(scope='session')
def user_keypairs(tmp_path_factory):
    """One Ed25519 keypair per test username, generated once for the whole session."""
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
            'public_path':  str(priv) + '.pub',
            'public_key':   (d / f'id_{username}.pub').read_text().strip(),
        }
    return pairs


# ---------------------------------------------------------------------------
# Main session fixture
# ---------------------------------------------------------------------------

@pytest.fixture(scope='session')
def lxc_env(tmp_path_factory, user_keypairs):
    """
    Provision four LXC containers and wire up full sshadmin certificate auth.

    CAPP    – Ubuntu 22.04: sshadmin Flask server + CA.  Database is
              completely isolated from the unit-test suite.
    C1/C2   – Ubuntu 22.04: OpenSSH client/server nodes enrolled as hosts.
    CALPINE – Alpine 3: Dropbear SSH server + OpenSSH client.  Tests
              cross-implementation interoperability.

    Yields a state dict; tears everything down on exit.
    """

    # ------------------------------------------------------------------ #
    # 1. Destroy stale containers; launch fresh ones                       #
    # ------------------------------------------------------------------ #
    for c in ALL_CONTAINERS:
        subprocess.run(['lxc', 'delete', '--force', c], capture_output=True)

    for img, name in [
        (UBUNTU_IMAGE, CAPP),
        (UBUNTU_IMAGE, C1),
        (UBUNTU_IMAGE, C2),
        (ALPINE_IMAGE, CALPINE),
    ]:
        _lxc('launch', img, name, '--config', 'security.privileged=true', timeout=300)

    state: dict = {}
    try:
        ips = {c: _get_ip(c) for c in ALL_CONTAINERS}
        state['ips'] = ips
        app_url = f'http://{ips[CAPP]}:{APP_PORT}'

        # ------------------------------------------------------------------ #
        # 2. CAPP: install deps, push source, generate CA, start Flask        #
        # ------------------------------------------------------------------ #
        _lxc_exec(CAPP, 'apt-get', 'update', '-q', timeout=120)
        _lxc_exec(CAPP, 'apt-get', 'install', '-y', '-q',
                  'python3-pip', 'openssh-client', timeout=300)
        _push_sshadmin_source(CAPP)
        _lxc_exec(CAPP, 'pip3', 'install', '-r', '/app/requirements.txt',
                  '--quiet', timeout=300)
        _lxc_exec(CAPP, 'mkdir', '-p', '/app/instance')

        # Generate the CA before the server starts so it finds the keys at boot.
        _lxc_exec(CAPP, 'python3', '-c', f"""
import sys, os
sys.path.insert(0, '/app')
os.environ['DATABASE_URL'] = 'sqlite:////{APP_DB}'
os.environ['SECRET_KEY']   = 'lxc-test-secret'
os.environ['SSH_CA_KEY']   = '/app/ca_key'
import sshadmin
sshadmin.cert_gen.generate_ca(comment='lxc-integration-test CA')
""")

        # Manage sshadmin via systemd so it survives lxc-exec session teardown.
        svc = (
            '[Unit]\nDescription=sshadmin test server\nAfter=network.target\n\n'
            '[Service]\nWorkingDirectory=/app\n'
            'ExecStart=/usr/bin/python3 /app/sshadmin.py\n'
            f'Environment="DATABASE_URL=sqlite:////{APP_DB}"\n'
            'Environment="SECRET_KEY=lxc-test-secret"\n'
            'Environment="SSH_CA_KEY=/app/ca_key"\n'
            'Environment="SSHADMIN_DISABLE_SSH_AUTH=1"\n'
            'Restart=on-failure\n\n'
            '[Install]\nWantedBy=multi-user.target\n'
        )
        _push_text(CAPP, svc, '/etc/systemd/system/sshadmin.service')
        _lxc_exec(CAPP, 'systemctl', 'daemon-reload')
        _lxc_exec(CAPP, 'systemctl', 'start', 'sshadmin')
        _wait_for_port(CAPP, APP_PORT, max_wait=90)

        ca_pubkey = _lxc_exec(CAPP, 'cat', '/app/ca_key.pub').stdout.strip()
        state['ca_pubkey'] = ca_pubkey

        # Pull the CA private key to the test host for the expired-cert helpers.
        ca_local_dir = tmp_path_factory.mktemp('lxc-ca')
        ca_key_local = ca_local_dir / 'ca_key'
        _pull_file(CAPP, '/app/ca_key', str(ca_key_local))
        os.chmod(str(ca_key_local), 0o600)
        state['ca_key_local'] = str(ca_key_local)

        # ------------------------------------------------------------------ #
        # 3. C1/C2: OpenSSH server, P-521 host key, OS users                  #
        # ------------------------------------------------------------------ #
        for c in SSH_CONTAINERS:
            _lxc_exec(c, 'apt-get', 'update', '-q', timeout=120)
            _lxc_exec(c, 'apt-get', 'install', '-y', '-q', 'openssh-server', timeout=300)
            # Replace the default ECDSA P-256 key with P-521 (sshadmin requirement).
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
        # 4. CALPINE: Alpine + Dropbear + OpenSSH client                       #
        # ------------------------------------------------------------------ #
        _lxc_exec(CALPINE, 'apk', 'add', '--no-cache',
                  'dropbear', 'openssh-client', timeout=300)

        # Dropbear 2024.86 uses its own binary key format and only generates
        # P-256 ECDSA keys.  It cannot load OpenSSH PEM-format keys via -r.
        _lxc_exec(CALPINE, 'mkdir', '-p', '/etc/dropbear')
        _lxc_exec(CALPINE, 'dropbearkey', '-t', 'ecdsa',
                  '-f', '/etc/dropbear/dropbear_ecdsa_host_key')

        # Extract the OpenSSH-format public key for known_hosts and enrollment.
        r = _lxc_exec(CALPINE, 'dropbearkey', '-y',
                      '-f', '/etc/dropbear/dropbear_ecdsa_host_key')
        alpine_host_pub = next(
            line for line in r.stdout.splitlines()
            if line.startswith('ecdsa-sha2-')
        )
        state['alpine_host_pub'] = alpine_host_pub

        for username in USERNAMES:
            _lxc_exec(CALPINE, 'adduser', '-D', '-s', '/bin/sh', username)
            _lxc_exec(CALPINE, 'mkdir', '-p', f'/home/{username}/.ssh')
            _lxc_exec(CALPINE, 'chmod', '700', f'/home/{username}/.ssh')
            _lxc_exec(CALPINE, 'chown', '-R',
                      f'{username}:{username}', f'/home/{username}/.ssh')

        # Start Dropbear using the default key paths (daemonizes automatically).
        _lxc_exec(CALPINE, 'dropbear', '-p', '22')

        # ------------------------------------------------------------------ #
        # 5. Register users via HTTP (alice is first → becomes admin)          #
        # ------------------------------------------------------------------ #
        alice_session = _AdminSession(app_url)
        _http_register(alice_session,
                        _make_sign_fn(user_keypairs['alice']['private_path']),
                        user_keypairs['alice']['public_key'], 'alice')

        for uname in ['bob', 'carol']:
            s = _AdminSession(app_url)
            _http_register(s,
                           _make_sign_fn(user_keypairs[uname]['private_path']),
                           user_keypairs[uname]['public_key'], uname)

        state['app_user_ids'] = {
            u: int(_sqlite_value(f"SELECT id FROM user WHERE username='{u}'"))
            for u in USERNAMES
        }
        state['credential_ids'] = {
            u: int(_sqlite_value(
                f"SELECT uc.id FROM user_credential uc "
                f"JOIN user usr ON usr.id = uc.user_id "
                f"WHERE usr.username='{u}' LIMIT 1"
            ))
            for u in USERNAMES
        }

        # ------------------------------------------------------------------ #
        # 6. Enroll C1/C2 as hosts; issue host certs.                          #
        #    Attempt CALPINE enrollment separately (expected to fail: P-256).  #
        # ------------------------------------------------------------------ #
        host_pub_keys: dict[str, str] = {}
        host_cert_data: dict[str, str] = {}
        host_ids: dict[str, int] = {}

        for container in SSH_CONTAINERS:
            ip = ips[container]

            alice_session.post('/hosts/add',
                               {'hostname': ip, 'description': f'LXC {container}'})

            host_id = int(_sqlite_value(f"SELECT id FROM host WHERE hostname='{ip}'"))
            token   = _sqlite_value(
                f"SELECT enrollment_token FROM host WHERE id={host_id}")
            host_ids[container] = host_id

            host_pub = _lxc_exec(container, 'cat',
                                  '/etc/ssh/ssh_host_ecdsa_key.pub').stdout.strip()
            host_pub_keys[container] = host_pub

            result = alice_session.post_json('/api/enroll/host',
                                             {'token': token, 'public_key': host_pub})
            assert result.get('ok'), \
                f'Host enrollment failed for {container}: {result}'

            alice_session.post('/certificates/issue/host',
                               {'host_id': host_id, 'valid_days': '365'})

            cert_data = _sqlite_value(
                f"SELECT c.certificate_data FROM certificate c "
                f"JOIN ssh_key sk ON sk.id = c.ssh_key_id "
                f"JOIN host h ON h.host_key_id = sk.id "
                f"WHERE h.id = {host_id} ORDER BY c.id DESC LIMIT 1"
            )
            host_cert_data[container] = cert_data

        # Attempt to enroll CALPINE.  Dropbear's native P-256 key is rejected
        # because sshadmin requires ecdsa-sha2-nistp521.
        alpine_ip = ips[CALPINE]
        alice_session.post('/hosts/add',
                           {'hostname': alpine_ip, 'description': 'Alpine Dropbear'})
        alpine_host_id = int(_sqlite_value(
            f"SELECT id FROM host WHERE hostname='{alpine_ip}'"))
        alpine_token = _sqlite_value(
            f"SELECT enrollment_token FROM host WHERE id={alpine_host_id}")
        state['alpine_enrollment_result'] = alice_session.post_json(
            '/api/enroll/host',
            {'token': alpine_token, 'public_key': state['alpine_host_pub']},
        )

        state['host_pub_keys'] = host_pub_keys
        state['host_cert_data'] = host_cert_data
        state['host_ids'] = host_ids

        # ------------------------------------------------------------------ #
        # 7. Issue user certificates                                            #
        # ------------------------------------------------------------------ #
        user_certs: dict[str, str] = {}
        for username in USERNAMES:
            cred_id = state['credential_ids'][username]
            alice_session.post('/certificates/issue/user',
                               {'credential_id': cred_id, 'valid_days': '365',
                                'principals': username})
            cert_data = _sqlite_value(
                f"SELECT c.certificate_data FROM certificate c "
                f"JOIN user_credential uc ON uc.user_key_id = c.ssh_key_id "
                f"WHERE uc.id = {cred_id} ORDER BY c.id DESC LIMIT 1"
            )
            user_certs[username] = cert_data
        state['user_certs'] = user_certs

        # ------------------------------------------------------------------ #
        # 8. Deploy CA, host certs, sshd drop-in to C1 and C2                  #
        # ------------------------------------------------------------------ #
        sshd_drop_in = (
            'PasswordAuthentication no\n'
            'PubkeyAuthentication yes\n'
            'AuthorizedKeysFile none\n'
            'TrustedUserCAKeys /etc/ssh/sshadmin_ca.pub\n'
            'HostCertificate /etc/ssh/ssh_host_ecdsa_key-cert.pub\n'
        )
        for c in SSH_CONTAINERS:
            _push_text(c, ca_pubkey + '\n', '/etc/ssh/sshadmin_ca.pub', mode='644')
            _push_text(c, host_cert_data[c] + '\n',
                       '/etc/ssh/ssh_host_ecdsa_key-cert.pub', mode='644')
            _push_text(c, sshd_drop_in,
                       '/etc/ssh/sshd_config.d/sshadmin.conf', mode='644')
            _lxc_exec(c, 'systemctl', 'reload', 'ssh')

        # ------------------------------------------------------------------ #
        # 9. known_hosts on C1: cert-authority for C2, raw key for Dropbear    #
        # ------------------------------------------------------------------ #
        # The @cert-authority line covers C2 host-cert verification.
        # The plain fingerprint line covers CALPINE: Dropbear presents a raw
        # P-256 key (no cert), so we trust it by fingerprint instead.
        alpine_ip       = ips[CALPINE]
        alpine_host_pub = state['alpine_host_pub']
        _push_text(
            C1,
            f'@cert-authority * {ca_pubkey}\n'
            f'{alpine_ip} {alpine_host_pub}\n',
            '/etc/ssh/ssh_known_hosts', mode='644',
        )

        # ------------------------------------------------------------------ #
        # 10. User keys + certs on C1 for outbound SSH                         #
        # ------------------------------------------------------------------ #
        for username in USERNAMES:
            priv     = user_keypairs[username]['private_path']
            home_ssh = f'/home/{username}/.ssh'
            _push_file(C1, priv, f'{home_ssh}/id_ed25519',
                       mode='600', owner=f'{username}:{username}')
            _push_text(C1, user_certs[username] + '\n',
                       f'{home_ssh}/id_ed25519-cert.pub',
                       mode='644', owner=f'{username}:{username}')

        # ------------------------------------------------------------------ #
        # 11. CALPINE: authorized_keys (inbound), alice's cert (outbound)       #
        # ------------------------------------------------------------------ #
        # Dropbear does not support TrustedUserCAKeys, so inbound connections
        # from C1 use the raw public key in authorized_keys.
        for username in USERNAMES:
            pub_key  = user_keypairs[username]['public_key']
            home_ssh = f'/home/{username}/.ssh'
            _push_text(CALPINE, pub_key + '\n',
                       f'{home_ssh}/authorized_keys',
                       mode='600', owner=f'{username}:{username}')

        # alice's private key + user cert on CALPINE for outbound cert auth.
        _push_file(CALPINE, user_keypairs['alice']['private_path'],
                   '/home/alice/.ssh/id_ed25519',
                   mode='600', owner='alice:alice')
        _push_text(CALPINE, user_certs['alice'] + '\n',
                   '/home/alice/.ssh/id_ed25519-cert.pub',
                   mode='644', owner='alice:alice')

        # CALPINE trusts any host cert signed by our CA (for outbound to C2).
        _push_text(CALPINE, f'@cert-authority * {ca_pubkey}\n',
                   '/etc/ssh/ssh_known_hosts', mode='644')

        yield state

    finally:
        for c in ALL_CONTAINERS:
            subprocess.run(['lxc', 'delete', '--force', c], capture_output=True)


# ===========================================================================
# Registration / enrollment / issuance assertions
# ===========================================================================

def test_three_users_registered(lxc_env):
    """All three users must be fully registered (completed_at set)."""
    for username in USERNAMES:
        completed = _sqlite_value(
            f"SELECT completed_at FROM user WHERE username='{username}'")
        assert completed, f'{username} not found or registration incomplete'
    is_admin = _sqlite_value("SELECT is_admin FROM user WHERE username='alice'")
    assert is_admin == '1', 'alice (first user) must be admin'


def test_each_user_has_ssh_identity(lxc_env):
    """Registration must auto-create a UserCredential for each login user."""
    for username in USERNAMES:
        found = _sqlite_value(
            f"SELECT uc.id FROM user_credential uc "
            f"JOIN user usr ON usr.id = uc.user_id "
            f"WHERE usr.username='{username}'"
        )
        assert found, f'UserCredential for {username} not found'


def test_both_ubuntu_hosts_enrolled(lxc_env):
    """Both Ubuntu containers must be enrolled (public key stored, enrolled_at set)."""
    ips = lxc_env['ips']
    for c in SSH_CONTAINERS:
        ip          = ips[c]
        enrolled_at = _sqlite_value(f"SELECT enrolled_at FROM host WHERE hostname='{ip}'")
        pub_key     = _sqlite_value(
            f"SELECT sk.public_key FROM host h "
            f"JOIN ssh_key sk ON sk.id = h.host_key_id "
            f"WHERE h.hostname='{ip}'"
        )
        assert enrolled_at, f'Host {c} not enrolled'
        assert pub_key.startswith('ecdsa-sha2-nistp521 '), \
            f'Host {c} wrong key type: {pub_key[:60]}'


def test_host_certs_issued(lxc_env):
    """A valid host certificate must be stored for each Ubuntu container."""
    for c in SSH_CONTAINERS:
        cert = lxc_env['host_cert_data'][c]
        assert cert, f'No host cert data for {c}'
        assert 'ecdsa-sha2-nistp521-cert-v01@openssh.com' in cert


def test_user_certs_issued(lxc_env):
    """A valid user certificate must be stored for each registered user."""
    for username in USERNAMES:
        cert = lxc_env['user_certs'][username]
        assert cert, f'No user cert for {username}'


# ===========================================================================
# SSH connectivity – Ubuntu C1 → C2 (OpenSSH ↔ OpenSSH, full cert auth)
# ===========================================================================

@pytest.mark.parametrize('username', USERNAMES)
def test_ssh_succeeds_with_valid_certs(lxc_env, username):
    """Each user can SSH from C1 to C2 using certificate auth only (no authorized_keys)."""
    c2_ip  = lxc_env['ips'][C2]
    result = _ssh_from(C1, username, c2_ip)
    assert result.returncode == 0, (
        f'SSH failed for {username}:\n'
        f'stdout: {result.stdout}\nstderr: {result.stderr}'
    )
    assert 'hello' in result.stdout


# ===========================================================================
# Expired certificate rejection
# ===========================================================================

def test_expired_user_cert_rejected(lxc_env, tmp_path, user_keypairs):
    """An expired user certificate must be refused by the SSH server."""
    ca_key = lxc_env['ca_key_local']
    c2_ip  = lxc_env['ips'][C2]

    pub_path = tmp_path / 'alice.pub'
    pub_path.write_text(user_keypairs['alice']['public_key'] + '\n')
    expired_cert = _sign_expired_user_cert(str(pub_path), 'alice', ca_key)

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
        'SSH should have been rejected with an expired user cert, but succeeded.\n'
        f'stdout: {result.stdout}\nstderr: {result.stderr}'
    )


def test_expired_host_cert_rejected(lxc_env, tmp_path):
    """An expired host certificate must be refused by the SSH client."""
    ca_key     = lxc_env['ca_key_local']
    c2_ip      = lxc_env['ips'][C2]
    valid_cert = lxc_env['host_cert_data'][C2]

    host_pub = _lxc_exec(C2, 'cat', '/etc/ssh/ssh_host_ecdsa_key.pub').stdout.strip()
    pub_path = tmp_path / 'host.pub'
    pub_path.write_text(host_pub + '\n')
    expired_cert = _sign_expired_host_cert(str(pub_path), c2_ip, ca_key)

    _push_text(C2, expired_cert + '\n',
               '/etc/ssh/ssh_host_ecdsa_key-cert.pub', mode='644')
    _lxc_exec(C2, 'systemctl', 'reload', 'ssh')
    time.sleep(1)

    try:
        result = _ssh_from(C1, 'alice', c2_ip, cmd='echo should-not-reach')
        assert result.returncode != 0, (
            'SSH should have been rejected when C2 presents an expired host cert.\n'
            f'stdout: {result.stdout}\nstderr: {result.stderr}'
        )
    finally:
        _push_text(C2, valid_cert + '\n',
                   '/etc/ssh/ssh_host_ecdsa_key-cert.pub', mode='644')
        _lxc_exec(C2, 'systemctl', 'reload', 'ssh')
        time.sleep(1)


# ===========================================================================
# Dropbear interoperability (CALPINE – Alpine + Dropbear)
# ===========================================================================

def test_dropbear_p256_enrollment_rejected(lxc_env):
    """sshadmin must reject enrollment of a Dropbear P-256 ECDSA host key.

    Dropbear 2024.86 generates ecdsa-sha2-nistp256 keys natively.  sshadmin
    only accepts ecdsa-sha2-nistp521, so enrollment must fail with a clear
    error.  This validates key-type enforcement in the enrollment API.
    """
    result = lxc_env['alpine_enrollment_result']
    assert not result.get('ok'), \
        f'Expected enrollment to be rejected for P-256 key, but got ok=True: {result}'
    error_msg = result.get('error', '').lower()
    assert error_msg, f'Expected a non-empty error field, got: {result}'


def test_openssh_to_dropbear_pubkey_auth(lxc_env):
    """OpenSSH client (C1) authenticates to Alpine/Dropbear via authorized_keys.

    Dropbear does not support TrustedUserCAKeys, so user certificate auth is
    not applicable here.  Host identity is verified by the raw P-256 fingerprint
    stored in /etc/ssh/ssh_known_hosts on C1 (not a CA-signed host cert).
    """
    alpine_ip = lxc_env['ips'][CALPINE]
    # Use the plain P-256 algorithm — Dropbear presents a raw P-256 key, not
    # a cert, so the cert-v01 variant would cause a handshake failure.
    result = _ssh_from(C1, 'alice', alpine_ip,
                       host_key_algo='ecdsa-sha2-nistp256')
    assert result.returncode == 0, (
        f'SSH from C1 to Alpine/Dropbear failed:\n'
        f'stdout: {result.stdout}\nstderr: {result.stderr}'
    )
    assert 'hello' in result.stdout


def test_alpine_openssh_to_ubuntu_cert_auth(lxc_env):
    """Alpine's OpenSSH client authenticates to C2 Ubuntu using alice's user certificate.

    Verifies that an OpenSSH client built against musl libc (Alpine) correctly
    performs certificate-based authentication against an OpenSSH server built
    against glibc (Ubuntu).
    """
    c2_ip  = lxc_env['ips'][C2]
    # CALPINE's /etc/ssh/ssh_known_hosts has '@cert-authority * <ca_pubkey>' so
    # the client validates C2's host certificate through the CA.
    result = _ssh_from(CALPINE, 'alice', c2_ip)
    assert result.returncode == 0, (
        f'Alpine OpenSSH -> Ubuntu cert-based SSH failed:\n'
        f'stdout: {result.stdout}\nstderr: {result.stderr}'
    )
    assert 'hello' in result.stdout


# ===========================================================================
# sshadmin_add enrollment script tests
# ===========================================================================

# Systemd service unit for CAPP with SSH auth server enabled.
_SSHADMIN_SVC_SSH_ENABLED = (
    '[Unit]\nDescription=sshadmin test server\nAfter=network.target\n\n'
    '[Service]\nWorkingDirectory=/app\n'
    'ExecStart=/usr/bin/python3 /app/sshadmin.py\n'
    f'Environment="DATABASE_URL=sqlite:////{APP_DB}"\n'
    'Environment="SECRET_KEY=lxc-test-secret"\n'
    'Environment="SSH_CA_KEY=/app/ca_key"\n'
    'Restart=on-failure\n\n'
    '[Install]\nWantedBy=multi-user.target\n'
)

# Original service unit (SSH auth disabled so it doesn't conflict with other tests).
_SSHADMIN_SVC_SSH_DISABLED = (
    '[Unit]\nDescription=sshadmin test server\nAfter=network.target\n\n'
    '[Service]\nWorkingDirectory=/app\n'
    'ExecStart=/usr/bin/python3 /app/sshadmin.py\n'
    f'Environment="DATABASE_URL=sqlite:////{APP_DB}"\n'
    'Environment="SECRET_KEY=lxc-test-secret"\n'
    'Environment="SSH_CA_KEY=/app/ca_key"\n'
    'Environment="SSHADMIN_DISABLE_SSH_AUTH=1"\n'
    'Restart=on-failure\n\n'
    '[Install]\nWantedBy=multi-user.target\n'
)


@pytest.fixture(scope='session')
def lxc_enroll_env(lxc_env, user_keypairs):
    """
    Provision two fresh containers (Ubuntu + Alpine) and enroll them via
    sshadmin_add run from C1 (which already has alice's registered key).

    The fixture temporarily enables the SSH auth server on CAPP (needed by
    the add_machine exec command) and restores the original service on teardown.
    """
    ips = lxc_env['ips']
    app_ip = ips[CAPP]
    ca_pubkey = lxc_env['ca_pubkey']

    for c in ENROLL_CONTAINERS:
        subprocess.run(['lxc', 'delete', '--force', c], capture_output=True)

    _lxc('launch', UBUNTU_IMAGE, CENROLL_UBUNTU,
         '--config', 'security.privileged=true', timeout=300)
    _lxc('launch', ALPINE_IMAGE, CENROLL_ALPINE,
         '--config', 'security.privileged=true', timeout=300)

    state: dict = {}
    try:
        enroll_ips = {
            CENROLL_UBUNTU: _get_ip(CENROLL_UBUNTU),
            CENROLL_ALPINE: _get_ip(CENROLL_ALPINE),
        }
        state['ips'] = enroll_ips
        alice_pub = user_keypairs['alice']['public_key']

        # ------------------------------------------------------------------ #
        # CENROLL_UBUNTU: OpenSSH server + alice with sudo                    #
        # ------------------------------------------------------------------ #
        _lxc_exec(CENROLL_UBUNTU, 'apt-get', 'update', '-q', timeout=120)
        _lxc_exec(CENROLL_UBUNTU, 'apt-get', 'install', '-y', '-q',
                  'openssh-server', 'sudo', timeout=300)
        _lxc_exec(CENROLL_UBUNTU, 'useradd', '-m', '-s', '/bin/bash', 'alice')
        _lxc_exec(CENROLL_UBUNTU, 'bash', '-c',
                  'mkdir -p /home/alice/.ssh && chmod 700 /home/alice/.ssh '
                  '&& chown alice:alice /home/alice/.ssh')
        _push_text(CENROLL_UBUNTU, alice_pub + '\n',
                   '/home/alice/.ssh/authorized_keys',
                   mode='600', owner='alice:alice')
        _push_text(CENROLL_UBUNTU, 'alice ALL=(ALL) NOPASSWD:ALL\n',
                   '/etc/sudoers.d/alice', mode='440')

        # ------------------------------------------------------------------ #
        # CENROLL_ALPINE: OpenSSH (not Dropbear) + alice with sudo            #
        # ------------------------------------------------------------------ #
        _lxc_exec(CENROLL_ALPINE, 'apk', 'add', '--no-cache',
                  'openssh', 'sudo', timeout=300)
        # Generate all host key types so OpenSSH server has keys to present.
        _lxc_exec(CENROLL_ALPINE, 'ssh-keygen', '-A')
        # Pre-create the sshd_config.d directory and wire it into the config
        # so the drop-in written by sshadmin_add is loaded on reload.
        _lxc_exec(CENROLL_ALPINE, 'mkdir', '-p', '/etc/ssh/sshd_config.d')
        _lxc_exec(CENROLL_ALPINE, 'sh', '-c',
                  'echo "Include /etc/ssh/sshd_config.d/*.conf" >> /etc/ssh/sshd_config')
        _lxc_exec(CENROLL_ALPINE, '/usr/sbin/sshd')
        _lxc_exec(CENROLL_ALPINE, 'adduser', '-D', '-s', '/bin/sh', 'alice')
        _lxc_exec(CENROLL_ALPINE, 'mkdir', '-p', '/home/alice/.ssh')
        _lxc_exec(CENROLL_ALPINE, 'chmod', '700', '/home/alice/.ssh')
        _lxc_exec(CENROLL_ALPINE, 'chown', '-R', 'alice:alice', '/home/alice/.ssh')
        _push_text(CENROLL_ALPINE, alice_pub + '\n',
                   '/home/alice/.ssh/authorized_keys',
                   mode='600', owner='alice:alice')
        _push_text(CENROLL_ALPINE,
                   'Defaults !requiretty\nalice ALL=(ALL) NOPASSWD:ALL\n',
                   '/etc/sudoers.d/alice', mode='440')
        # Remove the P-256 ECDSA key generated by ssh-keygen -A so that
        # sshadmin_add can generate a P-521 key without an overwrite prompt.
        _lxc_exec(CENROLL_ALPINE, 'rm', '-f',
                  '/etc/ssh/ssh_host_ecdsa_key',
                  '/etc/ssh/ssh_host_ecdsa_key.pub')

        # ------------------------------------------------------------------ #
        # Restart CAPP with SSH auth server enabled (needed for add_machine)  #
        # ------------------------------------------------------------------ #
        _push_text(CAPP, _SSHADMIN_SVC_SSH_ENABLED,
                   '/etc/systemd/system/sshadmin.service')
        _lxc_exec(CAPP, 'systemctl', 'daemon-reload')
        _lxc_exec(CAPP, 'systemctl', 'restart', 'sshadmin')
        _wait_for_port(CAPP, APP_PORT, max_wait=60)
        _wait_for_ssh_port(CAPP, port=2222, max_wait=30)

        # ------------------------------------------------------------------ #
        # Download sshadmin_add to C1 and make it executable                  #
        # ------------------------------------------------------------------ #
        script_url = f'http://{app_ip}:{APP_PORT}/download/sshadmin_add'
        _lxc_exec(C1, 'python3', '-c',
                  f"import urllib.request; "
                  f"open('/usr/local/bin/sshadmin_add','wb')"
                  f".write(urllib.request.urlopen('{script_url}').read())")
        _lxc_exec(C1, 'chmod', '+x', '/usr/local/bin/sshadmin_add')

        # ------------------------------------------------------------------ #
        # Run sshadmin_add from C1 (as alice) targeting each enroll container  #
        # ------------------------------------------------------------------ #
        ubuntu_ip = enroll_ips[CENROLL_UBUNTU]
        alpine_ip = enroll_ips[CENROLL_ALPINE]

        ubuntu_result = subprocess.run(
            ['lxc', 'exec', C1, '--', 'su', '-', 'alice', '-c',
             f'sshadmin_add alice@{ubuntu_ip}'],
            capture_output=True, text=True, timeout=180,
        )
        state['ubuntu_result'] = ubuntu_result

        alpine_result = subprocess.run(
            ['lxc', 'exec', C1, '--', 'su', '-', 'alice', '-c',
             f'sshadmin_add alice@{alpine_ip}'],
            capture_output=True, text=True, timeout=180,
        )
        state['alpine_result'] = alpine_result

        # Full sshd restart on Alpine so it picks up the new P-521 host key,
        # host cert, and TrustedUserCAKeys config.  A simple SIGHUP is
        # unreliable because Alpine may not write a PID file to the expected
        # path; pkill + respawn is the safest approach.
        _lxc_exec(CENROLL_ALPINE, 'sh', '-c',
                  'pkill sshd || true', check=False)
        time.sleep(1)
        _lxc_exec(CENROLL_ALPINE, '/usr/sbin/sshd', check=False)
        _wait_for_ssh_port(CENROLL_ALPINE, port=22, max_wait=15)

        # CENROLL_UBUNTU and CENROLL_ALPINE need the CA in their global
        # known_hosts so cert-verified outbound SSH from C1 to them works
        # (the @cert-authority line covers host-cert verification).
        # (C1's /etc/ssh/ssh_known_hosts already has this from lxc_env.)

        yield state

    finally:
        # Restore CAPP to SSH-disabled configuration used by other tests.
        _push_text(CAPP, _SSHADMIN_SVC_SSH_DISABLED,
                   '/etc/systemd/system/sshadmin.service')
        _lxc_exec(CAPP, 'systemctl', 'daemon-reload', check=False)
        _lxc_exec(CAPP, 'systemctl', 'restart', 'sshadmin', check=False)

        for c in ENROLL_CONTAINERS:
            subprocess.run(['lxc', 'delete', '--force', c], capture_output=True)


def test_sshadmin_add_enrolls_ubuntu(lxc_enroll_env):
    """sshadmin_add must exit 0 and report successful enrollment for Ubuntu target."""
    r = lxc_enroll_env['ubuntu_result']
    assert r.returncode == 0, (
        f'sshadmin_add failed for Ubuntu:\nstdout: {r.stdout}\nstderr: {r.stderr}'
    )
    assert 'enrolled successfully' in r.stdout, \
        f'Expected "enrolled successfully" in output:\n{r.stdout}'


def test_sshadmin_add_enrolls_alpine(lxc_enroll_env):
    """sshadmin_add must exit 0 and report successful enrollment for Alpine target."""
    r = lxc_enroll_env['alpine_result']
    assert r.returncode == 0, (
        f'sshadmin_add failed for Alpine:\nstdout: {r.stdout}\nstderr: {r.stderr}'
    )
    assert 'enrolled successfully' in r.stdout, \
        f'Expected "enrolled successfully" in output:\n{r.stdout}'


def test_sshadmin_add_ubuntu_host_cert_in_db(lxc_enroll_env):
    """After sshadmin_add, the Ubuntu enrollment target must have a host cert in the DB."""
    ubuntu_ip = lxc_enroll_env['ips'][CENROLL_UBUNTU]
    # sshadmin_add registers the host by its FQDN (hostname -f on the container);
    # the container may report a short name or the IP.  We look up by prefix match.
    row = _sqlite_value(
        f"SELECT h.hostname FROM host h "
        f"JOIN ssh_key sk ON sk.id = h.host_key_id "
        f"JOIN certificate c ON c.ssh_key_id = sk.id "
        f"WHERE h.enrolled_at IS NOT NULL "
        f"ORDER BY c.id DESC LIMIT 1"
    )
    assert row, (
        f'No enrolled host with a host cert found after Ubuntu enrollment. '
        f'Expected target IP: {ubuntu_ip}'
    )


def test_sshadmin_add_alpine_host_cert_in_db(lxc_enroll_env):
    """After sshadmin_add, the Alpine enrollment target must have a host cert in the DB."""
    alpine_ip = lxc_enroll_env['ips'][CENROLL_ALPINE]
    row = _sqlite_value(
        f"SELECT h.hostname FROM host h "
        f"JOIN ssh_key sk ON sk.id = h.host_key_id "
        f"JOIN certificate c ON c.ssh_key_id = sk.id "
        f"WHERE h.enrolled_at IS NOT NULL "
        f"ORDER BY c.id DESC LIMIT 1"
    )
    assert row, (
        f'No enrolled host with a host cert found after Alpine enrollment. '
        f'Expected target IP: {alpine_ip}'
    )


def test_sshadmin_add_ubuntu_ssh_cert_auth(lxc_enroll_env, lxc_env):
    """After sshadmin_add enrollment, alice can SSH from C1 to Ubuntu using cert auth.

    The enrolled Ubuntu sshd trusts TrustedUserCAKeys (the sshadmin CA), so
    alice's existing user cert (signed by the same CA with principal 'alice')
    is accepted — without an entry in authorized_keys.
    """
    ubuntu_ip = lxc_enroll_env['ips'][CENROLL_UBUNTU]
    # Remove alice's authorized_keys on the enrollment target so we prove
    # the connection succeeds via cert auth only, not the raw public key.
    _lxc_exec(CENROLL_UBUNTU, 'rm', '-f', '/home/alice/.ssh/authorized_keys', check=False)
    _lxc_exec(CENROLL_UBUNTU, 'bash', '-c',
              "echo 'AuthorizedKeysFile none' "
              ">> /etc/ssh/sshd_config.d/99-sshadmin.conf && "
              "systemctl reload ssh || systemctl reload sshd || true")
    time.sleep(1)

    result = _ssh_from(C1, 'alice', ubuntu_ip)
    assert result.returncode == 0, (
        f'Cert-based SSH from C1 to enrolled Ubuntu failed:\n'
        f'stdout: {result.stdout}\nstderr: {result.stderr}'
    )
    assert 'hello' in result.stdout


def test_sshadmin_add_alpine_ssh_cert_auth(lxc_enroll_env, lxc_env):
    """After sshadmin_add enrollment, alice can SSH from C1 to Alpine using cert auth.

    Verifies that the full enrollment flow works end-to-end on an Alpine
    (musl/busybox) target: key collection, CA signing, cert installation, and
    TrustedUserCAKeys being respected by Alpine's OpenSSH server.
    """
    alpine_ip = lxc_enroll_env['ips'][CENROLL_ALPINE]
    # Remove raw-key fallback to force cert-only auth.
    _lxc_exec(CENROLL_ALPINE, 'rm', '-f', '/home/alice/.ssh/authorized_keys', check=False)
    _lxc_exec(CENROLL_ALPINE, 'sh', '-c',
              "printf 'AuthorizedKeysFile none\\n' "
              ">> /etc/ssh/sshd_config.d/99-sshadmin.conf && "
              "kill -HUP $(cat /var/run/sshd.pid 2>/dev/null || "
              "cat /run/sshd.pid 2>/dev/null) 2>/dev/null || true",
              check=False)
    time.sleep(1)

    result = _ssh_from(C1, 'alice', alpine_ip)
    assert result.returncode == 0, (
        f'Cert-based SSH from C1 to enrolled Alpine failed:\n'
        f'stdout: {result.stdout}\nstderr: {result.stderr}'
    )
    assert 'hello' in result.stdout
