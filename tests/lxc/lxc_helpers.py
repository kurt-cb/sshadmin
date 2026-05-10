"""
Shared constants, LXC wrappers, HTTP session, and SSH utilities
for the LXC integration-test suite.

Imported by both conftest.py (fixtures) and individual test files.
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


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Base containers
CAPP    = 'sshadmin-lxc-app'
C1      = 'sshadmin-lxc-c1'
C2      = 'sshadmin-lxc-c2'
CALPINE = 'sshadmin-lxc-alpine'

# Group-isolation containers
C_ACCT  = 'sshadmin-lxc-acct'
C_SALES = 'sshadmin-lxc-sales'
C_HR    = 'sshadmin-lxc-hr'

# sshadmin_add enrollment containers
CENROLL_UBUNTU = 'sshadmin-lxc-enroll-ubuntu'
CENROLL_ALPINE = 'sshadmin-lxc-enroll-alpine'

ALL_BASE_CONTAINERS   = [CAPP, C1, C2, CALPINE]
SSH_CONTAINERS        = [C1, C2]
GROUP_CONTAINERS      = [C_ACCT, C_SALES, C_HR]
ENROLL_CONTAINERS     = [CENROLL_UBUNTU, CENROLL_ALPINE]

USERNAMES    = ['alice', 'bob', 'carol']
UBUNTU_IMAGE = 'images:ubuntu/22.04'
ALPINE_IMAGE = 'images:alpine/3.21'

SSHSIG_NAMESPACE = 'sshadmin'
APP_DB   = '/app/instance/sshadmin.db'
APP_PORT = 5000

GROUP_PRIMARY_USER = {
    'accounting': 'alice',
    'sales':      'bob',
    'hr':         'carol',
}

_HOST_KEY_ALGO_CERT = 'ecdsa-sha2-nistp521-cert-v01@openssh.com'

# Systemd service units for CAPP (used by lxc_enroll_env fixture)
_SVC_EXEC = (
    'ExecStart=/usr/bin/python3 -m coverage run '
    '--append --rcfile=/app/.coveragerc /app/sshadmin.py\n'
)
_SVC_BASE = (
    '[Unit]\nDescription=sshadmin test server\nAfter=network.target\n\n'
    '[Service]\nWorkingDirectory=/app\n'
    + _SVC_EXEC
    + f'Environment="DATABASE_URL=sqlite:////{APP_DB}"\n'
    'Environment="SECRET_KEY=lxc-test-secret"\n'
    'Environment="SSH_CA_KEY=/app/ca_key"\n'
    'Restart=on-failure\n\n'
    '[Install]\nWantedBy=multi-user.target\n'
)
SSHADMIN_SVC_SSH_ENABLED = _SVC_BASE
SSHADMIN_SVC_SSH_DISABLED = _SVC_BASE.replace(
    'Restart=on-failure',
    'Environment="SSHADMIN_DISABLE_SSH_AUTH=1"\nRestart=on-failure',
)

# Coverage config pushed to CAPP before starting the service.
CAPP_COVERAGERC = (
    '[coverage:run]\n'
    'branch = True\n'
    'data_file = /app/.coverage.capp\n'
    'sigterm = true\n'
)


# ---------------------------------------------------------------------------
# LXC helpers
# ---------------------------------------------------------------------------

def lxc(*args: str, timeout: int = 180) -> subprocess.CompletedProcess:
    return subprocess.run(
        ['lxc'] + list(args),
        check=True, capture_output=True, text=True, timeout=timeout,
    )


def lxc_exec(container: str, *cmd: str, check: bool = True,
             timeout: int = 120) -> subprocess.CompletedProcess:
    return subprocess.run(
        ['lxc', 'exec', container, '--'] + list(cmd),
        check=check, capture_output=True, text=True, timeout=timeout,
    )


def push_text(container: str, content: str, remote_path: str,
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
        lxc_exec(container, 'chmod', mode, remote_path)
    if owner:
        lxc_exec(container, 'chown', owner, remote_path)


def push_file(container: str, local_path: str | Path, remote_path: str,
              mode: str | None = None, owner: str | None = None) -> None:
    subprocess.run(
        ['lxc', 'file', 'push', str(local_path), f'{container}{remote_path}'],
        check=True, capture_output=True,
    )
    if mode:
        lxc_exec(container, 'chmod', mode, remote_path)
    if owner:
        lxc_exec(container, 'chown', owner, remote_path)


def pull_file(container: str, remote_path: str, local_path: str | Path) -> None:
    subprocess.run(
        ['lxc', 'file', 'pull', f'{container}{remote_path}', str(local_path)],
        check=True, capture_output=True,
    )


def get_ip(container: str, max_wait: int = 120) -> str:
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


def wait_for_port(container: str, port: int, max_wait: int = 90) -> None:
    """Block until an HTTP server at *port* inside *container* answers."""
    deadline = time.monotonic() + max_wait
    while time.monotonic() < deadline:
        r = lxc_exec(
            container, 'python3', '-c',
            f"import urllib.request; urllib.request.urlopen('http://localhost:{port}/'); print('ok')",
            check=False,
        )
        if 'ok' in r.stdout:
            return
        time.sleep(2)
    log = lxc_exec(container, 'cat', '/tmp/sshadmin.log', check=False).stdout
    raise RuntimeError(
        f'Port {port} on {container} not ready after {max_wait}s.\nLog:\n{log[-3000:]}'
    )


def wait_for_ssh_port(container: str, port: int = 22, max_wait: int = 30) -> None:
    """Block until an SSH server at *port* inside *container* accepts a TCP connection."""
    deadline = time.monotonic() + max_wait
    while time.monotonic() < deadline:
        r = lxc_exec(
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


def sqlite_value(query: str) -> str:
    """Run *query* against sshadmin's SQLite DB inside CAPP; return first column of first row."""
    r = lxc_exec(CAPP, 'python3', '-c', f"""
import sqlite3
conn = sqlite3.connect({APP_DB!r})
row  = conn.execute({query!r}).fetchone()
print(row[0] if row else '', end='')
""")
    return r.stdout.strip()


def push_sshadmin_source(container: str) -> None:
    """Bundle the sshadmin source tree and push it to /app inside *container*."""
    root = Path(__file__).resolve().parent.parent.parent
    with tempfile.NamedTemporaryFile(suffix='.tar.gz', delete=False) as f:
        tar_path = f.name
    try:
        subprocess.run(
            ['tar', '-C', str(root), '-czf', tar_path,
             'sshadmin.py', 'ssh_auth_server.py', 'templates', 'requirements.txt'],
            check=True, capture_output=True,
        )
        lxc_exec(container, 'mkdir', '-p', '/app')
        push_file(container, tar_path, '/tmp/sshadmin.tar.gz')
        lxc_exec(container, 'tar', '-xzf', '/tmp/sshadmin.tar.gz', '-C', '/app')
    finally:
        os.unlink(tar_path)


# ---------------------------------------------------------------------------
# HTTP session
# ---------------------------------------------------------------------------

class AdminSession:
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
        """POST form data; lists in *data* are expanded (doseq=True)."""
        body = urllib.parse.urlencode(data, doseq=True).encode()
        req  = urllib.request.Request(
            self._url(path), data=body,
            headers={'Content-Type': 'application/x-www-form-urlencoded'},
        )
        with self._opener.open(req) as resp:
            resp.read()
            return resp.geturl()

    def post_json(self, path: str, data: dict) -> dict:
        body = urllib.parse.urlencode(data, doseq=True).encode()
        req  = urllib.request.Request(
            self._url(path), data=body,
            headers={'Content-Type': 'application/x-www-form-urlencoded'},
        )
        try:
            with self._opener.open(req) as resp:
                return _json.loads(resp.read().decode())
        except urllib.error.HTTPError as e:
            return _json.loads(e.read().decode())


def http_register(session: AdminSession, sign_fn, public_key: str,
                  username: str, unix_username: str = None,
                  host_public_key: str = None, hostname: str = None) -> None:
    """Drive the sshadmin registration flow via HTTP, leaving the user logged in."""
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

    final_url = session.post('/register', {
        'username': username, 'unix_username': unix_username,
        'public_key': public_key,
    })
    token = final_url.rstrip('/').split('/')[-1]
    script = session.get(f'/api/auth/script?token={token}')
    m = re.search(r'^NONCE="([^"]+)"', script, re.MULTILINE)
    assert m, f'NONCE not found in auth script for {username}'
    sig = sign_fn(m.group(1))
    session.post('/api/challenge_response', {
        'token': token, 'signature': sig,
        'hostname': hostname, 'host_public_key': host_public_key,
    })
    status = session.get_json(f'/api/auth_status/{token}')
    assert status.get('status') == 'completed', \
        f'Registration of {username} did not complete: {status}'


def http_login(session: AdminSession, sign_fn, username: str) -> None:
    """Log in to sshadmin via the SSH challenge flow, setting the session cookie."""
    final_url = session.post('/login', {'username': username})
    token = final_url.rstrip('/').split('/')[-1]
    script = session.get(f'/api/auth/script?token={token}')
    m = re.search(r'^NONCE="([^"]+)"', script, re.MULTILINE)
    assert m, f'NONCE not found in login auth script for {username}'
    sig = sign_fn(m.group(1))
    session.post('/api/challenge_response', {'token': token, 'signature': sig})
    status = session.get_json(f'/api/auth_status/{token}')
    assert status.get('status') == 'completed', \
        f'Login of {username} did not complete: {status}'


# ---------------------------------------------------------------------------
# SSH helper
# ---------------------------------------------------------------------------

def ssh_from(container: str, username: str, target_ip: str,
             identity: str | None = None,
             cmd: str = 'echo hello',
             timeout: int = 30,
             host_key_algo: str = _HOST_KEY_ALGO_CERT,
             strict: bool = True) -> subprocess.CompletedProcess:
    """Run SSH from *container* as OS user *username* to *target_ip*."""
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
        'ssh -o BatchMode=yes -o ConnectTimeout=10 -o IdentitiesOnly=yes '
        + host_opts
        + f'-i {id_file} '
        + f"{username}@{target_ip} '{cmd}'"
    )
    return subprocess.run(
        ['lxc', 'exec', container, '--', 'su', '-', username, '-c', ssh_cmd],
        capture_output=True, text=True, timeout=timeout, check=False,
    )


# ---------------------------------------------------------------------------
# Signing helpers
# ---------------------------------------------------------------------------

def make_sign_fn(priv_path: str):
    """Return a callable that signs a nonce string using ssh-keygen -Y sign."""
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


def sign_expired_user_cert(pub_key_path: str, username: str, ca_key: str) -> str:
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
            '-z', str(serial), dest,
        ], check=True, capture_output=True)
        return Path(dest[:-4] + '-cert.pub').read_text().strip()


def sign_expired_host_cert(pub_key_path: str, hostname: str, ca_key: str) -> str:
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
            '-z', str(serial), dest,
        ], check=True, capture_output=True)
        return Path(dest[:-4] + '-cert.pub').read_text().strip()
