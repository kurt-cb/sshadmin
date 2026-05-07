"""End-to-end tests for the SSH-based auth server.

Covers the happy path (token consumed via SSH after pubkey auth) plus the
expected failure modes (wrong key, unknown user, cross-user token, expired
token, already-consumed token).
"""
from __future__ import annotations

import os
import socket
import threading
import time
from datetime import datetime, timedelta
from pathlib import Path

import paramiko
import pytest

import sshadmin
from conftest import latest_challenge, register_via_api, _TESTDIR
from ssh_auth_server import start_ssh_auth_server


# ---------- Fixtures ----------

@pytest.fixture
def ssh_server(app):
    """Bind the SSH auth server to a random localhost port; tear down on exit."""
    host_key_path = str(_TESTDIR / 'ssh_host_key_test')
    sock = start_ssh_auth_server(
        app=sshadmin.app, db=sshadmin.db,
        models={'User': sshadmin.User, 'Challenge': sshadmin.Challenge,
                'finalize_challenge': sshadmin._finalize_consumed_challenge},
        host='127.0.0.1', port=0,
        host_key_path=host_key_path,
    )
    port = sock.getsockname()[1]
    yield {'host': '127.0.0.1', 'port': port, 'socket': sock}
    try:
        sock.close()
    except Exception:
        pass


# ---------- Helpers ----------

def _load_pkey(key_path):
    """Load a private key file as the right paramiko PKey subclass.

    paramiko's `key_filename=` autodetection in SSHClient.connect is flaky for
    OpenSSH-format ECDSA-P521 keys; loading explicitly avoids the issue.
    """
    for cls in (paramiko.ECDSAKey, paramiko.Ed25519Key, paramiko.RSAKey):
        try:
            return cls.from_private_key_file(key_path)
        except paramiko.SSHException:
            continue
    raise RuntimeError(f'could not load key {key_path}')


def _ssh_send_token(host, port, username, key_path, token, *, recv_timeout=5.0):
    """Open an SSH session, paste the token, and return the server's text output.

    Returns the bytes the server sent back after we wrote the token.
    """
    pkey = _load_pkey(key_path)
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(
        host, port=port, username=username,
        pkey=pkey,
        look_for_keys=False, allow_agent=False,
        banner_timeout=10, auth_timeout=10,
    )
    try:
        chan = client.invoke_shell()
        chan.settimeout(recv_timeout)

        # Wait for the welcome banner / Token: prompt to arrive.
        seen = bytearray()
        deadline = time.monotonic() + recv_timeout
        while time.monotonic() < deadline:
            if chan.recv_ready():
                seen += chan.recv(4096)
                if b'Token:' in seen:
                    break
            time.sleep(0.05)

        chan.send((token + '\r').encode())

        # Drain response until channel closes or timeout.
        deadline = time.monotonic() + recv_timeout
        out = bytearray()
        while time.monotonic() < deadline:
            if chan.recv_ready():
                chunk = chan.recv(4096)
                if not chunk:
                    break
                out += chunk
            elif chan.exit_status_ready() or chan.closed:
                # final drain
                if chan.recv_ready():
                    out += chan.recv(4096)
                break
            else:
                time.sleep(0.05)
        return bytes(seen + out)
    finally:
        client.close()


def _wait_for_consumed(token, timeout=2.0):
    """Poll the DB until the challenge with `token` is consumed (or timeout)."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        with sshadmin.app.app_context():
            ch = sshadmin.Challenge.query.filter_by(token=token).first()
            if ch and ch.consumed_at is not None:
                return ch
        time.sleep(0.05)
    return None


# ---------- Tests ----------

def test_happy_path_register_via_ssh(client, keypair, sign, ssh_server):
    """Begin a register flow in the browser, finish it via SSH."""
    r = client.post('/register', data={'username': 'alice', 'public_key': keypair['public_key']})
    assert r.status_code == 302
    with sshadmin.app.app_context():
        ch = latest_challenge('register')
        token = ch.token

    out = _ssh_send_token(
        ssh_server['host'], ssh_server['port'],
        'alice', keypair['private_path'], token,
    )
    assert b'OK: challenge consumed for alice' in out

    consumed = _wait_for_consumed(token)
    assert consumed is not None

    # The browser polling endpoint should now finish the login.
    r = client.get(f'/api/auth_status/{token}')
    assert r.json['status'] == 'completed'

    # Auto-created SSHUser from the registration finalizer ran.
    with sshadmin.app.app_context():
        assert sshadmin.SSHUser.query.filter_by(username='alice').count() == 1


def test_happy_path_login_via_ssh(client, keypair, sign, ssh_server):
    register_via_api(client, sign, keypair['public_key'], username='alice')
    client.get('/logout')

    r = client.post('/login', data={'username': 'alice'})
    assert r.status_code == 302
    with sshadmin.app.app_context():
        ch = latest_challenge('login')
        token = ch.token

    out = _ssh_send_token(
        ssh_server['host'], ssh_server['port'],
        'alice', keypair['private_path'], token,
    )
    assert b'OK: challenge consumed for alice' in out

    consumed = _wait_for_consumed(token)
    assert consumed is not None

    r = client.get(f'/api/auth_status/{token}')
    assert r.json['status'] == 'completed'


def _try_connect(host, port, username, key_path):
    pkey = _load_pkey(key_path)
    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        c.connect(host, port=port, username=username, pkey=pkey,
                  look_for_keys=False, allow_agent=False, auth_timeout=5)
    finally:
        c.close()


def test_unknown_username_auth_fails(client, keypair, sign, ssh_server):
    register_via_api(client, sign, keypair['public_key'], username='alice')
    with pytest.raises(paramiko.AuthenticationException):
        _try_connect(ssh_server['host'], ssh_server['port'],
                     'ghost', keypair['private_path'])


def test_wrong_key_auth_fails(client, keypair, sign, keypair_ed25519, ssh_server):
    """User registered with `keypair`; offering `keypair_ed25519` instead must fail."""
    register_via_api(client, sign, keypair['public_key'], username='alice')
    with pytest.raises(paramiko.AuthenticationException):
        _try_connect(ssh_server['host'], ssh_server['port'],
                     'alice', keypair_ed25519['private_path'])


def test_pending_user_with_expired_challenge_auth_fails(client, keypair, ssh_server):
    """A pending user whose register challenge has expired cannot SSH-auth."""
    client.post('/register', data={'username': 'alice', 'public_key': keypair['public_key']})
    # Mark the challenge as expired (so the user has no active register window).
    with sshadmin.app.app_context():
        ch = latest_challenge('register')
        ch.expires_at = datetime.utcnow() - timedelta(minutes=1)
        sshadmin.db.session.commit()

    with pytest.raises(paramiko.AuthenticationException):
        _try_connect(ssh_server['host'], ssh_server['port'],
                     'alice', keypair['private_path'])


def test_cross_user_token_rejected(client, keypair, sign, keypair_ed25519, ssh_server):
    """Authenticated as alice, but pasted bob's token -> error, no consume."""
    # Alice and Bob both register normally first.
    register_via_api(client, sign, keypair['public_key'], username='alice')
    client.get('/logout')
    register_via_api(
        client,
        lambda n: sign(n, private_path=keypair_ed25519['private_path']),
        keypair_ed25519['public_key'], username='bob',
    )
    client.get('/logout')

    # Bob starts a fresh login challenge.
    client.post('/login', data={'username': 'bob'})
    with sshadmin.app.app_context():
        bob_token = latest_challenge('login').token

    # Alice authenticates via SSH and tries to consume bob's token.
    out = _ssh_send_token(
        ssh_server['host'], ssh_server['port'],
        'alice', keypair['private_path'], bob_token,
    )
    assert b'belongs to a different user' in out

    with sshadmin.app.app_context():
        assert sshadmin.Challenge.query.filter_by(token=bob_token).first().consumed_at is None


def test_unknown_token_rejected(client, keypair, sign, ssh_server):
    register_via_api(client, sign, keypair['public_key'], username='alice')
    out = _ssh_send_token(
        ssh_server['host'], ssh_server['port'],
        'alice', keypair['private_path'], 'no-such-token-at-all',
    )
    assert b'unknown token' in out


def test_already_consumed_token_rejected(client, keypair, sign, ssh_server):
    register_via_api(client, sign, keypair['public_key'], username='alice')
    client.get('/logout')
    client.post('/login', data={'username': 'alice'})
    with sshadmin.app.app_context():
        ch = latest_challenge('login')
        token, nonce = ch.token, ch.nonce

    sig = sign(nonce)
    r = client.post('/api/challenge_response', data={'token': token, 'signature': sig})
    assert r.status_code == 200

    out = _ssh_send_token(
        ssh_server['host'], ssh_server['port'],
        'alice', keypair['private_path'], token,
    )
    assert b'token already used' in out


def test_expired_token_rejected(client, keypair, sign, ssh_server):
    register_via_api(client, sign, keypair['public_key'], username='alice')
    client.get('/logout')
    client.post('/login', data={'username': 'alice'})
    with sshadmin.app.app_context():
        ch = latest_challenge('login')
        ch.expires_at = datetime.utcnow() - timedelta(minutes=1)
        sshadmin.db.session.commit()
        token = ch.token

    out = _ssh_send_token(
        ssh_server['host'], ssh_server['port'],
        'alice', keypair['private_path'], token,
    )
    assert b'token expired' in out


def test_await_page_renders_ssh_option(client, keypair, sign):
    """The auth_await page must include the SSH command + token blocks."""
    register_via_api(client, sign, keypair['public_key'], username='alice')
    client.get('/logout')

    r = client.post('/login', data={'username': 'alice'}, follow_redirects=False)
    r = client.get(r.headers['Location'])
    body = r.data.decode()
    assert 'PuTTY' in body
    assert 'TeraTerm' in body
    assert 'ssh -p ' in body
    assert 'alice@' in body
    # The new exec one-liner form ('auth TOKEN') is also shown.
    assert 'auth ' in body


# ---------- exec channel (`ssh user@host auth TOKEN`) ----------

def _ssh_exec_auth(host, port, username, key_path, token, *, recv_timeout=5.0):
    """Run `ssh user@host auth <token>` against the auth server. Returns (stdout, exit_status)."""
    pkey = _load_pkey(key_path)
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(
        host, port=port, username=username, pkey=pkey,
        look_for_keys=False, allow_agent=False,
        banner_timeout=10, auth_timeout=10,
    )
    try:
        chan = client.get_transport().open_session()
        chan.settimeout(recv_timeout)
        chan.exec_command(f'auth {token}')
        # Wait until exit status is available or timeout.
        deadline = time.monotonic() + recv_timeout
        out = bytearray()
        while time.monotonic() < deadline:
            if chan.recv_ready():
                out += chan.recv(4096)
            if chan.exit_status_ready():
                while chan.recv_ready():
                    out += chan.recv(4096)
                return bytes(out), chan.recv_exit_status()
            time.sleep(0.05)
        return bytes(out), -1
    finally:
        client.close()


def test_ssh_exec_auth_happy_path(client, keypair, sign, ssh_server):
    """`ssh user@host auth TOKEN` consumes the challenge in one shot."""
    register_via_api(client, sign, keypair['public_key'], username='alice')
    client.get('/logout')

    r = client.post('/login', data={'username': 'alice'})
    assert r.status_code == 302
    with sshadmin.app.app_context():
        token = latest_challenge('login').token

    out, status = _ssh_exec_auth(
        ssh_server['host'], ssh_server['port'],
        'alice', keypair['private_path'], token,
    )
    assert status == 0, (status, out)
    assert b'OK: challenge consumed for alice' in out

    consumed = _wait_for_consumed(token)
    assert consumed is not None
    r = client.get(f'/api/auth_status/{token}')
    assert r.json['status'] == 'completed'


def test_ssh_exec_usage_error(client, keypair, sign, ssh_server):
    register_via_api(client, sign, keypair['public_key'], username='alice')

    pkey = _load_pkey(keypair['private_path'])
    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(ssh_server['host'], port=ssh_server['port'],
              username='alice', pkey=pkey,
              look_for_keys=False, allow_agent=False)
    try:
        chan = c.get_transport().open_session()
        chan.exec_command('whoami')  # not 'auth ...'
        deadline = time.monotonic() + 5
        out = bytearray()
        while time.monotonic() < deadline:
            if chan.recv_ready():
                out += chan.recv(4096)
            if chan.exit_status_ready():
                break
            time.sleep(0.05)
        assert chan.recv_exit_status() == 2
        assert b'Usage:' in bytes(out)
    finally:
        c.close()


def test_ssh_exec_bad_token(client, keypair, sign, ssh_server):
    register_via_api(client, sign, keypair['public_key'], username='alice')
    out, status = _ssh_exec_auth(
        ssh_server['host'], ssh_server['port'],
        'alice', keypair['private_path'], 'nonexistent-token-xyz',
    )
    assert status == 1
    assert b'unknown token' in out
