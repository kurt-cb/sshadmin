"""Pytest fixtures for sshadmin tests.

Sets up env vars BEFORE importing sshadmin (config is read at import time),
provides a fresh DB per test, and exposes a real ECDSA P-521 keypair plus
a `sign` helper that produces real SSHSIG signatures via ssh-keygen.
"""
import os
import sys
import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest

# --- Configure env BEFORE sshadmin import ---
_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT))

_TESTDIR = Path(tempfile.mkdtemp(prefix='sshadmin-tests-'))
os.environ['DATABASE_URL'] = f'sqlite:///{_TESTDIR}/test.db'
os.environ['SSHADMIN_CA_KEY_PATH'] = str(_TESTDIR / 'ca_key')
os.environ['SECRET_KEY'] = 'test-secret-do-not-use'

import sshadmin  # noqa: E402


def pytest_sessionfinish(session, exitstatus):
    shutil.rmtree(_TESTDIR, ignore_errors=True)


@pytest.fixture
def app():
    """Fresh-DB Flask app with testing flags."""
    sshadmin.app.config['TESTING'] = True
    with sshadmin.app.app_context():
        sshadmin.db.drop_all()
        sshadmin.db.create_all()
        try:
            yield sshadmin.app
        finally:
            sshadmin.db.session.remove()
            sshadmin.db.drop_all()


@pytest.fixture
def client(app):
    with app.test_client() as c:
        yield c


@pytest.fixture(scope='session')
def keypair(tmp_path_factory):
    """Generate one ECDSA P-521 keypair for the whole session."""
    d = tmp_path_factory.mktemp('keys')
    priv = d / 'id_test'
    subprocess.run(
        ['ssh-keygen', '-t', 'ecdsa', '-b', '521', '-f', str(priv), '-N', '', '-C', 'pytest'],
        check=True, capture_output=True,
    )
    return {
        'private_path': str(priv),
        'public_path': str(priv) + '.pub',
        'public_key': (d / (priv.name + '.pub')).read_text().strip(),
    }


@pytest.fixture(scope='session')
def keypair_ed25519(tmp_path_factory):
    d = tmp_path_factory.mktemp('keys-ed25519')
    priv = d / 'id_ed'
    subprocess.run(
        ['ssh-keygen', '-t', 'ed25519', '-f', str(priv), '-N', '', '-C', 'pytest-ed'],
        check=True, capture_output=True,
    )
    return {
        'private_path': str(priv),
        'public_key': (d / (priv.name + '.pub')).read_text().strip(),
    }


@pytest.fixture
def sign(keypair):
    """Return a callable that signs an arbitrary nonce with the session keypair."""
    def _sign(nonce: str, namespace: str = sshadmin.SSHSIG_NAMESPACE,
              private_path: str = keypair['private_path']) -> str:
        with tempfile.TemporaryDirectory() as tmp:
            n = Path(tmp) / 'nonce'
            n.write_text(nonce)
            subprocess.run(
                ['ssh-keygen', '-Y', 'sign',
                 '-f', private_path, '-n', namespace, str(n)],
                check=True, capture_output=True,
            )
            return (Path(tmp) / 'nonce.sig').read_text()
    return _sign


@pytest.fixture
def ca_keys():
    """Generate a real CA at the configured path; cleaned up after the test."""
    ca_path = sshadmin.cert_gen.ca_key
    for p in (ca_path, ca_path + '.pub'):
        if os.path.exists(p):
            os.remove(p)
    sshadmin.cert_gen.generate_ca(comment='pytest CA')
    yield
    for p in (ca_path, ca_path + '.pub'):
        if os.path.exists(p):
            os.remove(p)


@pytest.fixture
def host_keypair(tmp_path_factory):
    """ECDSA P-521 keypair simulating a host being enrolled."""
    d = tmp_path_factory.mktemp('host-keys')
    priv = d / 'host_key'
    subprocess.run(
        ['ssh-keygen', '-t', 'ecdsa', '-b', '521', '-f', str(priv), '-N', '', '-C', 'host:test'],
        check=True, capture_output=True,
    )
    return {
        'private_path': str(priv),
        'public_key': (d / (priv.name + '.pub')).read_text().strip(),
    }


# --- Helpers ---

def latest_challenge(purpose: str = None):
    q = sshadmin.Challenge.query.order_by(sshadmin.Challenge.id.desc())
    if purpose is not None:
        q = q.filter_by(purpose=purpose)
    return q.first()


def register_via_api(client, sign, public_key, username='alice'):
    """Drive the full register flow; returns the User row at the end."""
    r = client.post('/register', data={'username': username, 'public_key': public_key})
    assert r.status_code == 302, r.data
    with sshadmin.app.app_context():
        ch = latest_challenge('register')
        token, nonce = ch.token, ch.nonce
    sig = sign(nonce)
    r = client.post('/api/challenge_response', data={'token': token, 'signature': sig})
    assert r.status_code == 200, r.data
    r = client.get(f'/api/auth_status/{token}')
    assert r.json['status'] == 'completed', r.json
    with sshadmin.app.app_context():
        return sshadmin.User.query.filter_by(username=username).first()
