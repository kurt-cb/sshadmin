"""Registration flow: form validation, challenge issuance, signature verification."""
from datetime import datetime, timedelta

import pytest

import sshadmin
from conftest import latest_challenge, register_via_api


def test_get_register_page(client):
    r = client.get('/register')
    assert r.status_code == 200
    assert b'SSH Public Key' in r.data
    assert b'unix_username' in r.data
    assert b'name="password"' not in r.data
    assert b'name="email"' not in r.data


def test_register_requires_username_and_pubkey(client):
    r = client.post('/register', data={})
    assert r.status_code == 302
    r = client.post('/register', data={'username': 'alice'}, follow_redirects=True)
    assert b'required' in r.data.lower()


def test_register_rejects_unknown_key_type(client):
    r = client.post('/register', data={
        'username': 'alice',
        'unix_username': 'alice',
        'public_key': 'ssh-rsa AAAAB3Nzac... user@host',
    }, follow_redirects=True)
    assert b'Public key must be one of' in r.data


def test_register_creates_pending_user_and_challenge(client, keypair):
    r = client.post('/register', data={
        'username': 'alice',
        'unix_username': 'alice',
        'public_key': keypair['public_key'],
    })
    assert r.status_code == 302
    assert '/auth/await/' in r.headers['Location']

    with sshadmin.app.app_context():
        u = sshadmin.User.query.filter_by(username='alice').first()
        assert u is not None
        assert u.completed_at is None

        ch = latest_challenge('register')
        assert ch is not None
        assert ch.user_id == u.id
        assert ch.consumed_at is None
        assert ch.expected_key is not None
        assert ch.unix_username == 'alice'
        # 30-min TTL
        ttl = ch.expires_at - datetime.utcnow()
        assert timedelta(minutes=29) < ttl <= timedelta(minutes=30)


def test_register_full_flow_logs_user_in(client, keypair, sign):
    user = register_via_api(client, sign, keypair['public_key'], username='alice')
    assert user is not None
    assert user.completed_at is not None
    assert user.is_admin is True  # first completed user

    # Subsequent dashboard request authenticated.
    r = client.get('/dashboard')
    # CA is missing in this test → admin redirect to /setup/ca; that's fine,
    # what we want to verify is that we are not redirected to /login.
    assert r.status_code in (200, 302)
    if r.status_code == 302:
        assert '/login' not in r.headers['Location']


def test_register_full_flow_creates_credential(client, keypair, sign):
    """Successful registration creates a UserCredential linking the user key to a host."""
    user = register_via_api(client, sign, keypair['public_key'], username='alice',
                            unix_username='alice', hostname='test.local')
    with sshadmin.app.app_context():
        creds = sshadmin.UserCredential.query.filter_by(user_id=user.id).all()
        assert len(creds) == 1
        cred = creds[0]
        assert cred.unix_username == 'alice'
        assert cred.host.hostname == 'test.local'
        assert cred.user_key is not None


def test_register_first_user_is_admin_subsequent_is_not(client, keypair, sign, keypair_ed25519):
    register_via_api(client, sign, keypair['public_key'], username='alice')
    client.get('/logout')

    def sign_with_b(nonce):
        return sign(nonce, private_path=keypair_ed25519['private_path'])

    bob = register_via_api(client, sign_with_b, keypair_ed25519['public_key'], username='bob')
    assert bob.is_admin is False
    with sshadmin.app.app_context():
        alice = sshadmin.User.query.filter_by(username='alice').first()
        assert alice.is_admin is True


def test_register_duplicate_completed_username_rejected(client, keypair, sign):
    register_via_api(client, sign, keypair['public_key'], username='alice')
    client.get('/logout')
    r = client.post('/register', data={
        'username': 'alice',
        'unix_username': 'alice',
        'public_key': keypair['public_key'],
    }, follow_redirects=True)
    assert b'already registered' in r.data.lower()


def test_register_resubmit_pending_user_issues_new_challenge(client, keypair, keypair_ed25519):
    """A user who started registration but never completed can re-submit with a new key."""
    r = client.post('/register', data={
        'username': 'alice',
        'unix_username': 'alice',
        'public_key': keypair['public_key'],
    })
    assert r.status_code == 302

    # Resubmit with a different (still allowed) public key for the same username.
    r = client.post('/register', data={
        'username': 'alice',
        'unix_username': 'alice',
        'public_key': keypair_ed25519['public_key'],
    })
    assert r.status_code == 302

    # The new challenge should record the new expected key.
    with sshadmin.app.app_context():
        ch = latest_challenge('register')
        parts = keypair_ed25519['public_key'].split()
        expected_parts = ch.expected_key.split()
        assert expected_parts[:2] == parts[:2]


def test_register_bad_signature_does_not_complete_user(client, keypair, sign, host_keypair):
    r = client.post('/register', data={
        'username': 'alice',
        'unix_username': 'alice',
        'public_key': keypair['public_key'],
    })
    assert r.status_code == 302

    with sshadmin.app.app_context():
        ch = latest_challenge('register')
        token = ch.token

    # Sign the WRONG message.
    bad_sig = sign('not-the-nonce')
    r = client.post('/api/challenge_response', data={
        'token': token, 'signature': bad_sig,
        'hostname': 'test.local',
        'host_public_key': host_keypair['public_key'],
    })
    assert r.status_code == 403
    assert r.json == {'ok': False, 'error': 'signature verification failed'}

    with sshadmin.app.app_context():
        u = sshadmin.User.query.filter_by(username='alice').first()
        assert u.completed_at is None
        ch = sshadmin.db.session.get(sshadmin.Challenge, ch.id)
        assert ch.consumed_at is None


def test_register_missing_host_data_rejected(client, keypair, sign):
    """Registration challenge_response must include hostname and host_public_key."""
    r = client.post('/register', data={
        'username': 'alice',
        'unix_username': 'alice',
        'public_key': keypair['public_key'],
    })
    assert r.status_code == 302

    with sshadmin.app.app_context():
        ch = latest_challenge('register')
        token, nonce = ch.token, ch.nonce

    sig = sign(nonce)
    # Submit WITHOUT host data.
    r = client.post('/api/challenge_response', data={
        'token': token, 'signature': sig,
    })
    assert r.status_code == 400
    assert 'hostname' in r.json['error'].lower() or 'host' in r.json['error'].lower()
