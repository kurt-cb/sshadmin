"""Direct API endpoint tests covering the public + login-required endpoints."""
from datetime import datetime, timedelta

import sshadmin
from conftest import latest_challenge, register_via_api


# ----------------- /api/ca-pubkey -----------------

def test_ca_pubkey_503_when_missing(client):
    r = client.get('/api/ca-pubkey')
    assert r.status_code == 503
    assert b'CA public key not configured' in r.data


def test_ca_pubkey_returns_pubkey(client, ca_keys):
    r = client.get('/api/ca-pubkey')
    assert r.status_code == 200
    assert r.headers['Content-Type'].startswith('text/plain')
    assert r.data.split()[0] in (b'ssh-rsa', b'ssh-ed25519',
                                  b'ecdsa-sha2-nistp256',
                                  b'ecdsa-sha2-nistp384',
                                  b'ecdsa-sha2-nistp521')


# ----------------- /api/ca-status -----------------

def test_ca_status_requires_login(client):
    r = client.get('/api/ca-status', follow_redirects=False)
    assert r.status_code == 302
    assert '/login' in r.headers['Location']


def test_ca_status_reports_when_logged_in(client, keypair, sign, ca_keys):
    register_via_api(client, sign, keypair['public_key'], username='alice')
    r = client.get('/api/ca-status')
    assert r.status_code == 200
    assert r.json == {'ca_available': True}


# ----------------- /api/auth/script -----------------

def test_auth_script_requires_token(client):
    r = client.get('/api/auth/script')
    assert r.status_code == 400


def test_auth_script_unknown_token(client):
    r = client.get('/api/auth/script?token=does-not-exist')
    assert r.status_code == 404


def test_auth_script_returns_script_for_active_challenge(client, keypair):
    client.post('/register', data={
        'username': 'alice', 'unix_username': 'alice',
        'public_key': keypair['public_key'],
    })
    with sshadmin.app.app_context():
        ch = latest_challenge('register')
        token, nonce = ch.token, ch.nonce

    r = client.get(f'/api/auth/script?token={token}')
    assert r.status_code == 200
    assert r.headers['Content-Type'].startswith('text/x-shellscript')
    body = r.data.decode()
    assert nonce in body
    # The script embeds the registered pubkey(s) in the REGISTERED_PUBKEYS array.
    key_parts = keypair['public_key'].split()
    assert key_parts[0] in body   # algorithm
    assert key_parts[1] in body   # base64
    assert sshadmin.SSHSIG_NAMESPACE in body
    # Registration scripts include host enrollment block.
    assert 'HOST_KEY' in body or 'host' in body.lower()


def test_auth_script_login_omits_host_enrollment(client, keypair, sign):
    register_via_api(client, sign, keypair['public_key'], username='alice')
    client.get('/logout')
    client.post('/login', data={'username': 'alice'})
    with sshadmin.app.app_context():
        ch = latest_challenge('login')
        token = ch.token

    r = client.get(f'/api/auth/script?token={token}')
    assert r.status_code == 200
    body = r.data.decode()
    # Login scripts do not include host enrollment sections.
    assert 'HOST_KEY_TYPE' not in body
    assert 'enrolling host' not in body.lower()


def test_auth_script_consumed_token(client, keypair, sign):
    register_via_api(client, sign, keypair['public_key'], username='alice')
    with sshadmin.app.app_context():
        ch = latest_challenge('register')
        token = ch.token

    r = client.get(f'/api/auth/script?token={token}')
    assert r.status_code == 409


def test_auth_script_expired_token(client, keypair):
    client.post('/register', data={
        'username': 'alice', 'unix_username': 'alice',
        'public_key': keypair['public_key'],
    })
    with sshadmin.app.app_context():
        ch = latest_challenge('register')
        ch.expires_at = datetime.utcnow() - timedelta(minutes=1)
        sshadmin.db.session.commit()
        token = ch.token

    r = client.get(f'/api/auth/script?token={token}')
    assert r.status_code == 410


# ----------------- /api/challenge_response -----------------

def test_challenge_response_requires_token_and_sig(client):
    r = client.post('/api/challenge_response', data={})
    assert r.status_code == 400


def test_challenge_response_invalid_token(client):
    r = client.post('/api/challenge_response', data={
        'token': 'nope', 'signature': 'sig',
    })
    assert r.status_code == 404


def test_challenge_response_already_used(client, keypair, sign):
    register_via_api(client, sign, keypair['public_key'], username='alice')
    with sshadmin.app.app_context():
        ch = latest_challenge('register')
        token, nonce = ch.token, ch.nonce
    sig = sign(nonce)
    r = client.post('/api/challenge_response', data={'token': token, 'signature': sig})
    assert r.status_code == 409


def test_challenge_response_expired(client, keypair, sign):
    client.post('/register', data={
        'username': 'alice', 'unix_username': 'alice',
        'public_key': keypair['public_key'],
    })
    with sshadmin.app.app_context():
        ch = latest_challenge('register')
        ch.expires_at = datetime.utcnow() - timedelta(minutes=1)
        sshadmin.db.session.commit()
        token, nonce = ch.token, ch.nonce
    sig = sign(nonce)
    r = client.post('/api/challenge_response', data={'token': token, 'signature': sig})
    assert r.status_code == 410


def test_challenge_response_with_host_enrolls_host(client, keypair, sign, host_keypair):
    client.post('/register', data={
        'username': 'alice', 'unix_username': 'alice',
        'public_key': keypair['public_key'],
    })
    with sshadmin.app.app_context():
        ch = latest_challenge('register')
        token, nonce = ch.token, ch.nonce
    sig = sign(nonce)

    r = client.post('/api/challenge_response', data={
        'token': token, 'signature': sig,
        'hostname': 'box1.example.com',
        'host_public_key': host_keypair['public_key'],
    })
    assert r.status_code == 200
    assert r.json['host']['enrolled'] is True

    with sshadmin.app.app_context():
        host = sshadmin.Host.query.filter_by(hostname='box1.example.com').first()
        assert host is not None
        assert host.is_enrolled
        # Compare algorithm + base64 only (comment may be stripped during normalization).
        assert host.public_key.split()[:2] == host_keypair['public_key'].split()[:2]


def test_challenge_response_rejects_wrong_host_key_type(client, keypair, sign, keypair_ed25519):
    client.post('/register', data={
        'username': 'alice', 'unix_username': 'alice',
        'public_key': keypair['public_key'],
    })
    with sshadmin.app.app_context():
        ch = latest_challenge('register')
        token, nonce = ch.token, ch.nonce
    sig = sign(nonce)

    # Pass an ed25519 key as the *host* key (not allowed — must be ecdsa-sha2-nistp521).
    r = client.post('/api/challenge_response', data={
        'token': token, 'signature': sig,
        'hostname': 'box1', 'host_public_key': keypair_ed25519['public_key'],
    })
    # Challenge is consumed (prevents replay) but registration is incomplete.
    assert r.status_code == 200
    assert r.json['ok'] is True
    assert r.json['host']['enrolled'] is False


# ----------------- /api/auth_status/<token> -----------------

def test_auth_status_unknown_token(client):
    r = client.get('/api/auth_status/no-such-token')
    assert r.status_code == 404


def test_auth_status_pending(client, keypair):
    client.post('/register', data={
        'username': 'alice', 'unix_username': 'alice',
        'public_key': keypair['public_key'],
    })
    with sshadmin.app.app_context():
        ch = latest_challenge('register')
        token = ch.token

    r = client.get(f'/api/auth_status/{token}')
    assert r.json['status'] == 'pending'


def test_auth_status_expired(client, keypair):
    client.post('/register', data={
        'username': 'alice', 'unix_username': 'alice',
        'public_key': keypair['public_key'],
    })
    with sshadmin.app.app_context():
        ch = latest_challenge('register')
        ch.expires_at = datetime.utcnow() - timedelta(minutes=1)
        sshadmin.db.session.commit()
        token = ch.token

    r = client.get(f'/api/auth_status/{token}')
    assert r.json['status'] == 'expired'


# ----------------- /api/enroll/host (admin-driven path) -----------------

def test_enroll_host_invalid_token(client):
    r = client.post('/api/enroll/host', data={
        'token': 'bogus', 'public_key': 'ecdsa-sha2-nistp521 AAAA...',
    })
    assert r.status_code == 403


def test_enroll_host_validates_key_type(client, keypair, sign, keypair_ed25519, ca_keys):
    """The legacy admin-issued host enrollment path must reject non-P521 keys."""
    register_via_api(client, sign, keypair['public_key'], username='alice')
    r = client.post('/hosts/add', data={'hostname': 'srv1', 'description': ''})
    assert r.status_code == 302

    with sshadmin.app.app_context():
        host = sshadmin.Host.query.filter_by(hostname='srv1').first()
        token = host.enrollment_token

    r = client.post('/api/enroll/host', data={
        'token': token, 'public_key': keypair_ed25519['public_key'],
    })
    assert r.status_code == 400
    assert b'must be ecdsa-sha2-nistp521' in r.data


def test_enroll_host_completes_with_correct_key(client, keypair, sign, host_keypair, ca_keys):
    register_via_api(client, sign, keypair['public_key'], username='alice')
    r = client.post('/hosts/add', data={'hostname': 'srv2'})
    assert r.status_code == 302

    with sshadmin.app.app_context():
        host = sshadmin.Host.query.filter_by(hostname='srv2').first()
        token = host.enrollment_token

    r = client.post('/api/enroll/host', data={
        'token': token, 'public_key': host_keypair['public_key'],
    })
    assert r.status_code == 200
    assert r.json['ok'] is True
    assert r.json['hostname'] == 'srv2'
    assert 'cert_data' in r.json

    with sshadmin.app.app_context():
        host = sshadmin.Host.query.filter_by(hostname='srv2').first()
        assert host.is_enrolled
        assert host.enrollment_token is None


# ----------------- /api/enroll/script -----------------

def test_enroll_script_requires_token(client):
    r = client.get('/api/enroll/script')
    assert r.status_code == 403


def test_enroll_script_returns_script_for_pending_host(client, keypair, sign, ca_keys):
    register_via_api(client, sign, keypair['public_key'], username='alice')
    r = client.post('/hosts/add', data={'hostname': 'srv3'})
    assert r.status_code == 302
    with sshadmin.app.app_context():
        host = sshadmin.Host.query.filter_by(hostname='srv3').first()
        token, host_id = host.enrollment_token, host.id

    r = client.get(f'/api/enroll/script?token={token}&host_id={host_id}')
    assert r.status_code == 200
    body = r.data.decode()
    assert 'ssh-keygen' in body
    assert token in body
    assert 'srv3' in body


def test_enroll_script_token_host_id_mismatch(client, keypair, sign, ca_keys):
    register_via_api(client, sign, keypair['public_key'], username='alice')
    r = client.post('/hosts/add', data={'hostname': 'srv4'})
    with sshadmin.app.app_context():
        host = sshadmin.Host.query.filter_by(hostname='srv4').first()
        token = host.enrollment_token

    r = client.get(f'/api/enroll/script?token={token}&host_id=9999')
    assert r.status_code == 403
