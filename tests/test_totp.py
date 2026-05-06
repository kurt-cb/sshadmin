"""TOTP setup, skip, verify, and login-via-TOTP tests."""
import pyotp
import pytest

import sshadmin
from conftest import latest_challenge, register_via_api


def _enable_totp_for(client):
    """Enable TOTP for the currently-logged-in user; return the secret."""
    r = client.get('/setup/totp')
    assert r.status_code == 200
    with client.session_transaction() as s:
        secret = s['pending_totp_secret']
    code = pyotp.TOTP(secret).now()
    r = client.post('/setup/totp', data={'action': 'verify', 'code': code})
    assert r.status_code == 302, r.data
    return secret


def test_setup_totp_get_renders_qr(client, keypair, sign):
    register_via_api(client, sign, keypair['public_key'], username='alice')
    r = client.get('/setup/totp')
    assert r.status_code == 200
    body = r.data.decode()
    # Inline SVG for the QR code is rendered.
    assert '<svg' in body
    # Provisioning URI uses our issuer and the username.
    assert 'sshadmin' in body
    assert 'alice' in body


def test_setup_totp_skip(client, keypair, sign):
    register_via_api(client, sign, keypair['public_key'], username='alice')
    client.get('/setup/totp')  # primes session secret
    r = client.post('/setup/totp', data={'action': 'skip'}, follow_redirects=False)
    assert r.status_code == 302
    with sshadmin.app.app_context():
        u = sshadmin.User.query.filter_by(username='alice').first()
        assert u.totp_enabled is False
        assert u.totp_secret is None


def test_setup_totp_verify_correct_code_enables(client, keypair, sign):
    register_via_api(client, sign, keypair['public_key'], username='alice')
    secret = _enable_totp_for(client)
    with sshadmin.app.app_context():
        u = sshadmin.User.query.filter_by(username='alice').first()
        assert u.totp_enabled is True
        assert u.totp_secret == secret


def test_setup_totp_rejects_wrong_code(client, keypair, sign):
    register_via_api(client, sign, keypair['public_key'], username='alice')
    client.get('/setup/totp')
    r = client.post('/setup/totp', data={'action': 'verify', 'code': '000000'},
                    follow_redirects=True)
    assert b'did not match' in r.data
    with sshadmin.app.app_context():
        u = sshadmin.User.query.filter_by(username='alice').first()
        assert u.totp_enabled is False


def test_setup_totp_already_enabled_redirects_to_profile(client, keypair, sign):
    register_via_api(client, sign, keypair['public_key'], username='alice')
    _enable_totp_for(client)
    r = client.get('/setup/totp', follow_redirects=False)
    assert r.status_code == 302
    assert r.headers['Location'].endswith('/profile')


def test_disable_totp_via_profile(client, keypair, sign, ca_keys):
    register_via_api(client, sign, keypair['public_key'], username='alice')
    _enable_totp_for(client)

    r = client.post('/profile/totp/disable', follow_redirects=False)
    assert r.status_code == 302
    with sshadmin.app.app_context():
        u = sshadmin.User.query.filter_by(username='alice').first()
        assert u.totp_enabled is False
        assert u.totp_secret is None


# ------- TOTP login path -------

def test_totp_login_completes_session(client, keypair, sign, ca_keys):
    register_via_api(client, sign, keypair['public_key'], username='alice')
    secret = _enable_totp_for(client)
    client.get('/logout')

    # Begin a login challenge.
    r = client.post('/login', data={'username': 'alice'})
    assert r.status_code == 302
    with sshadmin.app.app_context():
        ch = latest_challenge('login')
        token = ch.token

    # Submit a valid TOTP code instead of signing the challenge.
    code = pyotp.TOTP(secret).now()
    r = client.post('/api/totp_response', data={'token': token, 'code': code})
    assert r.status_code == 200, r.data
    assert r.json == {'ok': True, 'username': 'alice'}

    r = client.get(f'/api/auth_status/{token}')
    assert r.json['status'] == 'completed'

    r = client.get('/hosts')
    assert r.status_code == 200


def test_totp_login_rejects_wrong_code(client, keypair, sign):
    register_via_api(client, sign, keypair['public_key'], username='alice')
    _enable_totp_for(client)
    client.get('/logout')

    client.post('/login', data={'username': 'alice'})
    with sshadmin.app.app_context():
        ch = latest_challenge('login')
        token = ch.token

    r = client.post('/api/totp_response', data={'token': token, 'code': '000000'})
    assert r.status_code == 403
    assert r.json['error'] == 'invalid code'


def test_totp_endpoint_requires_totp_enabled(client, keypair, sign):
    register_via_api(client, sign, keypair['public_key'], username='alice')
    # No TOTP setup.
    client.get('/logout')

    client.post('/login', data={'username': 'alice'})
    with sshadmin.app.app_context():
        ch = latest_challenge('login')
        token = ch.token

    r = client.post('/api/totp_response', data={'token': token, 'code': '123456'})
    assert r.status_code == 403
    assert 'not enabled' in r.json['error']


def test_totp_cannot_be_used_for_registration(client, keypair, sign):
    """Registration challenges only accept signature responses; TOTP isn't enrolled yet."""
    client.post('/register', data={'username': 'alice', 'public_key': keypair['public_key']})
    with sshadmin.app.app_context():
        ch = latest_challenge('register')
        token = ch.token

    r = client.post('/api/totp_response', data={'token': token, 'code': '123456'})
    assert r.status_code == 403
    assert r.json['error'] == 'TOTP can only be used for login'


def test_totp_response_unknown_token(client):
    r = client.post('/api/totp_response', data={'token': 'nope', 'code': '123456'})
    assert r.status_code == 404


def test_totp_response_requires_token_and_code(client):
    r = client.post('/api/totp_response', data={'token': 'x'})
    assert r.status_code == 400


def test_login_await_shows_totp_option_when_enabled(client, keypair, sign):
    register_via_api(client, sign, keypair['public_key'], username='alice')
    _enable_totp_for(client)
    client.get('/logout')

    r = client.post('/login', data={'username': 'alice'}, follow_redirects=False)
    assert r.status_code == 302
    r = client.get(r.headers['Location'])
    body = r.data.decode()
    assert 'TOTP code' in body
    assert 'totp-form' in body
    assert 'one-liner' in body.lower() or 'oneliner' in body


def test_login_await_omits_totp_when_disabled(client, keypair, sign):
    register_via_api(client, sign, keypair['public_key'], username='alice')
    client.get('/logout')

    r = client.post('/login', data={'username': 'alice'}, follow_redirects=False)
    r = client.get(r.headers['Location'])
    body = r.data.decode()
    assert 'totp-form' not in body
    assert 'TOTP code' not in body
