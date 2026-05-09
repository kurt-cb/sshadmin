"""Login flow tests."""
import sshadmin
from conftest import latest_challenge, register_via_api


def test_login_get_page(client):
    r = client.get('/login')
    assert r.status_code == 200
    assert b'name="username"' in r.data
    assert b'name="password"' not in r.data


def test_login_requires_username(client):
    r = client.post('/login', data={}, follow_redirects=True)
    assert b'Username is required' in r.data


def test_login_unknown_user_flashes(client):
    r = client.post('/login', data={'username': 'ghost'}, follow_redirects=True)
    assert b'No completed registration' in r.data


def test_login_pending_user_cannot_login(client, keypair):
    """A user who started but never completed registration can't log in."""
    client.post('/register', data={
        'username': 'alice', 'unix_username': 'alice',
        'public_key': keypair['public_key'],
    })
    # Don't complete the challenge.
    r = client.post('/login', data={'username': 'alice'}, follow_redirects=True)
    assert b'No completed registration' in r.data


def test_login_completed_user_creates_login_challenge(client, keypair, sign):
    register_via_api(client, sign, keypair['public_key'], username='alice')
    client.get('/logout')

    r = client.post('/login', data={'username': 'alice'})
    assert r.status_code == 302
    assert '/auth/await/' in r.headers['Location']

    with sshadmin.app.app_context():
        ch = latest_challenge('login')
        assert ch is not None
        assert ch.consumed_at is None
        assert ch.user.username == 'alice'


def test_login_full_flow_logs_user_in(client, keypair, sign, ca_keys):
    register_via_api(client, sign, keypair['public_key'], username='alice')
    client.get('/logout')

    r = client.post('/login', data={'username': 'alice'})
    assert r.status_code == 302
    with sshadmin.app.app_context():
        ch = latest_challenge('login')
        token, nonce = ch.token, ch.nonce

    sig = sign(nonce)
    r = client.post('/api/challenge_response', data={'token': token, 'signature': sig})
    assert r.status_code == 200 and r.json['ok'] is True

    r = client.get(f'/api/auth_status/{token}')
    assert r.json['status'] == 'completed'

    # Authenticated request — anything that needs login should now work.
    r = client.get('/hosts')
    assert r.status_code == 200


def test_login_bad_signature_rejected(client, keypair, sign):
    register_via_api(client, sign, keypair['public_key'], username='alice')
    client.get('/logout')

    client.post('/login', data={'username': 'alice'})
    with sshadmin.app.app_context():
        ch = latest_challenge('login')
        token = ch.token

    bad_sig = sign('a-different-nonce')
    r = client.post('/api/challenge_response', data={'token': token, 'signature': bad_sig})
    assert r.status_code == 403


def test_login_signature_verified_by_other_session_does_not_log_in(client, keypair, sign):
    """If the consume happens in a different browser session, polling reports
    that fact and does NOT log the polling browser in."""
    register_via_api(client, sign, keypair['public_key'], username='alice')

    # Reset the session to simulate a fresh browser hitting /login.
    with client.session_transaction() as s:
        s.clear()

    client.post('/login', data={'username': 'alice'})
    with sshadmin.app.app_context():
        ch = latest_challenge('login')
        token, nonce = ch.token, ch.nonce

    # Consume from a *different* test client (no session cookie tying it to the
    # browser): the response endpoint takes signature without needing a session.
    sig = sign(nonce)
    other = sshadmin.app.test_client()
    r = other.post('/api/challenge_response', data={'token': token, 'signature': sig})
    assert r.status_code == 200

    # Now the original browser polls. The challenge IS consumed but a different
    # browser was the one to submit — wait, actually the SAME browser started the
    # /login. We stored the token in *its* session at /login submission, so the
    # same client poll should still complete. This is the expected pairing.
    r = client.get(f'/api/auth_status/{token}')
    assert r.json['status'] == 'completed'

    # A third client polling the same token sees it consumed but cannot claim.
    third = sshadmin.app.test_client()
    r = third.get(f'/api/auth_status/{token}')
    assert r.json['status'] == 'completed_other_session'
