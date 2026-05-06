"""Per-user visibility: non-admin sees only own; admin sees all."""
from datetime import datetime

import sshadmin
from conftest import latest_challenge, register_via_api


def _login(client, sign_fn, username):
    r = client.post('/login', data={'username': username})
    assert r.status_code == 302
    with sshadmin.app.app_context():
        ch = latest_challenge('login')
        token, nonce = ch.token, ch.nonce
    sig = sign_fn(nonce)
    r = client.post('/api/challenge_response', data={'token': token, 'signature': sig})
    assert r.status_code == 200
    client.get(f'/api/auth_status/{token}')


def _setup_two_users_with_hosts(client, sign, keypair, keypair_ed25519, ca_keys):
    """Alice (admin) + Bob (non-admin). Alice owns srv-a; Bob owns srv-b."""
    # Alice — first user, becomes admin. Creates srv-a.
    register_via_api(client, sign, keypair['public_key'], username='alice')
    client.post('/hosts/add', data={'hostname': 'srv-a'})
    client.get('/logout')

    # Bob — non-admin. Creates srv-b.
    register_via_api(
        client,
        lambda n: sign(n, private_path=keypair_ed25519['private_path']),
        keypair_ed25519['public_key'],
        username='bob',
    )
    client.post('/hosts/add', data={'hostname': 'srv-b'})
    client.get('/logout')


def test_non_admin_sees_only_own_hosts(client, keypair, sign, keypair_ed25519, ca_keys):
    _setup_two_users_with_hosts(client, sign, keypair, keypair_ed25519, ca_keys)

    _login(client, lambda n: sign(n, private_path=keypair_ed25519['private_path']), 'bob')
    r = client.get('/hosts')
    assert r.status_code == 200
    assert b'srv-b' in r.data
    assert b'srv-a' not in r.data


def test_admin_sees_all_hosts_with_owners_column(client, keypair, sign, keypair_ed25519, ca_keys):
    _setup_two_users_with_hosts(client, sign, keypair, keypair_ed25519, ca_keys)

    _login(client, sign, 'alice')
    r = client.get('/hosts')
    assert r.status_code == 200
    assert b'srv-a' in r.data
    assert b'srv-b' in r.data
    # Owners column header present
    assert b'Owners' in r.data


def test_non_admin_cannot_view_other_users_host_info(client, keypair, sign,
                                                     keypair_ed25519, host_keypair, ca_keys):
    # Alice enrolls srv-a (with a real pubkey so it's "is_enrolled").
    client.post('/register', data={'username': 'alice', 'public_key': keypair['public_key']})
    with sshadmin.app.app_context():
        ch = latest_challenge('register')
        token, nonce = ch.token, ch.nonce
    client.post('/api/challenge_response', data={
        'token': token, 'signature': sign(nonce),
        'hostname': 'srv-a', 'host_public_key': host_keypair['public_key'],
    })
    client.get(f'/api/auth_status/{token}')
    client.get('/logout')

    # Bob registers (non-admin).
    register_via_api(client,
                     lambda n: sign(n, private_path=keypair_ed25519['private_path']),
                     keypair_ed25519['public_key'], username='bob')

    with sshadmin.app.app_context():
        srv_a_id = sshadmin.Host.query.filter_by(hostname='srv-a').first().id

    r = client.get(f'/hosts/{srv_a_id}', follow_redirects=False)
    assert r.status_code == 302
    assert r.headers['Location'].endswith('/hosts')


def test_non_admin_sees_only_own_ssh_users(client, keypair, sign, keypair_ed25519, ca_keys):
    # Alice (admin): adds an SSHUser keyed to her.
    register_via_api(client, sign, keypair['public_key'], username='alice')
    client.post('/users/add', data={
        'username': 'alice-key',
        'public_key': 'ssh-ed25519 AAAA-fake-alice alice-key',
    })
    client.get('/users')          # consume flash before logging out
    client.get('/logout')
    # Wipe any residual session state between user contexts.
    with client.session_transaction() as s:
        s.clear()

    # Bob (non-admin): adds his own.
    register_via_api(client,
                     lambda n: sign(n, private_path=keypair_ed25519['private_path']),
                     keypair_ed25519['public_key'], username='bob')
    client.post('/users/add', data={
        'username': 'bob-key',
        'public_key': 'ssh-ed25519 AAAA-fake-bob bob-key',
    })
    client.get('/users')          # consume bob's flash

    # Bob lists users — sees only his.
    r = client.get('/users')
    assert r.status_code == 200
    assert b'bob-key' in r.data
    assert b'alice-key' not in r.data

    # Alice (admin) sees both.
    client.get('/logout')
    with client.session_transaction() as s:
        s.clear()
    _login(client, sign, 'alice')
    client.get('/users')
    r = client.get('/users')
    assert b'alice-key' in r.data
    assert b'bob-key' in r.data


def test_non_admin_cannot_delete_other_users_ssh_user(client, keypair, sign,
                                                     keypair_ed25519, ca_keys):
    register_via_api(client, sign, keypair['public_key'], username='alice')
    client.post('/users/add', data={
        'username': 'alice-key',
        'public_key': 'ssh-ed25519 AAAA-fake-alice alice-key',
    })
    with sshadmin.app.app_context():
        alice_user_id = sshadmin.SSHUser.query.filter_by(username='alice-key').first().id
    client.get('/logout')

    register_via_api(client,
                     lambda n: sign(n, private_path=keypair_ed25519['private_path']),
                     keypair_ed25519['public_key'], username='bob')

    r = client.post(f'/users/{alice_user_id}/delete', follow_redirects=True)
    assert b'only delete SSH users you created' in r.data
    with sshadmin.app.app_context():
        assert sshadmin.db.session.get(sshadmin.SSHUser, alice_user_id) is not None


def test_non_admin_cannot_delete_admin_share_target_can_leave(client, keypair, sign,
                                                              keypair_ed25519, ca_keys):
    """A co-owner can /hosts/<id>/delete to leave; remaining owners are unaffected."""
    register_via_api(client, sign, keypair['public_key'], username='alice')
    # Alice creates srv-shared and adds Bob via /share.
    client.post('/hosts/add', data={'hostname': 'srv-shared'})
    with sshadmin.app.app_context():
        host = sshadmin.Host.query.filter_by(hostname='srv-shared').first()
        host_id = host.id
        host.public_key = 'ecdsa-sha2-nistp521 AAAA-fake'
        host.enrolled_at = datetime.utcnow()
        host.enrollment_token = None
        sshadmin.db.session.commit()

    client.get('/logout')
    register_via_api(client,
                     lambda n: sign(n, private_path=keypair_ed25519['private_path']),
                     keypair_ed25519['public_key'], username='bob')
    with sshadmin.app.app_context():
        bob_id = sshadmin.User.query.filter_by(username='bob').first().id

    client.get('/logout')
    _login(client, sign, 'alice')
    client.post(f'/hosts/{host_id}/share', data={'user_id': bob_id})

    with sshadmin.app.app_context():
        host = sshadmin.db.session.get(sshadmin.Host, host_id)
        assert sorted(o.username for o in host.owners) == ['alice', 'bob']

    # Bob logs in and "leaves" — non-admin delete -> just removes his ownership.
    client.get('/logout')
    _login(client, lambda n: sign(n, private_path=keypair_ed25519['private_path']), 'bob')
    r = client.post(f'/hosts/{host_id}/delete', follow_redirects=False)
    assert r.status_code == 302

    with sshadmin.app.app_context():
        host = sshadmin.db.session.get(sshadmin.Host, host_id)
        assert host is not None
        assert [o.username for o in host.owners] == ['alice']
