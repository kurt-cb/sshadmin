"""Per-user visibility: non-admin sees only own; admin sees all."""
import sshadmin
from conftest import latest_challenge, register_via_api, set_host_enrolled


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
    register_via_api(client, sign, keypair['public_key'], username='alice')
    client.post('/hosts/add', data={'hostname': 'srv-a'})
    client.get('/logout')

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
    assert b'Owners' in r.data


def test_non_admin_cannot_view_other_users_host_info(client, keypair, sign,
                                                     keypair_ed25519, host_keypair, ca_keys):
    # Alice enrolls srv-a.
    client.post('/register', data={
        'username': 'alice', 'unix_username': 'alice',
        'public_key': keypair['public_key'],
    })
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


def test_non_admin_sees_only_own_credentials(client, keypair, sign, keypair_ed25519, ca_keys,
                                              host_keypair):
    """Non-admin user sees only their own credentials; admin sees all."""
    # Alice (admin) registers and creates a credential.
    register_via_api(client, sign, keypair['public_key'], username='alice',
                     unix_username='alice', hostname='srv-a.test',
                     host_public_key=host_keypair['public_key'])

    with sshadmin.app.app_context():
        alice_creds = sshadmin.UserCredential.query.join(sshadmin.User).filter(
            sshadmin.User.username == 'alice').all()
        assert len(alice_creds) == 1

    client.get('/logout')

    # Bob (non-admin) registers and creates a credential.
    import subprocess
    import tempfile
    from pathlib import Path
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / 'host_b'
        subprocess.run(['ssh-keygen', '-t', 'ecdsa', '-b', '521',
                        '-f', str(p), '-N', '', '-C', 'host:srv-b'],
                       check=True, capture_output=True)
        bob_host_key = (Path(d) / (p.name + '.pub')).read_text().strip()

    register_via_api(
        client,
        lambda n: sign(n, private_path=keypair_ed25519['private_path']),
        keypair_ed25519['public_key'],
        username='bob',
        unix_username='bob',
        hostname='srv-b.test',
        host_public_key=bob_host_key,
    )

    # Bob sees only his credential.
    r = client.get('/credentials')
    assert r.status_code == 200
    assert b'srv-b.test' in r.data
    assert b'srv-a.test' not in r.data

    # Alice (admin) sees both.
    client.get('/logout')
    _login(client, sign, 'alice')
    r = client.get('/credentials')
    assert b'srv-a.test' in r.data
    assert b'srv-b.test' in r.data


def test_non_admin_cannot_delete_other_users_credential(client, keypair, sign,
                                                        keypair_ed25519, ca_keys,
                                                        host_keypair):
    """Non-admin cannot delete another user's credential."""
    register_via_api(client, sign, keypair['public_key'], username='alice',
                     unix_username='alice', hostname='srv-a.test',
                     host_public_key=host_keypair['public_key'])

    with sshadmin.app.app_context():
        alice_cred_id = sshadmin.UserCredential.query.join(sshadmin.User).filter(
            sshadmin.User.username == 'alice').first().id

    client.get('/logout')

    register_via_api(client,
                     lambda n: sign(n, private_path=keypair_ed25519['private_path']),
                     keypair_ed25519['public_key'], username='bob')

    r = client.post(f'/credentials/{alice_cred_id}/delete', follow_redirects=True)
    assert b'only delete your own' in r.data
    with sshadmin.app.app_context():
        assert sshadmin.db.session.get(sshadmin.UserCredential, alice_cred_id) is not None


def test_non_admin_can_leave_shared_host(client, keypair, sign,
                                         keypair_ed25519, ca_keys):
    """A user can /hosts/<id>/delete to leave; remaining owners are unaffected."""
    register_via_api(client, sign, keypair['public_key'], username='alice')
    client.post('/hosts/add', data={'hostname': 'srv-shared'})
    with sshadmin.app.app_context():
        host = sshadmin.Host.query.filter_by(hostname='srv-shared').first()
        host_id = host.id
    set_host_enrolled(host_id)

    client.get('/logout')
    register_via_api(client,
                     lambda n: sign(n, private_path=keypair_ed25519['private_path']),
                     keypair_ed25519['public_key'], username='bob')
    with sshadmin.app.app_context():
        bob_id = sshadmin.User.query.filter_by(username='bob').first().id

    client.get('/logout')
    _login(client, sign, 'alice')
    client.post(f'/hosts/{host_id}/share', data={'user_id': bob_id, 'role': 'owner'})

    with sshadmin.app.app_context():
        host = sshadmin.db.session.get(sshadmin.Host, host_id)
        assert sorted(o.username for o in host.owners) == ['alice', 'bob']

    # Bob logs in and "leaves".
    client.get('/logout')
    _login(client, lambda n: sign(n, private_path=keypair_ed25519['private_path']), 'bob')
    r = client.post(f'/hosts/{host_id}/delete', follow_redirects=False)
    assert r.status_code == 302

    with sshadmin.app.app_context():
        host = sshadmin.db.session.get(sshadmin.Host, host_id)
        assert host is not None
        assert [o.username for o in host.owners] == ['alice']
