"""Host sharing semantics: implicit re-registration, manual share, ownership-based delete."""
import sshadmin
from conftest import latest_challenge, register_via_api, set_host_enrolled


def _register_user(client, sign_fn, public_key, username):
    """Register and log out, leaving the test_client unauthenticated."""
    register_via_api(client, sign_fn, public_key, username=username)
    client.get('/logout')


def _login(client, sign_fn, username, ca_keys=None):
    r = client.post('/login', data={'username': username})
    assert r.status_code == 302, r.data
    with sshadmin.app.app_context():
        ch = latest_challenge('login')
        token, nonce = ch.token, ch.nonce
    sig = sign_fn(nonce)
    r = client.post('/api/challenge_response', data={'token': token, 'signature': sig})
    assert r.status_code == 200, r.data
    r = client.get(f'/api/auth_status/{token}')
    assert r.json['status'] == 'completed'


def _enroll_host_with_creator(client, hostname='srv1'):
    """Create a host record (creator becomes owner via /hosts/add)."""
    r = client.post('/hosts/add', data={'hostname': hostname})
    assert r.status_code == 302
    with sshadmin.app.app_context():
        return sshadmin.Host.query.filter_by(hostname=hostname).first().id


# ------- Sharing via re-registration (challenge_response with host info) -------

def test_implicit_share_on_matching_pubkey(client, keypair, sign,
                                           keypair_ed25519, host_keypair, ca_keys):
    """User A enrolls a host. User B re-registers the same hostname/pubkey -> co-user."""
    # User A registers + enrolls host via challenge_response.
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
        'hostname': 'box1', 'host_public_key': host_keypair['public_key'],
    })
    assert r.json['host']['enrolled'] is True
    client.get(f'/api/auth_status/{token}')
    client.get('/logout')

    # User B registers + tries to enroll same host (same pubkey).
    r = client.post('/register', data={
        'username': 'bob', 'unix_username': 'bob',
        'public_key': keypair_ed25519['public_key'],
    })
    with sshadmin.app.app_context():
        ch = latest_challenge('register')
        token, nonce = ch.token, ch.nonce
    sig = sign(nonce, private_path=keypair_ed25519['private_path'])
    r = client.post('/api/challenge_response', data={
        'token': token, 'signature': sig,
        'hostname': 'box1', 'host_public_key': host_keypair['public_key'],
    })
    assert r.status_code == 200
    assert r.json['host']['enrolled'] is True
    assert r.json['host'].get('shared') is True

    with sshadmin.app.app_context():
        host = sshadmin.Host.query.filter_by(hostname='box1').first()
        user_names = sorted(u.username for u in host.users)
        assert 'alice' in user_names
        assert 'bob' in user_names


def test_share_refused_on_mismatched_pubkey(client, keypair, sign,
                                            keypair_ed25519, host_keypair, ca_keys):
    """Same hostname + different pubkey: registration completes but host_enrolled=False."""
    # User A enrolls box1 with pubkey A.
    client.post('/register', data={
        'username': 'alice', 'unix_username': 'alice',
        'public_key': keypair['public_key'],
    })
    with sshadmin.app.app_context():
        ch = latest_challenge('register')
        token, nonce = ch.token, ch.nonce
    client.post('/api/challenge_response', data={
        'token': token, 'signature': sign(nonce),
        'hostname': 'box1', 'host_public_key': host_keypair['public_key'],
    })
    client.get(f'/api/auth_status/{token}')
    client.get('/logout')

    # User B tries box1 with a *different* host key.
    import subprocess
    import tempfile
    from pathlib import Path
    with tempfile.TemporaryDirectory() as tmp:
        priv = Path(tmp) / 'host_other'
        subprocess.run(['ssh-keygen', '-t', 'ecdsa', '-b', '521',
                        '-f', str(priv), '-N', '', '-C', 'host:other'],
                       check=True, capture_output=True)
        other_pub = (priv.parent / (priv.name + '.pub')).read_text().strip()

    client.post('/register', data={
        'username': 'bob', 'unix_username': 'bob',
        'public_key': keypair_ed25519['public_key'],
    })
    with sshadmin.app.app_context():
        ch = latest_challenge('register')
        token, nonce = ch.token, ch.nonce
    sig = sign(nonce, private_path=keypair_ed25519['private_path'])
    r = client.post('/api/challenge_response', data={
        'token': token, 'signature': sig,
        'hostname': 'box1', 'host_public_key': other_pub,
    })
    assert r.status_code == 200
    assert r.json['ok'] is True  # Bob still gets registered.
    assert r.json['host']['enrolled'] is False
    assert 'different public key' in r.json['host']['reason']

    with sshadmin.app.app_context():
        host = sshadmin.Host.query.filter_by(hostname='box1').first()
        user_names = [u.username for u in host.users]
        assert 'alice' in user_names
        assert 'bob' not in user_names  # bob was NOT added to this host.


# ------- Manual share UI -------

def test_owner_can_share_host_with_another_user(client, keypair, sign,
                                                keypair_ed25519, ca_keys):
    register_via_api(client, sign, keypair['public_key'], username='alice')
    host_id = _enroll_host_with_creator(client, 'srv1')

    # Mark host as enrolled with a real key.
    set_host_enrolled(host_id)

    # Register a second user.
    client.get('/logout')
    register_via_api(client, lambda n: sign(n, private_path=keypair_ed25519['private_path']),
                     keypair_ed25519['public_key'], username='bob')

    with sshadmin.app.app_context():
        bob_id = sshadmin.User.query.filter_by(username='bob').first().id

    # Login as alice and share.
    client.get('/logout')
    _login(client, sign, 'alice', ca_keys=ca_keys)
    r = client.post(f'/hosts/{host_id}/share', data={'user_id': bob_id, 'role': 'owner'})
    assert r.status_code == 302

    with sshadmin.app.app_context():
        host = sshadmin.db.session.get(sshadmin.Host, host_id)
        owner_names = sorted(o.username for o in host.owners)
        assert owner_names == ['alice', 'bob']


def test_non_owner_cannot_share_host(client, keypair, sign, keypair_ed25519, ca_keys):
    register_via_api(client, sign, keypair['public_key'], username='alice')
    host_id = _enroll_host_with_creator(client, 'srv1')
    client.get('/logout')

    # Bob registers (not admin, not owner).
    register_via_api(client, lambda n: sign(n, private_path=keypair_ed25519['private_path']),
                     keypair_ed25519['public_key'], username='bob')

    with sshadmin.app.app_context():
        bob_id = sshadmin.User.query.filter_by(username='bob').first().id

    # Bob tries to share alice's host with himself.
    r = client.post(f'/hosts/{host_id}/share', data={'user_id': bob_id}, follow_redirects=True)
    assert b'Only an owner or admin' in r.data

    with sshadmin.app.app_context():
        host = sshadmin.db.session.get(sshadmin.Host, host_id)
        assert sorted(o.username for o in host.owners) == ['alice']


# ------- Delete semantics -------

def test_non_admin_delete_removes_only_their_ownership(client, keypair, sign,
                                                       keypair_ed25519, host_keypair, ca_keys):
    """Two co-users; one deletes -> HostUsers row gone but host remains."""
    # Alice creates + enrolls box1 (she's first user, so admin).
    client.post('/register', data={
        'username': 'alice', 'unix_username': 'alice',
        'public_key': keypair['public_key'],
    })
    with sshadmin.app.app_context():
        ch = latest_challenge('register')
        token, nonce = ch.token, ch.nonce
    client.post('/api/challenge_response', data={
        'token': token, 'signature': sign(nonce),
        'hostname': 'box1', 'host_public_key': host_keypair['public_key'],
    })
    client.get(f'/api/auth_status/{token}')
    client.get('/logout')

    # Bob registers and shares the host (same key → co-user).
    client.post('/register', data={
        'username': 'bob', 'unix_username': 'bob',
        'public_key': keypair_ed25519['public_key'],
    })
    with sshadmin.app.app_context():
        ch = latest_challenge('register')
        token, nonce = ch.token, ch.nonce
    sig = sign(nonce, private_path=keypair_ed25519['private_path'])
    client.post('/api/challenge_response', data={
        'token': token, 'signature': sig,
        'hostname': 'box1', 'host_public_key': host_keypair['public_key'],
    })
    client.get(f'/api/auth_status/{token}')

    with sshadmin.app.app_context():
        host = sshadmin.Host.query.filter_by(hostname='box1').first()
        host_id = host.id
        assert sorted(u.username for u in host.users) == ['alice', 'bob']

    # Bob (non-admin) "deletes" the host -> just removes his HostUsers row.
    r = client.post(f'/hosts/{host_id}/delete', follow_redirects=False)
    assert r.status_code == 302

    with sshadmin.app.app_context():
        host = sshadmin.Host.query.filter_by(hostname='box1').first()
        assert host is not None  # not deleted
        assert sorted(u.username for u in host.users) == ['alice']


def test_last_owner_delete_removes_host(client, keypair, sign, keypair_ed25519, ca_keys):
    """A non-admin sole-owner deleting their host wipes the host record."""
    # Alice = first user = admin.
    register_via_api(client, sign, keypair['public_key'], username='alice')
    client.get('/logout')

    # Bob registers (non-admin) and creates a host alone.
    register_via_api(
        client,
        lambda n: sign(n, private_path=keypair_ed25519['private_path']),
        keypair_ed25519['public_key'],
        username='bob',
    )
    host_id = _enroll_host_with_creator(client, 'soloserver')

    r = client.post(f'/hosts/{host_id}/delete', follow_redirects=True)
    assert b'no other users' in r.data

    with sshadmin.app.app_context():
        assert sshadmin.Host.query.filter_by(hostname='soloserver').first() is None


def test_admin_delete_wipes_host_with_co_owners(client, keypair, sign,
                                                keypair_ed25519, host_keypair, ca_keys):
    """Admin delete removes the host record entirely even if other users exist."""
    # Alice (admin) creates + enrolls box1 with bob as co-user via implicit share.
    client.post('/register', data={
        'username': 'alice', 'unix_username': 'alice',
        'public_key': keypair['public_key'],
    })
    with sshadmin.app.app_context():
        ch = latest_challenge('register')
        token, nonce = ch.token, ch.nonce
    client.post('/api/challenge_response', data={
        'token': token, 'signature': sign(nonce),
        'hostname': 'box1', 'host_public_key': host_keypair['public_key'],
    })
    client.get(f'/api/auth_status/{token}')
    client.get('/logout')

    client.post('/register', data={
        'username': 'bob', 'unix_username': 'bob',
        'public_key': keypair_ed25519['public_key'],
    })
    with sshadmin.app.app_context():
        ch = latest_challenge('register')
        token, nonce = ch.token, ch.nonce
    sig = sign(nonce, private_path=keypair_ed25519['private_path'])
    client.post('/api/challenge_response', data={
        'token': token, 'signature': sig,
        'hostname': 'box1', 'host_public_key': host_keypair['public_key'],
    })
    client.get(f'/api/auth_status/{token}')

    with sshadmin.app.app_context():
        host_id = sshadmin.Host.query.filter_by(hostname='box1').first().id

    # Login back as alice (admin) and delete.
    client.get('/logout')
    _login(client, sign, 'alice', ca_keys=ca_keys)
    r = client.post(f'/hosts/{host_id}/delete', follow_redirects=True)
    assert b'deleted' in r.data

    with sshadmin.app.app_context():
        assert sshadmin.Host.query.filter_by(hostname='box1').first() is None
