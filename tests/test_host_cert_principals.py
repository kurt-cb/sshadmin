"""Tests for host certificate principal handling.

Covers:
  - Non-strict mode (default): certs issued with no principals (wildcard)
  - Strict mode: certs list hostname + all stored aliases as principals
  - connect_host auto-stored as alias on enrollment
  - _ssh_add_alias SSH command: add alias + re-issue cert
  - Alias REST API endpoints
  - update_cert flow (via renew_host_cert after alias registration)
"""
from __future__ import annotations

import os
import subprocess
import tempfile

import pytest

import sshadmin
from conftest import register_via_api


# ── Helpers ──────────────────────────────────────────────────────────────────

def _cert_principals(cert_data: str) -> list[str]:
    """Parse the Principals list out of a cert string using ssh-keygen -L."""
    with tempfile.NamedTemporaryFile(mode='w', suffix='.pub', delete=False) as f:
        f.write(cert_data.strip() + '\n')
        fname = f.name
    try:
        out = subprocess.run(
            ['ssh-keygen', '-L', '-f', fname],
            capture_output=True, text=True, check=True,
        )
    finally:
        os.unlink(fname)

    principals = []
    in_principals = False
    for line in out.stdout.splitlines():
        stripped = line.strip()
        if stripped.startswith('Principals:'):
            in_principals = True
            continue
        if in_principals:
            if stripped.startswith('Critical Options') or stripped.startswith('Extensions'):
                break
            if stripped:
                principals.append(stripped)
    return principals


def _enable_strict(app):
    with app.app_context():
        cfg = sshadmin.db.session.get(sshadmin.SiteConfig, 'strict_host_principals')
        if cfg:
            cfg.value = '1'
        else:
            sshadmin.db.session.add(
                sshadmin.SiteConfig(key='strict_host_principals', value='1'))
        sshadmin.db.session.commit()


def _make_add_machine_data(host_keypair, user_keypair, *, hostname, connect_host=None):
    return {
        'hostname': hostname,
        'host_key': host_keypair['public_key'],
        'user': 'alice',
        'user_key': user_keypair['public_key'],
        'valid_days': 1,
        **(({'connect_host': connect_host}) if connect_host else {}),
    }


# ── Fixtures ─────────────────────────────────────────────────────────────────

@pytest.fixture
def alice_id(client, keypair, sign):
    register_via_api(client, sign, keypair['public_key'], username='alice')
    with sshadmin.app.app_context():
        return sshadmin.User.query.filter_by(username='alice').first().id


# ── Non-strict mode (wildcard) tests ─────────────────────────────────────────

def test_nonstrict_cert_has_no_principals(app, alice_id, keypair, host_keypair, ca_keys):
    """Default (non-strict) mode: host cert has no principals — valid for any hostname."""
    data = _make_add_machine_data(host_keypair, keypair, hostname='myserver.local')
    with app.app_context():
        result = sshadmin._ssh_add_machine(alice_id, data)

    assert result['ok'] is True
    assert result['host_cert']
    principals = _cert_principals(result['host_cert'])
    assert principals == [], f'expected no principals in non-strict mode, got {principals}'


def test_nonstrict_connect_host_stored_as_alias(app, alice_id, keypair, host_keypair, ca_keys):
    """connect_host is persisted as alias even in non-strict mode (for future strict-mode use)."""
    data = _make_add_machine_data(
        host_keypair, keypair, hostname='myserver.local', connect_host='192.168.1.100',
    )
    with app.app_context():
        result = sshadmin._ssh_add_machine(alice_id, data)
        assert result['ok'] is True
        host = sshadmin.Host.query.filter_by(hostname='myserver.local').first()
        aliases = [a.alias for a in host.aliases]
    assert '192.168.1.100' in aliases


# ── Strict mode tests ─────────────────────────────────────────────────────────

def test_strict_cert_has_hostname_principal(app, alice_id, keypair, host_keypair, ca_keys):
    """Strict mode without aliases: cert contains exactly the registered hostname."""
    _enable_strict(app)
    data = _make_add_machine_data(host_keypair, keypair, hostname='myserver.local')
    with app.app_context():
        result = sshadmin._ssh_add_machine(alice_id, data)

    assert result['ok'] is True
    principals = _cert_principals(result['host_cert'])
    assert principals == ['myserver.local'], principals


def test_strict_cert_includes_connect_host_ip(app, alice_id, keypair, host_keypair, ca_keys):
    """Critical case: register by hostname, connect by IP.

    Without strict mode this wouldn't matter (wildcard). With strict mode,
    the IP must be a principal or OpenSSH rejects the cert.
    sshadmin_add sends connect_host, which is stored as alias and included.
    """
    _enable_strict(app)
    data = _make_add_machine_data(
        host_keypair, keypair,
        hostname='myserver.local',
        connect_host='192.168.1.100',
    )
    with app.app_context():
        result = sshadmin._ssh_add_machine(alice_id, data)

    assert result['ok'] is True
    principals = _cert_principals(result['host_cert'])
    assert 'myserver.local' in principals, principals
    assert '192.168.1.100' in principals, principals


def test_strict_cert_includes_fqdn_and_short_name(app, alice_id, keypair, host_keypair, ca_keys):
    """Strict mode: FQDN registered, short name used as connect_host → both in cert."""
    _enable_strict(app)
    data = _make_add_machine_data(
        host_keypair, keypair,
        hostname='myserver.example.com',
        connect_host='myserver',
    )
    with app.app_context():
        result = sshadmin._ssh_add_machine(alice_id, data)

    assert result['ok'] is True
    principals = _cert_principals(result['host_cert'])
    assert 'myserver.example.com' in principals, principals
    assert 'myserver' in principals, principals


def test_strict_no_duplicate_when_connect_host_matches_hostname(
        app, alice_id, keypair, host_keypair, ca_keys):
    """Strict mode: connect_host == hostname → no duplicate principal."""
    _enable_strict(app)
    data = _make_add_machine_data(
        host_keypair, keypair,
        hostname='myserver.local',
        connect_host='myserver.local',
    )
    with app.app_context():
        result = sshadmin._ssh_add_machine(alice_id, data)

    assert result['ok'] is True
    principals = _cert_principals(result['host_cert'])
    assert principals == ['myserver.local'], principals


def test_no_host_cert_when_no_host_key_provided(
        app, alice_id, keypair, ca_keys):
    """User-only enrollment (no host key) → no host cert regardless of mode."""
    data = {
        'hostname': 'myserver.local',
        'user': 'alice',
        'user_key': keypair['public_key'],
        'valid_days': 1,
        'connect_host': '192.168.1.100',
    }
    with app.app_context():
        result = sshadmin._ssh_add_machine(alice_id, data)

    assert result['ok'] is True
    assert not result.get('host_cert')
    assert result['user_cert']


# ── _ssh_add_alias tests ──────────────────────────────────────────────────────

def test_ssh_add_alias_stores_alias_and_reissues(app, alice_id, keypair, host_keypair, ca_keys):
    """_ssh_add_alias stores the alias and returns a new cert."""
    # First enroll the host.
    data = _make_add_machine_data(host_keypair, keypair, hostname='myserver.local')
    with app.app_context():
        result = sshadmin._ssh_add_machine(alice_id, data)
    assert result['ok'] is True

    # Add an alias.
    with app.app_context():
        alias_result = sshadmin._ssh_add_alias(alice_id, {
            'hostname': 'myserver.local',
            'host_key': host_keypair['public_key'],
            'alias': '10.0.0.5',
        })
    assert alias_result['ok'] is True, alias_result
    assert '10.0.0.5' in alias_result['aliases']
    assert alias_result['host_cert']


def test_ssh_add_alias_strict_mode_cert_includes_alias(
        app, alice_id, keypair, host_keypair, ca_keys):
    """Strict mode: after add_alias, new cert includes the alias as principal."""
    _enable_strict(app)
    data = _make_add_machine_data(host_keypair, keypair, hostname='myserver.local')
    with app.app_context():
        sshadmin._ssh_add_machine(alice_id, data)
        alias_result = sshadmin._ssh_add_alias(alice_id, {
            'hostname': 'myserver.local',
            'host_key': host_keypair['public_key'],
            'alias': '10.0.0.5',
        })
    assert alias_result['ok'] is True
    principals = _cert_principals(alias_result['host_cert'])
    assert 'myserver.local' in principals
    assert '10.0.0.5' in principals


def test_ssh_add_alias_idempotent(app, alice_id, keypair, host_keypair, ca_keys):
    """Adding the same alias twice doesn't duplicate it."""
    data = _make_add_machine_data(host_keypair, keypair, hostname='myserver.local')
    with app.app_context():
        sshadmin._ssh_add_machine(alice_id, data)
        sshadmin._ssh_add_alias(alice_id, {
            'hostname': 'myserver.local',
            'host_key': host_keypair['public_key'],
            'alias': '10.0.0.5',
        })
        result2 = sshadmin._ssh_add_alias(alice_id, {
            'hostname': 'myserver.local',
            'host_key': host_keypair['public_key'],
            'alias': '10.0.0.5',
        })
    assert result2['ok'] is True
    assert result2['aliases'].count('10.0.0.5') == 1


def test_ssh_add_alias_rejects_wrong_key(app, alice_id, keypair, host_keypair,
                                         keypair_ed25519, ca_keys):
    """_ssh_add_alias rejects a request if the supplied key doesn't match the enrolled key."""
    data = _make_add_machine_data(host_keypair, keypair, hostname='myserver.local')
    with app.app_context():
        sshadmin._ssh_add_machine(alice_id, data)
        result = sshadmin._ssh_add_alias(alice_id, {
            'hostname': 'myserver.local',
            'host_key': keypair_ed25519['public_key'],
            'alias': '10.0.0.5',
        })
    assert result['ok'] is False
    assert 'does not match' in result['error']


# ── Alias REST API tests ───────────────────────────────────────────────────────

def test_api_aliases_list(client, keypair, sign, host_keypair, ca_keys):
    """GET /api/hosts/<id>/aliases returns current alias list."""
    register_via_api(client, sign, keypair['public_key'], username='alice')
    r = client.post('/hosts/add', data={'hostname': 'srv1'})
    assert r.status_code == 302
    with sshadmin.app.app_context():
        host = sshadmin.Host.query.filter_by(hostname='srv1').first()
        token, host_id = host.enrollment_token, host.id
    client.post('/api/enroll/host', data={'token': token, 'public_key': host_keypair['public_key']})

    r = client.get(f'/api/hosts/{host_id}/aliases')
    assert r.status_code == 200
    assert r.json['aliases'] == []


def test_api_aliases_add_and_delete(client, keypair, sign, host_keypair, ca_keys):
    """POST adds an alias; DELETE removes it."""
    register_via_api(client, sign, keypair['public_key'], username='alice')
    r = client.post('/hosts/add', data={'hostname': 'srv2'})
    with sshadmin.app.app_context():
        host = sshadmin.Host.query.filter_by(hostname='srv2').first()
        token, host_id = host.enrollment_token, host.id
    client.post('/api/enroll/host', data={'token': token, 'public_key': host_keypair['public_key']})

    r = client.post(f'/api/hosts/{host_id}/aliases', data={'alias': '192.168.1.50'})
    assert r.status_code == 200
    assert '192.168.1.50' in r.json['aliases']

    r = client.delete(f'/api/hosts/{host_id}/aliases/192.168.1.50')
    assert r.status_code == 200
    assert '192.168.1.50' not in r.json['aliases']


def test_api_aliases_requires_login(client):
    r = client.get('/api/hosts/1/aliases')
    assert r.status_code in (302, 401)


def test_api_aliases_add_empty_rejected(client, keypair, sign, host_keypair, ca_keys):
    """POST with empty alias is rejected."""
    register_via_api(client, sign, keypair['public_key'], username='alice')
    r = client.post('/hosts/add', data={'hostname': 'srv3'})
    with sshadmin.app.app_context():
        host = sshadmin.Host.query.filter_by(hostname='srv3').first()
        token, host_id = host.enrollment_token, host.id
    client.post('/api/enroll/host', data={'token': token, 'public_key': host_keypair['public_key']})

    r = client.post(f'/api/hosts/{host_id}/aliases', data={'alias': ''})
    assert r.status_code == 400


# ── update_cert flow (renew_host_cert uses all aliases) ───────────────────────

def test_renew_host_cert_uses_all_aliases_in_strict_mode(
        app, alice_id, keypair, host_keypair, ca_keys):
    """renew_host_cert (called by update_cert) includes all aliases in strict mode."""
    _enable_strict(app)
    data = _make_add_machine_data(
        host_keypair, keypair, hostname='myserver.local', connect_host='10.0.0.1',
    )
    with app.app_context():
        sshadmin._ssh_add_machine(alice_id, data)
        # Add a second alias via add_alias.
        sshadmin._ssh_add_alias(alice_id, {
            'hostname': 'myserver.local',
            'host_key': host_keypair['public_key'],
            'alias': '10.0.0.2',
        })
        # Renew cert (simulates update_cert command).
        renew_result = sshadmin._ssh_renew_host_cert(alice_id, {
            'hostname': 'myserver.local',
            'host_key': host_keypair['public_key'],
        })

    assert renew_result['ok'] is True, renew_result
    principals = _cert_principals(renew_result['host_cert'])
    assert 'myserver.local' in principals
    assert '10.0.0.1' in principals
    assert '10.0.0.2' in principals
