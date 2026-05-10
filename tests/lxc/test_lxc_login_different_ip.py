"""
Login-from-different-IP tests.

Covers two orthogonal scenarios:

1. Source IP transparency — a valid cert grants access from any client IP by
   default.  The same cert deployed to two different machines (C1 and C_SALES)
   can SSH to a third machine (C_ACCT) without restriction.  This demonstrates
   that SSH certificate auth is not source-IP-bound unless explicitly restricted.

2. Source-address critical option — a cert issued with the `source-address`
   critical option is accepted only when the SSH client's IP is in the
   allowed range.  Attempting to use such a cert from a different IP fails
   with "Permission denied" before any authentication step completes.

The group_env fixture provides the three isolated host containers and the
group identity files (id_group / id_group-cert.pub) on C1.
"""
import subprocess
import tempfile
from pathlib import Path

import pytest

from lxc_helpers import (
    C1, C_ACCT, C_SALES, CAPP, APP_DB, APP_PORT,
    ssh_from, push_file, push_text, lxc_exec, sqlite_value,
    AdminSession, http_login, make_sign_fn,
)

pytestmark = pytest.mark.lxc


# ---------------------------------------------------------------------------
# Scenario 1: cert works from multiple source IPs (no source-address restriction)
# ---------------------------------------------------------------------------

def test_group_cert_works_from_primary_origin(group_env, lxc_env):
    """alice's Accounting cert grants access to C_ACCT from C1 (normal origin)."""
    c_acct_ip = group_env['ips'][C_ACCT]
    result = ssh_from(C1, 'alice', c_acct_ip,
                      identity='/home/alice/.ssh/id_group')
    assert result.returncode == 0, (
        f'alice failed to SSH to C_ACCT from C1:\n'
        f'stdout: {result.stdout}\nstderr: {result.stderr}'
    )
    assert 'hello' in result.stdout


def test_group_cert_works_from_secondary_origin(group_env, lxc_env, user_keypairs):
    """alice's Accounting cert grants access to C_ACCT even from C_SALES (different IP).

    The SSH server (C_ACCT) only checks whether the cert's signing CA is trusted
    and whether the cert is valid.  The client's source IP is irrelevant unless
    a source-address critical option is embedded in the cert.

    To test this, alice's group identity (id_group / id_group-cert.pub) is
    deployed to the C_SALES container and used from there to reach C_ACCT.
    """
    c_acct_ip  = group_env['ips'][C_ACCT]
    c_sales_ip = group_env['ips'][C_SALES]  # noqa: F841 (used implicitly via container)

    alice_cert = group_env['group_user_certs']['alice']

    # Deploy alice's key + cert to C_SALES (different origin IP).
    push_file(C_SALES, user_keypairs['alice']['private_path'],
              '/home/alice/.ssh/id_group',
              mode='600', owner='alice:alice')
    push_text(C_SALES, alice_cert + '\n',
              '/home/alice/.ssh/id_group-cert.pub',
              mode='644', owner='alice:alice')

    result = ssh_from(C_SALES, 'alice', c_acct_ip,
                      identity='/home/alice/.ssh/id_group')
    assert result.returncode == 0, (
        f'alice failed to SSH to C_ACCT from C_SALES (different source IP).\n'
        f'This means the cert is unexpectedly source-IP-restricted.\n'
        f'stdout: {result.stdout}\nstderr: {result.stderr}'
    )
    assert 'hello' in result.stdout


# ---------------------------------------------------------------------------
# Scenario 2: source-address critical option enforces client IP restriction
# ---------------------------------------------------------------------------

def _issue_source_restricted_cert(alice_session: AdminSession, cred_id: int,
                                   source_address: str) -> str:
    """Issue a user cert for alice with a source-address critical option."""
    alice_session.post('/certificates/issue/user', {
        'credential_id':  cred_id,
        'valid_days':     '30',
        'principals':     'alice',
        'source_address': source_address,
    })
    return sqlite_value(
        f"SELECT c.certificate_data FROM certificate c "
        f"JOIN user_credential uc ON uc.user_key_id = c.ssh_key_id "
        f"WHERE uc.id = {cred_id} ORDER BY c.id DESC LIMIT 1"
    )


def test_source_address_restriction_allows_correct_ip(
        group_env, lxc_env, user_keypairs):
    """A cert with source-address=<C1 IP> permits SSH from C1 to C_ACCT."""
    c1_ip     = lxc_env['ips'][C1]
    c_acct_ip = group_env['ips'][C_ACCT]

    app_url  = lxc_env['app_url']
    cred_id  = lxc_env['credential_ids']['alice']

    alice_session = AdminSession(app_url)
    http_login(alice_session,
               make_sign_fn(user_keypairs['alice']['private_path']),
               'alice')

    restricted_cert = _issue_source_restricted_cert(
        alice_session, cred_id, source_address=c1_ip)

    push_text(C1, restricted_cert + '\n',
              '/home/alice/.ssh/id_restricted-cert.pub',
              mode='644', owner='alice:alice')
    # Reuse alice's private key — the cert is for the same key.
    push_file(C1, user_keypairs['alice']['private_path'],
              '/home/alice/.ssh/id_restricted',
              mode='600', owner='alice:alice')

    result = ssh_from(C1, 'alice', c_acct_ip,
                      identity='/home/alice/.ssh/id_restricted')
    assert result.returncode == 0, (
        f'alice should be allowed from C1 (source-address={c1_ip}) '
        f'but SSH failed:\nstdout: {result.stdout}\nstderr: {result.stderr}'
    )
    assert 'hello' in result.stdout


def test_source_address_restriction_denies_wrong_ip(
        group_env, lxc_env, user_keypairs):
    """A cert with source-address=<C1 IP> denies SSH from C_SALES (different IP).

    The restricted cert is placed on C_SALES and used to reach C_ACCT.  Because
    C_SALES's IP does not match the source-address in the cert's critical options,
    OpenSSH rejects the authentication before checking any other constraint.
    """
    c1_ip     = lxc_env['ips'][C1]
    c_acct_ip = group_env['ips'][C_ACCT]

    app_url = lxc_env['app_url']
    cred_id = lxc_env['credential_ids']['alice']

    alice_session = AdminSession(app_url)
    http_login(alice_session,
               make_sign_fn(user_keypairs['alice']['private_path']),
               'alice')

    restricted_cert = _issue_source_restricted_cert(
        alice_session, cred_id, source_address=c1_ip)

    # Deploy the restricted cert to C_SALES.
    push_text(C_SALES, restricted_cert + '\n',
              '/home/alice/.ssh/id_restricted-cert.pub',
              mode='644', owner='alice:alice')
    push_file(C_SALES, user_keypairs['alice']['private_path'],
              '/home/alice/.ssh/id_restricted',
              mode='600', owner='alice:alice')

    result = ssh_from(C_SALES, 'alice', c_acct_ip,
                      identity='/home/alice/.ssh/id_restricted')
    assert result.returncode != 0, (
        f'alice should be denied from C_SALES (cert restricts source to {c1_ip}) '
        f'but SSH succeeded unexpectedly.\n'
        f'stdout: {result.stdout}\nstderr: {result.stderr}'
    )
