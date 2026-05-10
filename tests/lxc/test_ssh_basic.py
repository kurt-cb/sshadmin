"""
Basic SSH connectivity tests — C1 → C2, certificate authentication only.

All three users have Ed25519 keys + certs signed by the site CA deployed to C1.
C2's sshd trusts the site CA via TrustedUserCAKeys and has no authorized_keys.
"""
import tempfile
from pathlib import Path

import pytest

from lxc_helpers import C1, C2, USERNAMES, ssh_from, push_file, lxc_exec

pytestmark = pytest.mark.lxc


@pytest.mark.parametrize('username', USERNAMES)
def test_ssh_succeeds_with_valid_cert(lxc_env, username):
    """Each user can SSH from C1 to C2 using their CA-signed cert (no password)."""
    c2_ip  = lxc_env['ips'][C2]
    result = ssh_from(C1, username, c2_ip)
    assert result.returncode == 0, (
        f'SSH failed for {username}:\n'
        f'stdout: {result.stdout}\nstderr: {result.stderr}'
    )
    assert 'hello' in result.stdout


def test_ssh_rejected_without_cert(lxc_env, user_keypairs):
    """SSH must fail when only a bare private key is presented (no cert, no authorized_keys).

    C2's sshd has AuthorizedKeysFile none and TrustedUserCAKeys set.  A bare
    private key with no associated certificate cannot authenticate.
    """
    c2_ip = lxc_env['ips'][C2]

    # Push alice's bare private key to C1 under a different name (no cert alongside it).
    push_file(C1, user_keypairs['alice']['private_path'],
              '/home/alice/.ssh/id_bare',
              mode='600', owner='alice:alice')

    result = ssh_from(C1, 'alice', c2_ip,
                      identity='/home/alice/.ssh/id_bare',
                      cmd='echo should-not-reach')
    assert result.returncode != 0, (
        'SSH should have been rejected with a bare key (no cert, no authorized_keys).\n'
        f'stdout: {result.stdout}\nstderr: {result.stderr}'
    )
