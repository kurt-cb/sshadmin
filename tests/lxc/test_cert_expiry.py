"""
Expired certificate rejection tests.

Verifies that OpenSSH on both the client side (host cert) and the server side
(user cert) correctly rejects certificates whose validity window has passed.
"""
import time

import pytest

from lxc_helpers import C1, C2, ssh_from, push_file, push_text, lxc_exec, \
    sign_expired_user_cert, sign_expired_host_cert

pytestmark = pytest.mark.lxc


def test_expired_user_cert_rejected(lxc_env, tmp_path, user_keypairs):
    """An expired user certificate must be refused by the SSH server (C2)."""
    ca_key = lxc_env['ca_key_local']
    c2_ip  = lxc_env['ips'][C2]

    pub_path = tmp_path / 'alice.pub'
    pub_path.write_text(user_keypairs['alice']['public_key'] + '\n')
    expired_cert = sign_expired_user_cert(str(pub_path), 'alice', ca_key)

    push_file(C1, user_keypairs['alice']['private_path'],
              '/home/alice/.ssh/id_expired',
              mode='600', owner='alice:alice')
    push_text(C1, expired_cert + '\n',
              '/home/alice/.ssh/id_expired-cert.pub',
              mode='644', owner='alice:alice')

    result = ssh_from(C1, 'alice', c2_ip,
                      identity='/home/alice/.ssh/id_expired',
                      cmd='echo should-not-reach')
    assert result.returncode != 0, (
        'SSH should have been rejected with an expired user cert, but succeeded.\n'
        f'stdout: {result.stdout}\nstderr: {result.stderr}'
    )


def test_expired_host_cert_rejected(lxc_env, tmp_path):
    """An expired host certificate must be refused by the SSH client (C1)."""
    ca_key     = lxc_env['ca_key_local']
    c2_ip      = lxc_env['ips'][C2]
    valid_cert = lxc_env['host_cert_data'][C2]

    host_pub = lxc_exec(C2, 'cat', '/etc/ssh/ssh_host_ecdsa_key.pub').stdout.strip()
    pub_path = tmp_path / 'host.pub'
    pub_path.write_text(host_pub + '\n')
    expired_cert = sign_expired_host_cert(str(pub_path), c2_ip, ca_key)

    push_text(C2, expired_cert + '\n',
              '/etc/ssh/ssh_host_ecdsa_key-cert.pub', mode='644')
    lxc_exec(C2, 'systemctl', 'reload', 'ssh')
    time.sleep(1)

    try:
        result = ssh_from(C1, 'alice', c2_ip, cmd='echo should-not-reach')
        assert result.returncode != 0, (
            'SSH should have been rejected when C2 presents an expired host cert.\n'
            f'stdout: {result.stdout}\nstderr: {result.stderr}'
        )
    finally:
        push_text(C2, valid_cert + '\n',
                  '/etc/ssh/ssh_host_ecdsa_key-cert.pub', mode='644')
        lxc_exec(C2, 'systemctl', 'reload', 'ssh')
        time.sleep(1)
