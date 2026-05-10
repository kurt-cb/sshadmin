"""
Registration and enrollment assertions.

Verifies that users are fully registered, credentials exist, host keys are
stored, and certificates are issued — before any live SSH tests run.
"""
import pytest

from lxc_helpers import USERNAMES, SSH_CONTAINERS, sqlite_value

pytestmark = pytest.mark.lxc


def test_three_users_registered(lxc_env):
    """All three users must be fully registered (completed_at set)."""
    for username in USERNAMES:
        completed = sqlite_value(
            f"SELECT completed_at FROM user WHERE username='{username}'")
        assert completed, f'{username} not found or registration incomplete'

    is_admin = sqlite_value("SELECT is_admin FROM user WHERE username='alice'")
    assert is_admin == '1', 'alice (first user) must be admin'


def test_each_user_has_ssh_credential(lxc_env):
    """Registration must auto-create a UserCredential for each user."""
    for username in USERNAMES:
        found = sqlite_value(
            f"SELECT uc.id FROM user_credential uc "
            f"JOIN user usr ON usr.id = uc.user_id "
            f"WHERE usr.username='{username}'"
        )
        assert found, f'UserCredential for {username} not found'


def test_both_ubuntu_hosts_enrolled(lxc_env):
    """Both Ubuntu containers must be enrolled (enrolled_at set, P-521 key stored)."""
    ips = lxc_env['ips']
    for c in SSH_CONTAINERS:
        ip          = ips[c]
        enrolled_at = sqlite_value(f"SELECT enrolled_at FROM host WHERE hostname='{ip}'")
        pub_key     = sqlite_value(
            f"SELECT sk.public_key FROM host h "
            f"JOIN ssh_key sk ON sk.id = h.host_key_id "
            f"WHERE h.hostname='{ip}'"
        )
        assert enrolled_at, f'Host {c} not enrolled'
        assert pub_key.startswith('ecdsa-sha2-nistp521 '), \
            f'Host {c} wrong key type: {pub_key[:60]}'


def test_host_certs_issued(lxc_env):
    """A valid host certificate must be stored for each Ubuntu container."""
    for c in SSH_CONTAINERS:
        cert = lxc_env['host_cert_data'][c]
        assert cert, f'No host cert data for {c}'
        assert 'ecdsa-sha2-nistp521-cert-v01@openssh.com' in cert


def test_user_certs_issued(lxc_env):
    """A valid user certificate must be stored for each registered user."""
    for username in USERNAMES:
        cert = lxc_env['user_certs'][username]
        assert cert, f'No user cert for {username}'
