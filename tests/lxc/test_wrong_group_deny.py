"""
CA group isolation tests — Accounting / Sales / HR model.

Topology (set up by the group_env fixture):

  Groups and their dedicated host containers:
    Accounting  →  C_ACCT   (TrustedUserCAKeys = Accounting CA only)
    Sales       →  C_SALES  (TrustedUserCAKeys = Sales CA only)
    HR          →  C_HR     (TrustedUserCAKeys = HR CA only)

  User certificates issued per group:
    alice  →  signed by Accounting CA
    bob    →  signed by Sales CA
    carol  →  signed by HR CA

  Identity files on C1 (origin node):
    /home/<user>/.ssh/id_group        – copy of user's private key
    /home/<user>/.ssh/id_group-cert.pub – cert signed by that user's group CA

The cryptographic enforcement is done entirely by OpenSSH on each target host.
There is no runtime policy check: the cert's signing CA is either in
TrustedUserCAKeys or it isn't.  A user in the wrong group cannot authenticate
regardless of any sshadmin policy setting.

Expected matrix (True = should succeed, False = must be denied):

              C_ACCT   C_SALES   C_HR
  alice        True     False    False
  bob         False     True     False
  carol       False    False      True
"""
import pytest

from lxc_helpers import C1, C_ACCT, C_SALES, C_HR, ssh_from

pytestmark = pytest.mark.lxc

# (username, target_container, expected_to_succeed)
_MATRIX = [
    ('alice', C_ACCT,  True,  'alice is in Accounting — cert matches C_ACCT CA'),
    ('alice', C_SALES, False, 'alice cert (Accounting CA) rejected by C_SALES (Sales CA)'),
    ('alice', C_HR,    False, 'alice cert (Accounting CA) rejected by C_HR (HR CA)'),
    ('bob',   C_SALES, True,  'bob is in Sales — cert matches C_SALES CA'),
    ('bob',   C_ACCT,  False, 'bob cert (Sales CA) rejected by C_ACCT (Accounting CA)'),
    ('bob',   C_HR,    False, 'bob cert (Sales CA) rejected by C_HR (HR CA)'),
    ('carol', C_HR,    True,  'carol is in HR — cert matches C_HR CA'),
    ('carol', C_ACCT,  False, 'carol cert (HR CA) rejected by C_ACCT (Accounting CA)'),
    ('carol', C_SALES, False, 'carol cert (HR CA) rejected by C_SALES (Sales CA)'),
]

_IDS = [
    f'{user}→{container.replace("sshadmin-lxc-", "")}:{"allow" if ok else "deny"}'
    for user, container, ok, _ in _MATRIX
]


@pytest.mark.parametrize('username,target,should_succeed,reason', _MATRIX, ids=_IDS)
def test_group_access(group_env, lxc_env, username, target, should_succeed, reason):
    """
    Verify per-group SSH access: correct group succeeds, wrong group is denied.

    The group cert for each user is deployed to C1 as id_group / id_group-cert.pub.
    The target container's sshd only trusts its own group's CA public key.
    """
    target_ip = group_env['ips'][target]
    result = ssh_from(
        C1, username, target_ip,
        identity=f'/home/{username}/.ssh/id_group',
    )

    if should_succeed:
        assert result.returncode == 0, (
            f'Expected SSH to succeed ({reason}) but it failed.\n'
            f'stdout: {result.stdout}\nstderr: {result.stderr}'
        )
        assert 'hello' in result.stdout
    else:
        assert result.returncode != 0, (
            f'Expected SSH to be denied ({reason}) but it succeeded.\n'
            f'stdout: {result.stdout}\nstderr: {result.stderr}'
        )


def test_group_ca_keys_are_distinct(group_env):
    """Each group must have its own CA public key, different from the others."""
    pubkeys = list(group_env['group_ca_pubkeys'].values())
    assert len(pubkeys) == 3, 'Expected 3 group CA public keys'
    assert len(set(pubkeys)) == 3, \
        'Group CA public keys must all be distinct — some groups share a CA key'


def test_group_ca_keys_differ_from_site_ca(group_env, lxc_env):
    """Group CA keys must not be the same as the main site CA key.

    If a group CA equals the site CA, hosts in that group would accept any
    user cert issued by sshadmin, defeating the isolation purpose.
    """
    site_ca = lxc_env['ca_pubkey']
    for group_name, group_ca in group_env['group_ca_pubkeys'].items():
        assert group_ca != site_ca, (
            f'Group "{group_name}" is using the site CA key instead of its own — '
            f'this eliminates group isolation'
        )


@pytest.mark.parametrize('username,target,should_succeed,reason', _MATRIX, ids=_IDS)
def test_group_access_with_default_identity_fails_on_group_hosts(
        group_env, lxc_env, username, target, should_succeed, reason):
    """
    The default site-CA cert (id_ed25519-cert.pub) must NOT grant access to
    group-specific hosts, regardless of which user holds it.

    Group hosts only trust their group CA.  The site CA is not in their
    TrustedUserCAKeys, so site-CA-signed certs are always rejected.
    """
    target_ip = group_env['ips'][target]
    result = ssh_from(
        C1, username, target_ip,
        # Default identity — cert signed by site CA, not a group CA.
        identity=f'/home/{username}/.ssh/id_ed25519',
    )
    assert result.returncode != 0, (
        f'Site-CA cert for {username} should be rejected by group host '
        f'{target.replace("sshadmin-lxc-", "")} but SSH succeeded.\n'
        f'stdout: {result.stdout}\nstderr: {result.stderr}'
    )
