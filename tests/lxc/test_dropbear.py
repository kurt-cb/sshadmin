"""
Dropbear interoperability tests (Alpine / CALPINE container).

Dropbear 2024.86 generates P-256 ECDSA keys natively and does not support
TrustedUserCAKeys.  These tests verify:
  - sshadmin rejects enrollment of a P-256 host key.
  - OpenSSH client on C1 can authenticate to Dropbear via authorized_keys.
  - OpenSSH client on Alpine (musl libc) can use a cert to reach C2 (glibc).
"""
import pytest

from lxc_helpers import C1, C2, CALPINE, ssh_from

pytestmark = pytest.mark.lxc


def test_dropbear_p256_enrollment_rejected(lxc_env):
    """sshadmin must reject enrollment of a Dropbear P-256 host key.

    sshadmin only accepts ecdsa-sha2-nistp521 host keys.  Dropbear generates
    ecdsa-sha2-nistp256 natively.  Enrollment must fail with a clear error.
    """
    result = lxc_env['alpine_enrollment_result']
    assert not result.get('ok'), (
        f'Expected enrollment to be rejected for P-256 key, but got ok=True: {result}'
    )
    assert result.get('error', ''), f'Expected a non-empty error field, got: {result}'


def test_openssh_to_dropbear_pubkey_auth(lxc_env):
    """OpenSSH client on C1 authenticates to Alpine/Dropbear via authorized_keys.

    Dropbear does not support TrustedUserCAKeys so user cert auth is not
    applicable here.  Host identity is verified by the raw P-256 fingerprint
    in /etc/ssh/ssh_known_hosts on C1.
    """
    alpine_ip = lxc_env['ips'][CALPINE]
    result = ssh_from(C1, 'alice', alpine_ip,
                      host_key_algo='ecdsa-sha2-nistp256')
    assert result.returncode == 0, (
        f'SSH from C1 to Alpine/Dropbear failed:\n'
        f'stdout: {result.stdout}\nstderr: {result.stderr}'
    )
    assert 'hello' in result.stdout


def test_alpine_openssh_to_ubuntu_cert_auth(lxc_env):
    """Alpine's OpenSSH client authenticates to C2 Ubuntu using alice's cert.

    Verifies cross-libc interoperability: OpenSSH built against musl (Alpine)
    correctly performs certificate auth against OpenSSH built against glibc (Ubuntu).
    """
    c2_ip  = lxc_env['ips'][C2]
    result = ssh_from(CALPINE, 'alice', c2_ip)
    assert result.returncode == 0, (
        f'Alpine OpenSSH → Ubuntu cert-based SSH failed:\n'
        f'stdout: {result.stdout}\nstderr: {result.stderr}'
    )
    assert 'hello' in result.stdout
