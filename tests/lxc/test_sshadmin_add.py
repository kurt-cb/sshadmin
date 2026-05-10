"""
sshadmin_add enrollment script tests.

sshadmin_add is a shell script that SSHes into a target machine and enrolls it
as an sshadmin host in one step.  These tests verify that the script runs to
completion on both Ubuntu (glibc/OpenSSH) and Alpine (musl/busybox) targets,
and that certificate-based SSH works after enrollment.
"""
import pytest

from lxc_helpers import C1, CENROLL_UBUNTU, CENROLL_ALPINE, ssh_from, lxc_exec, \
    sqlite_value, push_text

pytestmark = pytest.mark.lxc


def test_sshadmin_add_enrolls_ubuntu(lxc_enroll_env):
    """sshadmin_add must exit 0 and report success on an Ubuntu target."""
    r = lxc_enroll_env['ubuntu_result']
    assert r.returncode == 0, (
        f'sshadmin_add failed for Ubuntu:\nstdout: {r.stdout}\nstderr: {r.stderr}'
    )
    assert 'enrolled successfully' in r.stdout, \
        f'Expected "enrolled successfully" in output:\n{r.stdout}'


def test_sshadmin_add_enrolls_alpine(lxc_enroll_env):
    """sshadmin_add must exit 0 and report success on an Alpine target."""
    r = lxc_enroll_env['alpine_result']
    assert r.returncode == 0, (
        f'sshadmin_add failed for Alpine:\nstdout: {r.stdout}\nstderr: {r.stderr}'
    )
    assert 'enrolled successfully' in r.stdout, \
        f'Expected "enrolled successfully" in output:\n{r.stdout}'


def test_sshadmin_add_ubuntu_host_cert_in_db(lxc_enroll_env):
    """After sshadmin_add, the Ubuntu target must have a host cert in the DB."""
    row = sqlite_value(
        "SELECT h.hostname FROM host h "
        "JOIN ssh_key sk ON sk.id = h.host_key_id "
        "JOIN certificate c ON c.ssh_key_id = sk.id "
        "WHERE h.enrolled_at IS NOT NULL "
        "ORDER BY c.id DESC LIMIT 1"
    )
    assert row, (
        f'No enrolled host with a host cert found after Ubuntu enrollment. '
        f'Expected target IP: {lxc_enroll_env["ips"][CENROLL_UBUNTU]}'
    )


def test_sshadmin_add_alpine_host_cert_in_db(lxc_enroll_env):
    """After sshadmin_add, the Alpine target must have a host cert in the DB."""
    row = sqlite_value(
        "SELECT h.hostname FROM host h "
        "JOIN ssh_key sk ON sk.id = h.host_key_id "
        "JOIN certificate c ON c.ssh_key_id = sk.id "
        "WHERE h.enrolled_at IS NOT NULL "
        "ORDER BY c.id DESC LIMIT 1"
    )
    assert row, (
        f'No enrolled host with a host cert found after Alpine enrollment. '
        f'Expected target IP: {lxc_enroll_env["ips"][CENROLL_ALPINE]}'
    )


def test_sshadmin_add_ubuntu_ssh_cert_auth(lxc_enroll_env):
    """After sshadmin_add, alice can SSH from C1 to the Ubuntu target via cert auth.

    authorized_keys is removed first to prove it's cert auth, not raw-key auth.
    """
    ubuntu_ip = lxc_enroll_env['ips'][CENROLL_UBUNTU]
    lxc_exec(CENROLL_UBUNTU, 'rm', '-f', '/home/alice/.ssh/authorized_keys', check=False)
    lxc_exec(CENROLL_UBUNTU, 'bash', '-c',
              "echo 'AuthorizedKeysFile none' "
              ">> /etc/ssh/sshd_config.d/99-sshadmin.conf && "
              "systemctl reload ssh || systemctl reload sshd || true")
    import time; time.sleep(1)

    result = ssh_from(C1, 'alice', ubuntu_ip)
    assert result.returncode == 0, (
        f'Cert-based SSH from C1 to enrolled Ubuntu failed:\n'
        f'stdout: {result.stdout}\nstderr: {result.stderr}'
    )
    assert 'hello' in result.stdout


def test_sshadmin_add_alpine_ssh_cert_auth(lxc_enroll_env):
    """After sshadmin_add, alice can SSH from C1 to the Alpine target via cert auth."""
    alpine_ip = lxc_enroll_env['ips'][CENROLL_ALPINE]
    lxc_exec(CENROLL_ALPINE, 'rm', '-f', '/home/alice/.ssh/authorized_keys', check=False)
    lxc_exec(CENROLL_ALPINE, 'sh', '-c',
              "printf 'AuthorizedKeysFile none\\n' "
              ">> /etc/ssh/sshd_config.d/99-sshadmin.conf && "
              "kill -HUP $(cat /var/run/sshd.pid 2>/dev/null || "
              "cat /run/sshd.pid 2>/dev/null) 2>/dev/null || true",
              check=False)
    import time; time.sleep(1)

    result = ssh_from(C1, 'alice', alpine_ip)
    assert result.returncode == 0, (
        f'Cert-based SSH from C1 to enrolled Alpine failed:\n'
        f'stdout: {result.stdout}\nstderr: {result.stderr}'
    )
    assert 'hello' in result.stdout
