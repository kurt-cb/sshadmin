"""
Pytest fixtures for the LXC integration-test suite.

Non-fixture helpers and constants live in lxc_helpers.py (same directory).
"""
from __future__ import annotations

import importlib.util as _ilu
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

# Load lxc_helpers by its filesystem path and register it in sys.modules so
# that both this conftest and the lxc test files can do
# `from lxc_helpers import ...` without adding tests/lxc/ to sys.path.
# Adding tests/lxc/ to sys.path would shadow tests/conftest.py and break
# `from conftest import ...` calls in the unit-test suite.
_lh_spec = _ilu.spec_from_file_location(
    'lxc_helpers', Path(__file__).parent / 'lxc_helpers.py')
_lh_mod = _ilu.module_from_spec(_lh_spec)
sys.modules['lxc_helpers'] = _lh_mod
_lh_spec.loader.exec_module(_lh_mod)
del _ilu, _lh_spec, _lh_mod

from lxc_helpers import (
    # containers
    CAPP, C1, C2, CALPINE,
    C_ACCT, C_SALES, C_HR,
    CENROLL_UBUNTU, CENROLL_ALPINE,
    ALL_BASE_CONTAINERS, SSH_CONTAINERS, GROUP_CONTAINERS, ENROLL_CONTAINERS,
    # misc constants
    USERNAMES, UBUNTU_IMAGE, ALPINE_IMAGE, APP_DB, APP_PORT,
    SSHADMIN_SVC_SSH_ENABLED, SSHADMIN_SVC_SSH_DISABLED, CAPP_COVERAGERC,
    # LXC helpers
    lxc, lxc_exec, push_text, push_file, pull_file,
    get_ip, wait_for_port, wait_for_ssh_port,
    sqlite_value, push_sshadmin_source,
    # HTTP helpers
    AdminSession, http_register, http_login,
    # SSH helper
    ssh_from,
    # signing helpers
    make_sign_fn, sign_expired_user_cert, sign_expired_host_cert,
)


# Module-level: set by lxc_env teardown when CAPP coverage was collected.
# Read by pytest_terminal_summary to merge it into the local .coverage.
_capp_cov_path: 'Path | None' = None


# ---------------------------------------------------------------------------
# pytest hook: merge CAPP coverage after pytest-cov writes its .coverage
# ---------------------------------------------------------------------------

@pytest.hookimpl(trylast=True)
def pytest_terminal_summary(terminalreporter, exitstatus, config):
    global _capp_cov_path
    if _capp_cov_path is None or not _capp_cov_path.exists():
        return
    project_root = Path(__file__).parent.parent.parent
    r = subprocess.run(
        [sys.executable, '-m', 'coverage', 'combine', '--append', str(_capp_cov_path)],
        cwd=str(project_root), capture_output=True, text=True,
    )
    _capp_cov_path.unlink(missing_ok=True)
    _capp_cov_path = None
    if r.returncode == 0:
        subprocess.run([sys.executable, '-m', 'coverage', 'html'],
                       cwd=str(project_root), capture_output=True)
        terminalreporter.write_sep('=', 'CAPP coverage merged — htmlcov/ updated', green=True)
    else:
        terminalreporter.write_line(
            f'CAPP coverage combine failed: {r.stderr}', red=True)


# ---------------------------------------------------------------------------
# Skip guard and marker registration
# ---------------------------------------------------------------------------

def _lxc_available() -> bool:
    try:
        r = subprocess.run(['lxc', 'version'], capture_output=True, timeout=5)
        return r.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def pytest_configure(config):
    config.addinivalue_line('markers', 'lxc: LXC end-to-end integration tests')


def pytest_collection_modifyitems(items):
    skip_lxc = pytest.mark.skipif(
        not _lxc_available(), reason='LXC not available'
    )
    for item in items:
        if item.get_closest_marker('lxc'):
            item.add_marker(skip_lxc)


# ---------------------------------------------------------------------------
# Pytest command-line option
# ---------------------------------------------------------------------------

def pytest_addoption(parser):
    parser.addoption(
        '--keep-containers',
        action='store_true',
        default=False,
        help='Leave LXC containers running after tests (useful for debugging).',
    )


# ---------------------------------------------------------------------------
# user_keypairs – session-scoped keypairs for alice, bob, carol
# ---------------------------------------------------------------------------

@pytest.fixture(scope='session')
def user_keypairs(tmp_path_factory):
    """One Ed25519 keypair per test username, generated once for the whole session."""
    d = tmp_path_factory.mktemp('lxc-user-keys')
    pairs: dict[str, dict] = {}
    for username in USERNAMES:
        priv = d / f'id_{username}'
        subprocess.run(
            ['ssh-keygen', '-t', 'ed25519', '-f', str(priv),
             '-N', '', '-C', f'{username}@lxc-test'],
            check=True, capture_output=True,
        )
        pairs[username] = {
            'private_path': str(priv),
            'public_path':  str(priv) + '.pub',
            'public_key':   (d / f'id_{username}.pub').read_text().strip(),
        }
    return pairs


# ---------------------------------------------------------------------------
# lxc_env – base topology: CAPP + C1 + C2 + CALPINE
# ---------------------------------------------------------------------------

@pytest.fixture(scope='session')
def lxc_env(request, tmp_path_factory, user_keypairs):
    """
    Provision four LXC containers and wire up full sshadmin certificate auth.

    CAPP    – Ubuntu 22.04: sshadmin Flask server + site CA.
    C1/C2   – Ubuntu 22.04: OpenSSH client/server nodes, enrolled as hosts.
    CALPINE – Alpine 3: Dropbear server + OpenSSH client.

    Yields a state dict; tears everything down on exit unless --keep-containers.
    """
    keep = request.config.getoption('--keep-containers', default=False)

    for c in ALL_BASE_CONTAINERS:
        subprocess.run(['lxc', 'delete', '--force', c], capture_output=True)

    for img, name in [
        (UBUNTU_IMAGE, CAPP),
        (UBUNTU_IMAGE, C1),
        (UBUNTU_IMAGE, C2),
        (ALPINE_IMAGE, CALPINE),
    ]:
        lxc('launch', img, name, '--config', 'security.privileged=true', timeout=300)

    state: dict = {}
    try:
        ips = {c: get_ip(c) for c in ALL_BASE_CONTAINERS}
        state['ips'] = ips
        app_url = f'http://{ips[CAPP]}:{APP_PORT}'
        state['app_url'] = app_url

        # ── CAPP: install deps, push source, generate CA, start Flask ──────── #
        lxc_exec(CAPP, 'apt-get', 'update', '-q', timeout=120)
        lxc_exec(CAPP, 'apt-get', 'install', '-y', '-q',
                 'python3-pip', 'openssh-client', timeout=300)
        push_sshadmin_source(CAPP)
        lxc_exec(CAPP, 'pip3', 'install', '-r', '/app/requirements.txt',
                 '--quiet', timeout=300)
        lxc_exec(CAPP, 'mkdir', '-p', '/app/instance')
        push_text(CAPP, CAPP_COVERAGERC, '/app/.coveragerc')

        lxc_exec(CAPP, 'python3', '-c', f"""
import sys, os
sys.path.insert(0, '/app')
os.environ['DATABASE_URL'] = 'sqlite:////{APP_DB}'
os.environ['SECRET_KEY']   = 'lxc-test-secret'
os.environ['SSH_CA_KEY']   = '/app/ca_key'
import sshadmin
sshadmin.cert_gen.generate_ca(comment='lxc-integration-test CA')
""")

        push_text(CAPP, SSHADMIN_SVC_SSH_DISABLED,
                  '/etc/systemd/system/sshadmin.service')
        lxc_exec(CAPP, 'systemctl', 'daemon-reload')
        lxc_exec(CAPP, 'systemctl', 'start', 'sshadmin')
        wait_for_port(CAPP, APP_PORT, max_wait=90)

        ca_pubkey = lxc_exec(CAPP, 'cat', '/app/ca_key.pub').stdout.strip()
        state['ca_pubkey'] = ca_pubkey

        ca_local_dir = tmp_path_factory.mktemp('lxc-ca')
        ca_key_local = ca_local_dir / 'ca_key'
        pull_file(CAPP, '/app/ca_key', str(ca_key_local))
        os.chmod(str(ca_key_local), 0o600)
        state['ca_key_local'] = str(ca_key_local)

        # ── C1/C2: OpenSSH server, P-521 host key, OS users ─────────────────  #
        for c in SSH_CONTAINERS:
            lxc_exec(c, 'apt-get', 'update', '-q', timeout=120)
            lxc_exec(c, 'apt-get', 'install', '-y', '-q', 'openssh-server', timeout=300)
            lxc_exec(c, 'bash', '-c',
                     'rm -f /etc/ssh/ssh_host_ecdsa_key* && '
                     'ssh-keygen -t ecdsa -b 521 '
                     '-f /etc/ssh/ssh_host_ecdsa_key -N "" -C ""')
            for username in USERNAMES:
                lxc_exec(c, 'useradd', '-m', '-s', '/bin/bash', username)
                lxc_exec(c, 'bash', '-c',
                          f'mkdir -p /home/{username}/.ssh && '
                          f'chmod 700 /home/{username}/.ssh && '
                          f'chown -R {username}:{username} /home/{username}/.ssh')

        # ── CALPINE: Alpine + Dropbear + OpenSSH client ───────────────────── #
        lxc_exec(CALPINE, 'apk', 'add', '--no-cache',
                 'dropbear', 'openssh-client', timeout=300)
        lxc_exec(CALPINE, 'mkdir', '-p', '/etc/dropbear')
        lxc_exec(CALPINE, 'dropbearkey', '-t', 'ecdsa',
                 '-f', '/etc/dropbear/dropbear_ecdsa_host_key')

        r = lxc_exec(CALPINE, 'dropbearkey', '-y',
                     '-f', '/etc/dropbear/dropbear_ecdsa_host_key')
        alpine_host_pub = next(
            line for line in r.stdout.splitlines()
            if line.startswith('ecdsa-sha2-')
        )
        state['alpine_host_pub'] = alpine_host_pub

        for username in USERNAMES:
            lxc_exec(CALPINE, 'adduser', '-D', '-s', '/bin/sh', username)
            lxc_exec(CALPINE, 'mkdir', '-p', f'/home/{username}/.ssh')
            lxc_exec(CALPINE, 'chmod', '700', f'/home/{username}/.ssh')
            lxc_exec(CALPINE, 'chown', '-R',
                     f'{username}:{username}', f'/home/{username}/.ssh')
        lxc_exec(CALPINE, 'dropbear', '-p', '22')

        # ── Register users (alice first → admin) ─────────────────────────── #
        alice_session = AdminSession(app_url)
        http_register(alice_session,
                      make_sign_fn(user_keypairs['alice']['private_path']),
                      user_keypairs['alice']['public_key'], 'alice')
        for uname in ['bob', 'carol']:
            s = AdminSession(app_url)
            http_register(s,
                          make_sign_fn(user_keypairs[uname]['private_path']),
                          user_keypairs[uname]['public_key'], uname)

        state['app_user_ids'] = {
            u: int(sqlite_value(f"SELECT id FROM user WHERE username='{u}'"))
            for u in USERNAMES
        }
        state['credential_ids'] = {
            u: int(sqlite_value(
                f"SELECT uc.id FROM user_credential uc "
                f"JOIN user usr ON usr.id = uc.user_id "
                f"WHERE usr.username='{u}' LIMIT 1"
            ))
            for u in USERNAMES
        }

        # ── Enroll C1/C2 as hosts; issue host certs ──────────────────────── #
        host_pub_keys: dict[str, str] = {}
        host_cert_data: dict[str, str] = {}
        host_ids: dict[str, int] = {}

        for container in SSH_CONTAINERS:
            ip = ips[container]
            alice_session.post('/hosts/add',
                               {'hostname': ip, 'description': f'LXC {container}'})
            host_id = int(sqlite_value(f"SELECT id FROM host WHERE hostname='{ip}'"))
            token   = sqlite_value(
                f"SELECT enrollment_token FROM host WHERE id={host_id}")
            host_ids[container] = host_id

            host_pub = lxc_exec(container, 'cat',
                                 '/etc/ssh/ssh_host_ecdsa_key.pub').stdout.strip()
            host_pub_keys[container] = host_pub
            result = alice_session.post_json('/api/enroll/host',
                                            {'token': token, 'public_key': host_pub})
            assert result.get('ok'), f'Host enrollment failed for {container}: {result}'

            alice_session.post('/certificates/issue/host',
                               {'host_id': host_id, 'valid_days': '365'})
            cert_data = sqlite_value(
                f"SELECT c.certificate_data FROM certificate c "
                f"JOIN ssh_key sk ON sk.id = c.ssh_key_id "
                f"JOIN host h ON h.host_key_id = sk.id "
                f"WHERE h.id = {host_id} ORDER BY c.id DESC LIMIT 1"
            )
            host_cert_data[container] = cert_data

        alpine_ip = ips[CALPINE]
        alice_session.post('/hosts/add',
                           {'hostname': alpine_ip, 'description': 'Alpine Dropbear'})
        alpine_host_id = int(sqlite_value(
            f"SELECT id FROM host WHERE hostname='{alpine_ip}'"))
        alpine_token = sqlite_value(
            f"SELECT enrollment_token FROM host WHERE id={alpine_host_id}")
        state['alpine_enrollment_result'] = alice_session.post_json(
            '/api/enroll/host',
            {'token': alpine_token, 'public_key': state['alpine_host_pub']},
        )

        state['host_pub_keys']  = host_pub_keys
        state['host_cert_data'] = host_cert_data
        state['host_ids']       = host_ids

        # ── Issue user certificates (default/site CA) ─────────────────────── #
        user_certs: dict[str, str] = {}
        for username in USERNAMES:
            cred_id = state['credential_ids'][username]
            alice_session.post('/certificates/issue/user',
                               {'credential_id': cred_id, 'valid_days': '365',
                                'principals': username})
            cert_data = sqlite_value(
                f"SELECT c.certificate_data FROM certificate c "
                f"JOIN user_credential uc ON uc.user_key_id = c.ssh_key_id "
                f"WHERE uc.id = {cred_id} ORDER BY c.id DESC LIMIT 1"
            )
            user_certs[username] = cert_data
        state['user_certs'] = user_certs

        # ── Deploy CA, host certs, sshd drop-in to C1 and C2 ─────────────── #
        sshd_drop_in = (
            'PasswordAuthentication no\n'
            'PubkeyAuthentication yes\n'
            'AuthorizedKeysFile none\n'
            'TrustedUserCAKeys /etc/ssh/sshadmin_ca.pub\n'
            'HostCertificate /etc/ssh/ssh_host_ecdsa_key-cert.pub\n'
        )
        for c in SSH_CONTAINERS:
            push_text(c, ca_pubkey + '\n', '/etc/ssh/sshadmin_ca.pub', mode='644')
            push_text(c, host_cert_data[c] + '\n',
                      '/etc/ssh/ssh_host_ecdsa_key-cert.pub', mode='644')
            push_text(c, sshd_drop_in,
                      '/etc/ssh/sshd_config.d/sshadmin.conf', mode='644')
            lxc_exec(c, 'systemctl', 'reload', 'ssh')

        # ── known_hosts on C1: CA covers C2; raw key covers CALPINE ──────── #
        push_text(
            C1,
            f'@cert-authority * {ca_pubkey}\n'
            f'{alpine_ip} {alpine_host_pub}\n',
            '/etc/ssh/ssh_known_hosts', mode='644',
        )

        # ── User keys + certs on C1 for outbound SSH ─────────────────────── #
        for username in USERNAMES:
            priv     = user_keypairs[username]['private_path']
            home_ssh = f'/home/{username}/.ssh'
            push_file(C1, priv, f'{home_ssh}/id_ed25519',
                      mode='600', owner=f'{username}:{username}')
            push_text(C1, user_certs[username] + '\n',
                      f'{home_ssh}/id_ed25519-cert.pub',
                      mode='644', owner=f'{username}:{username}')

        # ── CALPINE: authorized_keys + alice cert for outbound ────────────── #
        for username in USERNAMES:
            push_text(CALPINE, user_keypairs[username]['public_key'] + '\n',
                      f'/home/{username}/.ssh/authorized_keys',
                      mode='600', owner=f'{username}:{username}')
        push_file(CALPINE, user_keypairs['alice']['private_path'],
                  '/home/alice/.ssh/id_ed25519',
                  mode='600', owner='alice:alice')
        push_text(CALPINE, user_certs['alice'] + '\n',
                  '/home/alice/.ssh/id_ed25519-cert.pub',
                  mode='644', owner='alice:alice')
        push_text(CALPINE, f'@cert-authority * {ca_pubkey}\n',
                  '/etc/ssh/ssh_known_hosts', mode='644')

        yield state

    finally:
        global _capp_cov_path
        # Stop the service gracefully so coverage writes its data file
        # (sigterm=true in /app/.coveragerc causes the coverage atexit to fire).
        lxc_exec(CAPP, 'systemctl', 'stop', 'sshadmin', check=False)
        time.sleep(2)

        # Pull coverage from CAPP to the project root for later combining.
        project_root = Path(__file__).parent.parent.parent
        capp_cov = project_root / '.coverage.capp'
        pull_r = subprocess.run(
            ['lxc', 'file', 'pull', f'{CAPP}/app/.coverage.capp', str(capp_cov)],
            capture_output=True,
        )
        if pull_r.returncode == 0 and capp_cov.exists():
            _capp_cov_path = capp_cov

        if not keep:
            for c in ALL_BASE_CONTAINERS:
                subprocess.run(['lxc', 'delete', '--force', c], capture_output=True)


# ---------------------------------------------------------------------------
# group_env – multi-CA isolation: Accounting / Sales / HR
# ---------------------------------------------------------------------------

@pytest.fixture(scope='session')
def group_env(request, lxc_env, user_keypairs):
    """
    Extends lxc_env with three isolated CA groups and dedicated host containers.

    Groups and their primary users:
      accounting → alice   C_ACCT  trusts Accounting CA only
      sales      → bob     C_SALES trusts Sales CA only
      hr         → carol   C_HR    trusts HR CA only

    Each group has its own CA keypair generated by sshadmin at group-create time.
    A cert signed by the Accounting CA is cryptographically rejected by C_SALES
    and C_HR — OpenSSH enforces this via TrustedUserCAKeys with no runtime check.

    Group identity files on C1:
      /home/<user>/.ssh/id_group         – copy of private key
      /home/<user>/.ssh/id_group-cert.pub – cert signed by group CA

    The default id_ed25519 / id_ed25519-cert.pub (site CA) are untouched.
    """
    keep    = request.config.getoption('--keep-containers', default=False)
    ips     = lxc_env['ips']
    app_url = lxc_env['app_url']

    for c in GROUP_CONTAINERS:
        subprocess.run(['lxc', 'delete', '--force', c], capture_output=True)
    for c in GROUP_CONTAINERS:
        lxc('launch', UBUNTU_IMAGE, c,
            '--config', 'security.privileged=true', timeout=300)

    state: dict = {}
    try:
        group_ips = {c: get_ip(c) for c in GROUP_CONTAINERS}
        state['ips'] = group_ips

        # ── Prepare each group container ──────────────────────────────────── #
        for c in GROUP_CONTAINERS:
            lxc_exec(c, 'apt-get', 'update', '-q', timeout=120)
            lxc_exec(c, 'apt-get', 'install', '-y', '-q', 'openssh-server', timeout=300)
            lxc_exec(c, 'bash', '-c',
                     'rm -f /etc/ssh/ssh_host_ecdsa_key* && '
                     'ssh-keygen -t ecdsa -b 521 '
                     '-f /etc/ssh/ssh_host_ecdsa_key -N "" -C ""')
            # Create all three users so SSH failures are due to CA mismatch,
            # not a missing unix account.
            for username in USERNAMES:
                lxc_exec(c, 'useradd', '-m', '-s', '/bin/bash', username)
                lxc_exec(c, 'bash', '-c',
                          f'mkdir -p /home/{username}/.ssh && '
                          f'chmod 700 /home/{username}/.ssh && '
                          f'chown -R {username}:{username} /home/{username}/.ssh')

        # ── Log in as alice (admin) ───────────────────────────────────────── #
        alice_session = AdminSession(app_url)
        http_login(alice_session,
                   make_sign_fn(user_keypairs['alice']['private_path']),
                   'alice')

        # ── Enable multi-group mode ───────────────────────────────────────── #
        alice_session.post('/admin_settings', {
            'user_key_types':      ['ecdsa-sha2-nistp521', 'ssh-ed25519',
                                    'ecdsa-sha2-nistp384'],
            'multi_group_enabled': '1',
        })

        # ── Create groups (alice auto-approved into each as creator) ─────── #
        group_ids: dict[str, int] = {}
        for group_name in ('accounting', 'sales', 'hr'):
            alice_session.post('/groups/create', {
                'name':        group_name,
                'description': f'{group_name.title()} department CA group',
            })
            group_ids[group_name] = int(sqlite_value(
                f"SELECT id FROM ca_group WHERE name='{group_name}'"))
        state['group_ids'] = group_ids

        # ── Remove alice/bob/carol from the default group ─────────────────── #
        # Without this, _get_user_cert_ca_key() returns the default group's CA
        # (the site CA) because it has the lowest group ID, defeating isolation.
        default_id = int(sqlite_value("SELECT id FROM ca_group WHERE name='default'"))
        for username in USERNAMES:
            uid    = lxc_env['app_user_ids'][username]
            mem_id = sqlite_value(
                f"SELECT id FROM user_group_membership "
                f"WHERE user_id={uid} AND group_id={default_id}"
            )
            if mem_id:
                alice_session.post(f'/groups/{default_id}/remove-user/{mem_id}', {})

        # ── Bob requests Sales access; carol requests HR access ────────────── #
        bob_session = AdminSession(app_url)
        http_login(bob_session,
                   make_sign_fn(user_keypairs['bob']['private_path']), 'bob')
        bob_session.post(f'/groups/{group_ids["sales"]}/request-access',
                         {'unix_principals': 'bob'})

        carol_session = AdminSession(app_url)
        http_login(carol_session,
                   make_sign_fn(user_keypairs['carol']['private_path']), 'carol')
        carol_session.post(f'/groups/{group_ids["hr"]}/request-access',
                           {'unix_principals': 'carol'})

        # ── Alice approves bob (Sales) and carol (HR) ─────────────────────── #
        bob_uid   = lxc_env['app_user_ids']['bob']
        carol_uid = lxc_env['app_user_ids']['carol']

        bob_mem = sqlite_value(
            f"SELECT id FROM user_group_membership "
            f"WHERE user_id={bob_uid} AND group_id={group_ids['sales']}"
        )
        alice_session.post(
            f'/groups/{group_ids["sales"]}/approve-user/{bob_mem}',
            {'unix_principals': 'bob'})

        carol_mem = sqlite_value(
            f"SELECT id FROM user_group_membership "
            f"WHERE user_id={carol_uid} AND group_id={group_ids['hr']}"
        )
        alice_session.post(
            f'/groups/{group_ids["hr"]}/approve-user/{carol_mem}',
            {'unix_principals': 'carol'})

        # ── Pull group CA public keys from CAPP ───────────────────────────── #
        group_ca_pubkeys: dict[str, str] = {}
        for group_name, gid in group_ids.items():
            ca_key_path = sqlite_value(
                f"SELECT ca_key_path FROM ca_group WHERE id={gid}")
            pub = lxc_exec(CAPP, 'cat', ca_key_path + '.pub').stdout.strip()
            group_ca_pubkeys[group_name] = pub
        state['group_ca_pubkeys'] = group_ca_pubkeys

        # ── Issue group-specific user certs ───────────────────────────────── #
        # After removing users from the default group:
        #   alice → first active group = accounting → signed by Accounting CA
        #   bob   → first active group = sales      → signed by Sales CA
        #   carol → first active group = hr         → signed by HR CA
        group_user_certs: dict[str, str] = {}
        for username in USERNAMES:
            cred_id = lxc_env['credential_ids'][username]
            alice_session.post('/certificates/issue/user',
                               {'credential_id': cred_id, 'valid_days': '365',
                                'principals': username})
            cert_data = sqlite_value(
                f"SELECT c.certificate_data FROM certificate c "
                f"JOIN user_credential uc ON uc.user_key_id = c.ssh_key_id "
                f"WHERE uc.id = {cred_id} ORDER BY c.id DESC LIMIT 1"
            )
            group_user_certs[username] = cert_data
        state['group_user_certs'] = group_user_certs

        # ── Deploy group identity to C1 (id_group / id_group-cert.pub) ────── #
        for username in USERNAMES:
            priv     = user_keypairs[username]['private_path']
            home_ssh = f'/home/{username}/.ssh'
            push_file(C1, priv, f'{home_ssh}/id_group',
                      mode='600', owner=f'{username}:{username}')
            push_text(C1, group_user_certs[username] + '\n',
                      f'{home_ssh}/id_group-cert.pub',
                      mode='644', owner=f'{username}:{username}')

        # ── Enroll group containers as hosts + issue host certs ────────────── #
        container_for_group = {
            'accounting': C_ACCT,
            'sales':      C_SALES,
            'hr':         C_HR,
        }
        group_host_ids: dict[str, int] = {}
        group_host_cert_data: dict[str, str] = {}

        for group_name, container in container_for_group.items():
            ip = group_ips[container]
            alice_session.post('/hosts/add',
                               {'hostname': ip,
                                'description': f'{group_name.title()} test host'})
            host_id = int(sqlite_value(f"SELECT id FROM host WHERE hostname='{ip}'"))
            token   = sqlite_value(
                f"SELECT enrollment_token FROM host WHERE id={host_id}")
            group_host_ids[group_name] = host_id

            host_pub = lxc_exec(container, 'cat',
                                 '/etc/ssh/ssh_host_ecdsa_key.pub').stdout.strip()
            result = alice_session.post_json('/api/enroll/host',
                                            {'token': token, 'public_key': host_pub})
            assert result.get('ok'), \
                f'Group host enrollment failed for {container}: {result}'

            alice_session.post('/certificates/issue/host',
                               {'host_id': host_id, 'valid_days': '365'})
            host_cert = sqlite_value(
                f"SELECT c.certificate_data FROM certificate c "
                f"JOIN ssh_key sk ON sk.id = c.ssh_key_id "
                f"JOIN host h ON h.host_key_id = sk.id "
                f"WHERE h.id = {host_id} ORDER BY c.id DESC LIMIT 1"
            )
            group_host_cert_data[group_name] = host_cert

        state['group_host_ids']       = group_host_ids
        state['group_host_cert_data'] = group_host_cert_data
        state['container_for_group']  = container_for_group

        # ── Configure sshd on each group container ────────────────────────── #
        # TrustedUserCAKeys = only the group's own CA key.
        # HostCertificate   = signed by the site CA (C1 known_hosts covers it).
        for group_name, container in container_for_group.items():
            push_text(container, group_ca_pubkeys[group_name] + '\n',
                      '/etc/ssh/group_ca.pub', mode='644')
            push_text(container, group_host_cert_data[group_name] + '\n',
                      '/etc/ssh/ssh_host_ecdsa_key-cert.pub', mode='644')
            push_text(container,
                      'PasswordAuthentication no\n'
                      'PubkeyAuthentication yes\n'
                      'AuthorizedKeysFile none\n'
                      'TrustedUserCAKeys /etc/ssh/group_ca.pub\n'
                      'HostCertificate /etc/ssh/ssh_host_ecdsa_key-cert.pub\n',
                      '/etc/ssh/sshd_config.d/sshadmin.conf', mode='644')
            lxc_exec(container, 'systemctl', 'reload', 'ssh')

        yield state

    finally:
        if not keep:
            for c in GROUP_CONTAINERS:
                subprocess.run(['lxc', 'delete', '--force', c], capture_output=True)


# ---------------------------------------------------------------------------
# lxc_enroll_env – sshadmin_add enrollment script tests
# ---------------------------------------------------------------------------

@pytest.fixture(scope='session')
def lxc_enroll_env(request, lxc_env, user_keypairs):
    """
    Provision two fresh containers and enroll them via the sshadmin_add script
    run from C1 (which already has alice's registered key).

    Temporarily enables the SSH auth server on CAPP; restores it on teardown.
    """
    keep   = request.config.getoption('--keep-containers', default=False)
    ips    = lxc_env['ips']
    app_ip = ips[CAPP]

    for c in ENROLL_CONTAINERS:
        subprocess.run(['lxc', 'delete', '--force', c], capture_output=True)
    lxc('launch', UBUNTU_IMAGE, CENROLL_UBUNTU,
        '--config', 'security.privileged=true', timeout=300)
    lxc('launch', ALPINE_IMAGE, CENROLL_ALPINE,
        '--config', 'security.privileged=true', timeout=300)

    state: dict = {}
    try:
        enroll_ips = {
            CENROLL_UBUNTU: get_ip(CENROLL_UBUNTU),
            CENROLL_ALPINE: get_ip(CENROLL_ALPINE),
        }
        state['ips'] = enroll_ips
        alice_pub = user_keypairs['alice']['public_key']

        lxc_exec(CENROLL_UBUNTU, 'apt-get', 'update', '-q', timeout=120)
        lxc_exec(CENROLL_UBUNTU, 'apt-get', 'install', '-y', '-q',
                 'openssh-server', 'sudo', timeout=300)
        lxc_exec(CENROLL_UBUNTU, 'useradd', '-m', '-s', '/bin/bash', 'alice')
        lxc_exec(CENROLL_UBUNTU, 'bash', '-c',
                 'mkdir -p /home/alice/.ssh && chmod 700 /home/alice/.ssh '
                 '&& chown alice:alice /home/alice/.ssh')
        push_text(CENROLL_UBUNTU, alice_pub + '\n',
                  '/home/alice/.ssh/authorized_keys',
                  mode='600', owner='alice:alice')
        push_text(CENROLL_UBUNTU, 'alice ALL=(ALL) NOPASSWD:ALL\n',
                  '/etc/sudoers.d/alice', mode='440')

        lxc_exec(CENROLL_ALPINE, 'apk', 'add', '--no-cache',
                 'openssh', 'sudo', timeout=300)
        lxc_exec(CENROLL_ALPINE, 'ssh-keygen', '-A')
        lxc_exec(CENROLL_ALPINE, 'mkdir', '-p', '/etc/ssh/sshd_config.d')
        lxc_exec(CENROLL_ALPINE, 'sh', '-c',
                 'echo "Include /etc/ssh/sshd_config.d/*.conf" >> /etc/ssh/sshd_config')
        lxc_exec(CENROLL_ALPINE, '/usr/sbin/sshd')
        lxc_exec(CENROLL_ALPINE, 'adduser', '-D', '-s', '/bin/sh', 'alice')
        lxc_exec(CENROLL_ALPINE, 'mkdir', '-p', '/home/alice/.ssh')
        lxc_exec(CENROLL_ALPINE, 'chmod', '700', '/home/alice/.ssh')
        lxc_exec(CENROLL_ALPINE, 'chown', '-R', 'alice:alice', '/home/alice/.ssh')
        push_text(CENROLL_ALPINE, alice_pub + '\n',
                  '/home/alice/.ssh/authorized_keys',
                  mode='600', owner='alice:alice')
        push_text(CENROLL_ALPINE,
                  'Defaults !requiretty\nalice ALL=(ALL) NOPASSWD:ALL\n',
                  '/etc/sudoers.d/alice', mode='440')
        lxc_exec(CENROLL_ALPINE, 'rm', '-f',
                 '/etc/ssh/ssh_host_ecdsa_key',
                 '/etc/ssh/ssh_host_ecdsa_key.pub')

        push_text(CAPP, SSHADMIN_SVC_SSH_ENABLED,
                  '/etc/systemd/system/sshadmin.service')
        lxc_exec(CAPP, 'systemctl', 'daemon-reload')
        lxc_exec(CAPP, 'systemctl', 'restart', 'sshadmin')
        wait_for_port(CAPP, APP_PORT, max_wait=60)
        wait_for_ssh_port(CAPP, port=2222, max_wait=30)

        script_url = f'http://{app_ip}:{APP_PORT}/download/sshadmin_add'
        lxc_exec(C1, 'python3', '-c',
                 f"import urllib.request; "
                 f"open('/usr/local/bin/sshadmin_add','wb')"
                 f".write(urllib.request.urlopen('{script_url}').read())")
        lxc_exec(C1, 'chmod', '+x', '/usr/local/bin/sshadmin_add')

        ubuntu_ip = enroll_ips[CENROLL_UBUNTU]
        alpine_ip = enroll_ips[CENROLL_ALPINE]

        state['ubuntu_result'] = subprocess.run(
            ['lxc', 'exec', C1, '--', 'su', '-', 'alice', '-c',
             f'sshadmin_add alice@{ubuntu_ip}'],
            capture_output=True, text=True, timeout=180,
        )
        state['alpine_result'] = subprocess.run(
            ['lxc', 'exec', C1, '--', 'su', '-', 'alice', '-c',
             f'sshadmin_add alice@{alpine_ip}'],
            capture_output=True, text=True, timeout=180,
        )

        lxc_exec(CENROLL_ALPINE, 'sh', '-c', 'pkill sshd || true', check=False)
        time.sleep(1)
        lxc_exec(CENROLL_ALPINE, '/usr/sbin/sshd', check=False)
        wait_for_ssh_port(CENROLL_ALPINE, port=22, max_wait=30)

        yield state

    finally:
        push_text(CAPP, SSHADMIN_SVC_SSH_DISABLED,
                  '/etc/systemd/system/sshadmin.service')
        lxc_exec(CAPP, 'systemctl', 'daemon-reload', check=False)
        lxc_exec(CAPP, 'systemctl', 'restart', 'sshadmin', check=False)

        if not keep:
            for c in ENROLL_CONTAINERS:
                subprocess.run(['lxc', 'delete', '--force', c], capture_output=True)
