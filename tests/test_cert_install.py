"""Tests for the per-cert install token + install one-liner + install script endpoints."""
import os
import re
import subprocess
import tempfile
from datetime import datetime, timedelta
from pathlib import Path

import pytest

import sshadmin
from conftest import register_via_api


# ---------- Helpers ----------

def _issue_user_cert(client, ssh_user_id, valid_days=1):
    """Drive the issue-user-cert form and return the resulting Certificate row."""
    r = client.post('/certificates/issue/user', data={
        'user_id': ssh_user_id,
        'valid_days': str(valid_days),
        'principals': 'alice',
    }, follow_redirects=False)
    assert r.status_code == 302, r.data
    with sshadmin.app.app_context():
        cert = (
            sshadmin.Certificate.query
            .order_by(sshadmin.Certificate.id.desc())
            .first()
        )
        return cert


def _issue_host_cert(client, host_id, valid_days=1):
    r = client.post('/certificates/issue/host', data={
        'host_id': host_id, 'valid_days': str(valid_days),
    }, follow_redirects=False)
    assert r.status_code == 302, r.data
    with sshadmin.app.app_context():
        return (
            sshadmin.Certificate.query
            .order_by(sshadmin.Certificate.id.desc())
            .first()
        )


# ---------- Cert install page + endpoints ----------

def test_cert_issued_redirects_to_install_page(client, keypair, sign, ca_keys):
    """After issuing a user cert, we should land on the install page (not /certificates)."""
    register_via_api(client, sign, keypair['public_key'], username='alice')

    with sshadmin.app.app_context():
        ssh_user = sshadmin.SSHUser.query.filter_by(username='alice').first()
        assert ssh_user is not None
        ssh_user_id = ssh_user.id

    r = client.post('/certificates/issue/user', data={
        'user_id': ssh_user_id, 'valid_days': '1', 'principals': 'alice',
    })
    assert r.status_code == 302
    assert '/install' in r.headers['Location']


def test_install_page_renders_one_liner(client, keypair, sign, ca_keys):
    register_via_api(client, sign, keypair['public_key'], username='alice')
    with sshadmin.app.app_context():
        ssh_user_id = sshadmin.SSHUser.query.filter_by(username='alice').first().id

    cert = _issue_user_cert(client, ssh_user_id)
    r = client.get(f'/certificates/{cert.id}/install')
    assert r.status_code == 200
    body = r.data.decode()
    # One-liner uses curl + the install token endpoint.
    assert 'curl -fsSL' in body
    assert '/api/cert/install/script' in body
    assert cert.install_token in body


def test_install_data_endpoint_returns_cert_body(client, keypair, sign, ca_keys):
    register_via_api(client, sign, keypair['public_key'], username='alice')
    with sshadmin.app.app_context():
        ssh_user_id = sshadmin.SSHUser.query.filter_by(username='alice').first().id

    cert = _issue_user_cert(client, ssh_user_id)
    token = cert.install_token

    r = client.get(f'/api/cert/install/data?token={token}')
    assert r.status_code == 200
    body = r.data.decode().strip()
    assert body.endswith('-cert-v01@openssh.com' if False else cert.certificate_data.split()[0][:5]) is False  # sanity
    # Body should be the OpenSSH certificate text.
    assert body.startswith(('ecdsa-sha2-', 'ssh-ed25519', 'ssh-rsa'))
    assert '-cert-v01@openssh.com' in body


def test_install_data_unknown_token(client):
    r = client.get('/api/cert/install/data?token=nope')
    assert r.status_code == 404


def test_install_data_no_token(client):
    r = client.get('/api/cert/install/data')
    assert r.status_code == 400


def test_install_data_expired_token(client, keypair, sign, ca_keys):
    register_via_api(client, sign, keypair['public_key'], username='alice')
    with sshadmin.app.app_context():
        ssh_user_id = sshadmin.SSHUser.query.filter_by(username='alice').first().id

    cert = _issue_user_cert(client, ssh_user_id)
    token = cert.install_token

    with sshadmin.app.app_context():
        c = sshadmin.db.session.get(sshadmin.Certificate, cert.id)
        c.install_token_expires_at = datetime.utcnow() - timedelta(minutes=1)
        sshadmin.db.session.commit()

    r = client.get(f'/api/cert/install/data?token={token}')
    assert r.status_code == 410


def test_install_script_endpoint_returns_bash(client, keypair, sign, ca_keys):
    register_via_api(client, sign, keypair['public_key'], username='alice')
    with sshadmin.app.app_context():
        ssh_user_id = sshadmin.SSHUser.query.filter_by(username='alice').first().id

    cert = _issue_user_cert(client, ssh_user_id)
    r = client.get(f'/api/cert/install/script?token={cert.install_token}')
    assert r.status_code == 200
    body = r.data.decode()
    assert body.startswith('#!/usr/bin/env bash')
    assert 'install/data' in body
    assert cert.install_token in body
    # User-cert branch should reference ~/.ssh
    assert '~/.ssh' in body or '$SSH_DIR' in body or '${HOME}/.ssh' in body


def test_install_script_distinguishes_user_vs_host(client, keypair, sign,
                                                    host_keypair, ca_keys):
    """Script generated for a host cert must reference the host paths."""
    register_via_api(client, sign, keypair['public_key'], username='alice')
    # Add a host directly via /api/enroll/host (admin-driven path).
    r = client.post('/hosts/add', data={'hostname': 'srv1'})
    assert r.status_code == 302
    with sshadmin.app.app_context():
        host = sshadmin.Host.query.filter_by(hostname='srv1').first()
        host_token = host.enrollment_token
    r = client.post('/api/enroll/host', data={
        'token': host_token, 'public_key': host_keypair['public_key'],
    })
    assert r.status_code == 200

    with sshadmin.app.app_context():
        host_id = sshadmin.Host.query.filter_by(hostname='srv1').first().id
    cert = _issue_host_cert(client, host_id)

    r = client.get(f'/api/cert/install/script?token={cert.install_token}')
    body = r.data.decode()
    assert 'CERT_TYPE="host"' in body
    assert '/etc/ssh' in body
    assert 'sshd_config.d' in body


def test_download_cert_returns_data(client, keypair, sign, ca_keys):
    register_via_api(client, sign, keypair['public_key'], username='alice')
    with sshadmin.app.app_context():
        ssh_user_id = sshadmin.SSHUser.query.filter_by(username='alice').first().id

    cert = _issue_user_cert(client, ssh_user_id)
    r = client.get(f'/certificates/{cert.id}/download')
    assert r.status_code == 200
    assert r.headers['Content-Disposition'].startswith('attachment')
    assert b'-cert-v01@openssh.com' in r.data


def test_install_script_round_trip_actually_writes_user_cert(client, keypair, sign,
                                                             ca_keys, tmp_path,
                                                             monkeypatch):
    """Run the install script in a fake $HOME and verify the cert is placed
    next to the matching .pub."""
    register_via_api(client, sign, keypair['public_key'], username='alice')
    with sshadmin.app.app_context():
        ssh_user_id = sshadmin.SSHUser.query.filter_by(username='alice').first().id
    cert = _issue_user_cert(client, ssh_user_id)

    # Set up a fake ~/.ssh that contains only the registered pubkey.
    fake_home = tmp_path / 'home-alice'
    fake_ssh = fake_home / '.ssh'
    fake_ssh.mkdir(parents=True)
    pub_path = fake_ssh / 'id_ecdsa.pub'
    pub_path.write_text(keypair['public_key'] + '\n')

    # Get the script from the API and write to a temp file.
    r = client.get(f'/api/cert/install/script?token={cert.install_token}')
    script_path = tmp_path / 'install.sh'
    script_path.write_text(r.data.decode())
    script_path.chmod(0o755)

    # Patch the script to fetch the cert text from the test_client (the script
    # tries to curl the running server, which doesn't exist in tests). Easier:
    # just set CERT_DATA via a wrapper.
    cert_text = cert.certificate_data
    wrapper = tmp_path / 'wrapper.sh'
    wrapper.write_text(
        '#!/usr/bin/env bash\n'
        'set -euo pipefail\n'
        f'export HOME={fake_home}\n'
        # Stub `curl` on PATH so it returns the cert text.
        f'mkdir -p {tmp_path}/bin\n'
        f'cat > {tmp_path}/bin/curl <<EOF\n'
        '#!/usr/bin/env bash\n'
        f'cat {tmp_path}/cert-data\n'
        'EOF\n'
        f'chmod +x {tmp_path}/bin/curl\n'
        f'export PATH={tmp_path}/bin:$PATH\n'
        f'bash {script_path}\n'
    )
    (tmp_path / 'cert-data').write_text(cert_text + '\n')
    wrapper.chmod(0o755)

    result = subprocess.run(['bash', str(wrapper)], capture_output=True, text=True)
    assert result.returncode == 0, (result.stdout, result.stderr)
    expected = fake_ssh / 'id_ecdsa-cert.pub'
    assert expected.exists(), result.stdout
    assert expected.read_text().strip() == cert_text.strip()
