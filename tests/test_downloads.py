"""Tests for script download endpoints and their content."""
import pytest


# ── /download/sshadmin and /download/sshadmin_add ──────────────────────────────

@pytest.mark.parametrize('url', ['/download/sshadmin', '/download/sshadmin_add'])
def test_download_sshadmin_returns_200(client, url):
    r = client.get(url)
    assert r.status_code == 200


@pytest.mark.parametrize('url', ['/download/sshadmin', '/download/sshadmin_add'])
def test_download_sshadmin_content_type(client, url):
    r = client.get(url)
    assert 'shellscript' in r.content_type


@pytest.mark.parametrize('url', ['/download/sshadmin', '/download/sshadmin_add'])
def test_download_sshadmin_filename(client, url):
    r = client.get(url)
    assert 'filename=sshadmin' in r.headers.get('Content-Disposition', '')


@pytest.mark.parametrize('url', ['/download/sshadmin', '/download/sshadmin_add'])
def test_download_sshadmin_is_shell_script(client, url):
    r = client.get(url)
    assert r.data.startswith(b'#!/')


@pytest.mark.parametrize('url', ['/download/sshadmin', '/download/sshadmin_add'])
def test_download_sshadmin_host_and_port_rendered(client, url):
    r = client.get(url)
    body = r.data.decode()
    assert 'SSHADMIN_HOST=' in body
    assert 'SSHADMIN_SSH_PORT=' in body
    # Jinja2 placeholders must be fully substituted
    assert '{{' not in body


# ── /register page ─────────────────────────────────────────────────────────────

def test_register_hides_ca_pubkey_command_when_no_ca(client):
    r = client.get('/register')
    assert r.status_code == 200
    # The curl command that fetches /api/ca-pubkey must not appear when CA
    # is not configured — running it would return 503 and confuse the user.
    assert b'/api/ca-pubkey' not in r.data


def test_register_shows_ca_pubkey_command_when_ca_configured(client, ca_keys):
    r = client.get('/register')
    assert r.status_code == 200
    assert b'/api/ca-pubkey' in r.data


def test_register_always_shows_sshadmin_download_command(client):
    r = client.get('/register')
    assert r.status_code == 200
    assert b'/download/sshadmin' in r.data


# ── /api/enroll/script (enrollment_script.sh) calls ca-pubkey ─────────────────

def test_enroll_script_calls_ca_pubkey(client, keypair, sign, ca_keys):
    """enrollment_script.sh must include the /api/ca-pubkey fetch so hosts can
    trust user certificates signed by the CA."""
    from conftest import register_via_api
    register_via_api(client, sign, keypair['public_key'], username='alice')
    r = client.post('/hosts/add', data={'hostname': 'box1'})
    import sshadmin
    with sshadmin.app.app_context():
        host = sshadmin.Host.query.filter_by(hostname='box1').first()
        token = host.enrollment_token
    r = client.get(f'/api/enroll/script?token={token}')
    assert r.status_code == 200
    assert b'/api/ca-pubkey' in r.data
