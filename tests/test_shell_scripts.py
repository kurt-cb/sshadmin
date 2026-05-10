"""
Shell script template tests — syntax and static analysis.

The shell scripts in templates/ are Jinja2 templates containing {{ variable }}
placeholders.  They cannot be executed directly, so coverage is approached in
two layers:

  1. Syntax check (bash -n): substitute placeholder variables with safe dummy
     values, then run `bash -n` to verify the rendered script parses cleanly.
     This catches mismatched quotes, unclosed subshells, etc.

  2. Static analysis (shellcheck, optional): if shellcheck is available on
     PATH it is run on the rendered script.  shellcheck finds semantic issues
     that bash -n misses (quoting, unbound variables, etc.).  The test is
     skipped if shellcheck is not installed.
"""
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest

TEMPLATES_DIR = Path(__file__).parent.parent / 'templates'

# Dummy substitution values for each Jinja2 variable.
_DUMMY_VARS: dict[str, str] = {
    'server_url':        'https://sshadmin.example.com',
    'token':             'dummytoken1234567890',
    'nonce':             'dummynonce0987654321',
    'username':          'alice',
    'purpose':           'user',
    'host_key_type':     'ecdsa',
    'pk':                'AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAI',
    'sshsig_namespace':  'sshadmin-auth',
    'cert_pubkey_line':  'ecdsa-sha2-nistp256 AAAAE2Vj dummy@host',
    'cert_type':         'user',
    'target_name':       'myhost.example.com',
    'hostname':          'myhost',
    'key_type':          'ecdsa',
    'ssh_host':          'sshadmin.example.com',
    'ssh_port':          '2222',
}


def _render(script_path: Path) -> str:
    """Replace every {{ var }} placeholder with a safe dummy value."""
    text = script_path.read_text()
    return re.sub(
        r'\{\{\s*(\w+)\s*\}\}',
        lambda m: _DUMMY_VARS.get(m.group(1), 'DUMMY'),
        text,
    )


def _shell_scripts() -> list[Path]:
    return list(TEMPLATES_DIR.glob('*.sh'))


@pytest.mark.parametrize('script', _shell_scripts(), ids=lambda p: p.name)
def test_bash_syntax(script: Path):
    """bash -n must succeed on the rendered template (no Jinja2 placeholders)."""
    rendered = _render(script)
    with tempfile.NamedTemporaryFile(suffix='.sh', mode='w', delete=False) as fh:
        fh.write(rendered)
        tmp = Path(fh.name)
    try:
        result = subprocess.run(
            ['bash', '-n', str(tmp)],
            capture_output=True, text=True,
        )
        assert result.returncode == 0, (
            f'bash -n failed for {script.name}:\n{result.stderr}'
        )
    finally:
        tmp.unlink(missing_ok=True)


@pytest.mark.parametrize('script', _shell_scripts(), ids=lambda p: p.name)
def test_shellcheck(script: Path):
    """shellcheck must report no errors on the rendered template."""
    if not shutil.which('shellcheck'):
        pytest.skip('shellcheck not installed')

    rendered = _render(script)
    with tempfile.NamedTemporaryFile(suffix='.sh', mode='w', delete=False) as fh:
        fh.write(rendered)
        tmp = Path(fh.name)
    try:
        result = subprocess.run(
            ['shellcheck', '--shell=bash', str(tmp)],
            capture_output=True, text=True,
        )
        assert result.returncode == 0, (
            f'shellcheck errors in {script.name}:\n{result.stdout}\n{result.stderr}'
        )
    finally:
        tmp.unlink(missing_ok=True)
