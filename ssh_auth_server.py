"""SSH-based alternative auth path for sshadmin.

Listens on a configurable port. Users connect with:

    ssh -p <PORT> <username>@<host>

The server authenticates the user via their registered SSH public key, then
opens an interactive session that prompts for the challenge token shown in
the browser. On submission the challenge is validated and consumed using the
same logic as the REST/curl path.

This is the "Option 3" UX: works in OpenSSH, plink, PuTTY, TeraTerm, and any
other SSH client that supports public-key auth — no exec command needed.
"""
from __future__ import annotations

import base64
import json as _json
import os
import socket
import subprocess
import threading
import time
from datetime import datetime

import paramiko


SESSION_TIMEOUT = 120  # seconds the user has to paste the token after auth.
TOKEN_MAX_LEN = 200    # generous; tokens are 43 chars, leave room.

WELCOME_BANNER = (
    "\r\n"
    "===  sshadmin authentication  ===\r\n"
    "\r\n"
    "You are authenticated by your SSH public key as user: {username}\r\n"
    "\r\n"
    "To finish the login or registration shown in your browser, paste the\r\n"
    "challenge token displayed on the 'Awaiting verification' page and press\r\n"
    "Enter. The token is one-time-use and expires 30 minutes after issue.\r\n"
    "\r\n"
    "Press Ctrl-C or Ctrl-D to abort without consuming the token.\r\n"
    "\r\n"
)


def _ensure_host_key(path):
    """Generate or load the SSH server's host identity (RSA 2048)."""
    if os.path.exists(path):
        return paramiko.RSAKey(filename=path)
    os.makedirs(os.path.dirname(path) or '.', exist_ok=True)
    key = paramiko.RSAKey.generate(2048)
    key.write_private_key_file(path)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    # Write the .pub alongside, so we can sign it with the CA and so users
    # can pin it manually without going through the cert path.
    pub_path = path + '.pub'
    if not os.path.exists(pub_path):
        with open(pub_path, 'w') as f:
            f.write(f'{key.get_name()} {key.get_base64()} sshadmin-auth\n')
        try:
            os.chmod(pub_path, 0o644)
        except OSError:
            pass
    return key


def _ensure_signed_host_cert(host_key_path, ca_key_path, principals):
    """If the CA exists, sign the SSH server's host key. Returns the cert path
    or None if signing is not available."""
    if not ca_key_path or not os.path.exists(ca_key_path):
        return None
    pub_path = host_key_path + '.pub'
    cert_path = host_key_path + '-cert.pub'
    if os.path.exists(cert_path):
        return cert_path
    if not os.path.exists(pub_path):
        return None
    serial = str(int(time.time() * 1000))
    cmd = [
        'ssh-keygen', '-s', ca_key_path, '-h',
        '-I', f'sshadmin-auth-{serial}',
        '-n', ','.join(principals or ['sshadmin']),
        '-V', '+52w',
        '-z', serial,
        pub_path,
    ]
    try:
        subprocess.run(cmd, check=True, capture_output=True, text=True)
    except subprocess.CalledProcessError:
        return None
    if os.path.exists(cert_path):
        try:
            os.chmod(cert_path, 0o644)
        except OSError:
            pass
        return cert_path
    return None


def _offered_key_matches_stored(offered_key, stored_pubkey_str):
    """Compare a paramiko PKey against the SSH-format public key text on file."""
    parts = (stored_pubkey_str or '').split()
    if len(parts) < 2:
        return False
    try:
        offered_b64 = base64.b64encode(offered_key.asbytes()).decode()
    except Exception:
        return False
    return parts[1] == offered_b64


class _SSHAuthServerInterface(paramiko.ServerInterface):
    """Per-connection paramiko server interface."""

    def __init__(self, app, models):
        self.app = app
        self.User = models['User']
        self.Challenge = models['Challenge']
        self.UserCredential = models.get('UserCredential')
        self.user_id = None
        self.username = None
        self.credential_id = None  # set when a specific credential key matched
        # session_event fires for either shell or exec request.
        self.session_event = threading.Event()
        self.exec_command = None  # set when client sent an exec request

    def get_allowed_auths(self, username):
        return 'publickey'

    def check_auth_password(self, username, password):
        return paramiko.AUTH_FAILED

    def check_auth_publickey(self, username, key):
        with self.app.app_context():
            user = self.User.query.filter_by(username=username).first()
            if not user:
                return paramiko.AUTH_FAILED

            if user.completed_at is not None:
                # Completed user: check all registered credential keys.
                if self.UserCredential is None:
                    return paramiko.AUTH_FAILED
                matched_cred = None
                for cred in user.credentials:
                    if _offered_key_matches_stored(key, cred.user_key.public_key):
                        matched_cred = cred
                        break
                if matched_cred is None:
                    return paramiko.AUTH_FAILED
                self.credential_id = matched_cred.id
            else:
                # Pending user (mid-registration): accept only if there is an
                # active register challenge whose expected_key matches the offered
                # key. Abandoned registrations with no live challenge are rejected.
                active = (
                    self.Challenge.query
                    .filter_by(user_id=user.id, purpose='register', consumed_at=None)
                    .filter(self.Challenge.expires_at > datetime.utcnow())
                    .first()
                )
                if active is None:
                    return paramiko.AUTH_FAILED
                if not _offered_key_matches_stored(key, active.expected_key):
                    return paramiko.AUTH_FAILED

            self.user_id = user.id
            self.username = user.username
            return paramiko.AUTH_SUCCESSFUL

    def check_channel_request(self, kind, chanid):
        if kind == 'session':
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_pty_request(self, channel, term, width, height,
                                  pixelwidth, pixelheight, modes):
        return True

    def check_channel_shell_request(self, channel):
        self.session_event.set()
        return True

    def check_channel_exec_request(self, channel, command):
        # Allow `ssh user@host auth <token>` style invocations.
        try:
            self.exec_command = command.decode('utf-8', errors='replace')
        except Exception:
            self.exec_command = ''
        self.session_event.set()
        return True


def _read_line_from_channel(channel, deadline):
    """Read a single line of input from the channel with simple line editing.

    Returns the line text on success, or None on EOF / Ctrl-C / Ctrl-D /
    timeout. Echoes printable characters and basic backspace.
    """
    buf = bytearray()
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return None
        if not channel.recv_ready():
            time.sleep(0.05)
            if channel.closed or channel.eof_received:
                return None
            continue
        try:
            data = channel.recv(4096)
        except Exception:
            return None
        if not data:
            return None
        for byte in data:
            if byte in (0x0D, 0x0A):  # CR / LF
                channel.send(b'\r\n')
                return bytes(buf).decode('utf-8', errors='ignore').strip()
            if byte in (0x03, 0x04):  # Ctrl-C / Ctrl-D
                channel.send(b'\r\n')
                return None
            if byte in (0x08, 0x7F):  # backspace
                if buf:
                    buf.pop()
                    channel.send(b'\b \b')
                continue
            if 0x20 <= byte < 0x7F and len(buf) < TOKEN_MAX_LEN:
                buf.append(byte)
                channel.send(bytes([byte]))


def _consume_token(token, authenticated_user_id, app, models):
    """Validate + consume a challenge token submitted by an authenticated SSH user.

    Returns (ok: bool, message: str, purpose: str or None).
    """
    Challenge = models['Challenge']
    User = models['User']
    db = models['db']

    with app.app_context():
        challenge = Challenge.query.filter_by(token=token).first()
        if challenge is None:
            return False, 'unknown token. Check the value on the Awaiting page.', None
        if challenge.user_id != authenticated_user_id:
            return False, 'this token belongs to a different user.', None
        if challenge.consumed_at is not None:
            return False, 'token already used.', None
        if challenge.expires_at < datetime.utcnow():
            return False, 'token expired. Restart from the browser.', None
        # Registration must go through the curl auth script (which collects the
        # host key). SSH exec cannot provide the required host data.
        if challenge.purpose == 'register':
            return (False,
                    'registration must be completed via the auth script '
                    '(curl -fsSL "..." | sudo bash), not via SSH exec.',
                    None)

        challenge.consumed_at = datetime.utcnow()
        models['finalize_challenge'](challenge)
        db.session.commit()
        user = db.session.get(User, challenge.user_id)
        return True, (
            f'challenge consumed for {user.username} '
            f'({"register" if challenge.purpose == "register" else "login"}).'
        ), challenge.purpose


def _serve_interactive(channel, server_iface, app, models):
    """Interactive shell mode: print banner, prompt for token, consume."""
    exit_status = 0
    try:
        channel.send(WELCOME_BANNER.format(username=server_iface.username).encode())
        channel.send(b'Token: ')

        deadline = time.monotonic() + SESSION_TIMEOUT
        token = _read_line_from_channel(channel, deadline)

        if token is None:
            channel.send(b'\r\nNo token received. Aborting without changes.\r\n')
            exit_status = 1
            return
        if not token:
            channel.send(b'Empty input. Aborting.\r\n')
            exit_status = 1
            return

        ok, message, _ = _consume_token(token, server_iface.user_id, app, models)
        prefix = 'OK: ' if ok else 'ERROR: '
        suffix = '\r\nSwitch back to your browser tab — it should redirect within a few seconds.\r\n' if ok else '\r\n'
        channel.send(f'\r\n{prefix}{message}{suffix}'.encode())
        exit_status = 0 if ok else 1
    finally:
        _close_channel(channel, exit_status=exit_status)


def _serve_exec(channel, server_iface, app, models):
    """Non-interactive exec mode: 'ssh user@host auth <token>'.

    The exec command must be of the form 'auth <token>'. We log a single line
    of structured output and an exit status — no banner, no prompt.
    """
    cmd = (server_iface.exec_command or '').strip()
    parts = cmd.split(maxsplit=1)
    exit_status = 1
    try:
        verb = parts[0] if parts else ''

        if verb == 'auth':
            if len(parts) != 2:
                channel.send(b'Usage: ssh -p <port> <user>@<host> auth <token>\r\n')
                exit_status = 2
                return
            token = parts[1].strip()
            ok, message, _ = _consume_token(token, server_iface.user_id, app, models)
            if ok:
                channel.send(f'OK: {message}\r\n'.encode())
                exit_status = 0
            else:
                channel.send(f'ERROR: {message}\r\n'.encode())
                exit_status = 1

        elif verb == 'get_cert':
            if len(parts) != 2:
                channel.send(b'Usage: ssh <user>@<host> get_cert <subject>\r\n')
                exit_status = 2
                return
            subject = parts[1].strip()
            get_cert_fn = models.get('get_cert')
            if get_cert_fn is None:
                channel.send(b'ERROR: get_cert not available\r\n')
                exit_status = 1
                return
            cert_data = get_cert_fn(subject)
            if cert_data is None:
                channel.send(f'ERROR: no valid certificate found for {subject!r}\r\n'.encode())
                exit_status = 1
            else:
                channel.sendall(cert_data.encode())
                exit_status = 0

        elif verb == 'add_machine':
            if len(parts) != 2:
                channel.send(b'Usage: ssh <user>@<host> add_machine <base64-json>\r\n')
                exit_status = 2
                return
            try:
                data = _json.loads(base64.b64decode(parts[1]))
            except Exception:
                channel.send(b'ERROR: invalid base64-JSON payload\r\n')
                exit_status = 1
                return
            add_machine_fn = models.get('add_machine')
            if add_machine_fn is None:
                channel.send(b'ERROR: add_machine not available\r\n')
                exit_status = 1
                return
            result = add_machine_fn(server_iface.user_id, data)
            channel.sendall((_json.dumps(result) + '\n').encode())
            exit_status = 0 if result.get('ok') else 1

        else:
            channel.send(b'Usage: ssh <user>@<host> auth <token>\r\n')
            channel.send(b'       ssh <user>@<host> get_cert <subject>\r\n')
            channel.send(b'       ssh <user>@<host> add_machine <base64-json>\r\n')
            exit_status = 2
    finally:
        _close_channel(channel, exit_status=exit_status)


def _close_channel(channel, exit_status=None):
    """Close a channel; optionally set the exit status if not already sent."""
    if exit_status is not None:
        try:
            channel.send_exit_status(exit_status)
        except Exception:
            pass
    try:
        channel.close()
    except Exception:
        pass


def _handle_client(client_sock, addr, app, host_key, models):
    """Handle one TCP connection: SSH transport + auth + session."""
    transport = paramiko.Transport(client_sock)
    transport.add_server_key(host_key)
    server_iface = _SSHAuthServerInterface(app, models)
    try:
        try:
            transport.start_server(server=server_iface)
        except paramiko.SSHException:
            return

        channel = transport.accept(timeout=20)
        if channel is None:
            return

        if not server_iface.session_event.wait(timeout=10):
            try:
                channel.send(b'No session request received. Closing.\r\n')
            finally:
                channel.close()
            return

        if server_iface.exec_command is not None:
            _serve_exec(channel, server_iface, app, models)
        else:
            _serve_interactive(channel, server_iface, app, models)
    finally:
        try:
            transport.close()
        except Exception:
            pass


def start_ssh_auth_server(app, db, models, host='0.0.0.0', port=2222,
                          host_key_path=None, ca_key_path=None,
                          host_principals=None):
    """Bind a listening socket and launch the accept loop in a daemon thread.

    Returns the bound TCP socket so callers can inspect the port (useful for
    tests using port=0).
    """
    if host_key_path is None:
        instance_dir = os.path.dirname(
            (app.config.get('SQLALCHEMY_DATABASE_URI') or '').replace('sqlite:///', '')
        )
        host_key_path = os.path.join(instance_dir or '.', 'ssh_host_key')

    host_key = _ensure_host_key(host_key_path)

    # If the sshadmin CA is configured, sign the host key so clients with the
    # CA pubkey in known_hosts can auto-accept.
    cert_path = _ensure_signed_host_cert(host_key_path, ca_key_path,
                                          host_principals or ['sshadmin', '*'])
    if cert_path:
        try:
            host_key.load_certificate(cert_path)
        except Exception:
            pass

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((host, port))
    sock.listen(64)

    bound_models = dict(models)
    bound_models['db'] = db

    def accept_loop():
        while True:
            try:
                client_sock, addr = sock.accept()
            except OSError:
                return
            t = threading.Thread(
                target=_handle_client,
                args=(client_sock, addr, app, host_key, bound_models),
                daemon=True,
            )
            t.start()

    threading.Thread(target=accept_loop, daemon=True, name='sshadmin-ssh-accept').start()
    return sock
