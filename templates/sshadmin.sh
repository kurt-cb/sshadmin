#!/bin/sh
# sshadmin — Zero-touch machine enrollment and certificate renewal for sshadmin
#
# RUN THIS SCRIPT ON YOUR CURRENT (ALREADY ENROLLED) MACHINE.
# It will reach out to the target machine over SSH on your behalf.
# Do NOT run it on the machine you are trying to enroll.
#
# Commands:
#   sshadmin [options] user@host              Enroll a new host
#   sshadmin update [options] user@host        Renew the USER cert on an already-enrolled host
#   sshadmin updatehost [options] user@host    Renew the HOST cert (requires sudo on remote)
#   sshadmin alias [options] user@host         Register current IP/name as alias, re-issue host cert
#   sshadmin update_cert [options] user@host   Re-issue host cert with all stored aliases
#
# What each command does:
#  add:         Collect/generate keys, enroll host with sshadmin, install host+user certs, configure sshd
#  update:      Check if the user cert on the remote machine is expiring soon; renew if needed
#  updatehost:  Check if the host cert is expiring soon; renew if needed (requires sudo on remote)
#  alias:       Add the connection IP/hostname as a registered alias; re-issue cert with new alias
#  update_cert: Re-issue host cert using all currently stored aliases (adds current IP as alias too)
#
# Requirements (on THIS machine):
#  - A registered sshadmin account using the same SSH key as your default identity
#  - SSH access to the target machine
#  - python3 OR jq  (for JSON handling)
#
# Requirements (on the target machine):
#  - sudo (for host-key operations and sshd reload)
#  - python3 OR jq  (for JSON handling)

set -eu

SSHADMIN_HOST="{{ ssh_host }}"
SSHADMIN_SSH_PORT="{{ ssh_port }}"
SSHADMIN_USER="${SUDO_USER:-${USER}}"
VALID_DAYS=365
RENEW_THRESHOLD_DAYS=30

die()  { echo "ERROR: $*" >&2; exit 1; }
info() { echo "[sshadmin] $*"; }

usage() {
    cat <<EOF
sshadmin — manage SSH certificates via sshadmin.
Run on your CURRENT (enrolled) machine to operate on a remote machine.

Commands:
  sshadmin [options] user@host                  Enroll a new host
  sshadmin update [options] user@host           Renew expiring user cert on remote
  sshadmin updatehost [options] user@host       Renew expiring host cert on remote (needs sudo)
  sshadmin alias [options] user@host            Register host's current IP/name as alias, re-issue cert
  sshadmin update_cert [options] user@host      Re-issue host cert with all stored aliases (forced)

Options:
  -u USER    Your sshadmin username (default: \$USER)
  -d DAYS    Certificate validity in days (default: 365)
  -f         Force renewal even if the cert is not near expiry
  -h         Show this help

Examples:
  sshadmin alice@newserver.example.com               # enroll newserver
  sshadmin update alice@server1.example.com          # renew user cert if expiring within 30d
  sshadmin updatehost alice@server1.example.com      # renew host cert if expiring within 30d
  sshadmin alias alice@192.168.1.100                 # add 192.168.1.100 as alias, re-issue cert
  sshadmin update_cert alice@server1.example.com     # re-issue cert with all stored aliases
  sshadmin -f update alice@server1.example.com       # force-renew user cert regardless of expiry
EOF
}

# ── Dependency checks ─────────────────────────────────────────────────────────

HAVE_BASH=0;   command -v bash   >/dev/null 2>&1 && HAVE_BASH=1
HAVE_PYTHON=0; command -v python3 >/dev/null 2>&1 && HAVE_PYTHON=1
HAVE_JQ=0;     command -v jq     >/dev/null 2>&1 && HAVE_JQ=1

if [ "$HAVE_PYTHON" = "0" ] && [ "$HAVE_JQ" = "0" ]; then
    die "python3 or jq is required for JSON handling.\nInstall one (e.g. 'apk add python3' or 'apk add jq') and retry."
fi

# Detect base64 wrapping: GNU coreutils needs -w0; busybox base64 never wraps
_B64_WRAP=""
if echo x | base64 -w0 >/dev/null 2>&1; then
    _B64_WRAP="-w0"
fi

# ── JSON helpers (python3 preferred; jq fallback) ─────────────────────────────

# b64enc: encode stdin as single-line base64
b64enc() {
    if [ "$HAVE_PYTHON" = "1" ]; then
        python3 -c "import sys,base64; sys.stdout.write(base64.b64encode(sys.stdin.buffer.read()).decode())"
    else
        # shellcheck disable=SC2086
        base64 ${_B64_WRAP}
    fi
}

# json_get FIELD: extract a string field from JSON on stdin
json_get() {
    _field="$1"
    if [ "$HAVE_PYTHON" = "1" ]; then
        python3 -c "import sys,json; print(json.load(sys.stdin).get('$_field') or '')"
    else
        jq -r ".$_field // empty"
    fi
}

# build_payload: read raw JSON from stdin, inject valid_days + connect_host, output as base64.
# connect_host is added so the server can include the connection address (IP or hostname
# the user typed) as an extra principal in the host cert — without it, the cert only has
# the remote's self-reported hostname and will fail verification when connecting by IP.
build_payload() {
    if [ "$HAVE_PYTHON" = "1" ]; then
        python3 -c "
import sys, json, base64
d = json.load(sys.stdin)
d['valid_days'] = int('${VALID_DAYS}')
d['connect_host'] = '${REMOTE_HOST}'
sys.stdout.write(base64.b64encode(json.dumps(d).encode()).decode())
"
    else
        # shellcheck disable=SC2086
        jq -c ". + {valid_days: ${VALID_DAYS}, connect_host: \"${REMOTE_HOST}\"}" | base64 ${_B64_WRAP}
    fi
}

# ── Update subcommands ────────────────────────────────────────────────────────

# Check remaining validity of a cert file on the remote machine (in days).
# Prints the number of remaining days, or -1 if the file is missing/unreadable.
_remote_cert_days_left() {
    local cert_path="$1"
    ssh -o BatchMode=yes -o StrictHostKeyChecking=accept-new "$TARGET" sh <<CHKEXP
if [ ! -f "$cert_path" ]; then
    echo -1
    exit 0
fi
if command -v python3 >/dev/null 2>&1; then
    python3 - "$cert_path" <<'PY'
import sys, subprocess, datetime, re
out = subprocess.check_output(['ssh-keygen', '-L', '-f', sys.argv[1]], text=True)
m = re.search(r'Valid:.*?to\s+(\d{4}-\d{2}-\d{2})', out)
if not m:
    print(-1)
else:
    exp = datetime.datetime.strptime(m.group(1), '%Y-%m-%d').date()
    print(max(0, (exp - datetime.date.today()).days))
PY
elif command -v ssh-keygen >/dev/null 2>&1; then
    # Fallback: parse via awk (less accurate — date only, no time)
    exp_line=\$(ssh-keygen -L -f "$cert_path" 2>/dev/null | awk '/Valid:/{print \$NF}')
    if [ -z "\$exp_line" ]; then echo -1; exit 0; fi
    # exp_line format: 2025-12-31T00:00:00 or 2025-12-31
    exp_date=\$(echo "\$exp_line" | cut -c1-10)
    today=\$(date +%Y-%m-%d)
    # Date arithmetic via python3 or simple comparison
    echo 0  # conservative: report 0 so renewal is attempted
else
    echo -1
fi
CHKEXP
}

_cmd_update() {
    info "Checking user cert on ${REMOTE_HOST}..."

    # Find the user key file (and thus the cert file path) on the remote machine.
    # Uses the same search order as the enroll GATHER step.
    REMOTE_KEY_INFO=$(ssh -o BatchMode=yes -o StrictHostKeyChecking=accept-new "$TARGET" sh <<'FINDKEY'
USER_KEY=""
USER_KEY_FILE="$HOME/.ssh/id_sshadmin"

for _candidate in \
    "$HOME/.ssh/id_sshadmin.pub" \
    "$HOME/.ssh/id_sshadmin_ecdsa_521.pub" \
    "$HOME/.ssh/id_sshadmin_ed25519.pub"; do
    if [ -f "$_candidate" ]; then
        _kt=$(awk '{print $1}' < "$_candidate")
        case "$_kt" in
            ecdsa-sha2-nistp521|ecdsa-sha2-nistp384|ssh-ed25519)
                USER_KEY=$(cat "$_candidate")
                USER_KEY_FILE="${_candidate%.pub}"
                break ;;
        esac
    fi
done

if [ -z "$USER_KEY" ] && [ -d "$HOME/.ssh" ]; then
    for _pub in "$HOME"/.ssh/*.pub; do
        [ -f "$_pub" ] || continue
        case "$_pub" in *-cert.pub) continue ;; esac
        _kt=$(awk '{print $1}' < "$_pub")
        case "$_kt" in
            ecdsa-sha2-nistp521|ecdsa-sha2-nistp384|ssh-ed25519)
                USER_KEY=$(cat "$_pub")
                USER_KEY_FILE="${_pub%.pub}"
                break ;;
        esac
    done
fi

if command -v python3 >/dev/null 2>&1; then
    python3 - "$USER_KEY" "$USER_KEY_FILE" <<'PYSCRIPT'
import sys, json
user_key, user_key_file = sys.argv[1:]
print(json.dumps({"user_key": user_key, "user_key_file": user_key_file}))
PYSCRIPT
else
    printf '{"user_key":"%s","user_key_file":"%s"}\n' "$USER_KEY" "$USER_KEY_FILE"
fi
FINDKEY
)

    REMOTE_USER_KEY=$(printf '%s' "$REMOTE_KEY_INFO" | json_get user_key)
    REMOTE_USER_KEY_FILE=$(printf '%s' "$REMOTE_KEY_INFO" | json_get user_key_file)
    [ -n "$REMOTE_USER_KEY" ] || die "No suitable SSH key found on ${REMOTE_HOST}. Run 'sshadmin ${TARGET}' first."

    USER_CERT_PATH="${REMOTE_USER_KEY_FILE}-cert.pub"
    DAYS_LEFT=$(_remote_cert_days_left "$USER_CERT_PATH")
    info "User cert days remaining: ${DAYS_LEFT} (${REMOTE_USER_KEY_FILE##*/}-cert.pub)"
    if [ "$FORCE_RENEW" = "0" ] && [ "$DAYS_LEFT" -gt "$RENEW_THRESHOLD_DAYS" ]; then
        info "User cert is valid for ${DAYS_LEFT} more days (threshold: ${RENEW_THRESHOLD_DAYS}). No renewal needed."
        info "Use -f to force renewal."
        exit 0
    fi
    info "Renewing user cert (remote user: ${REMOTE_USER}, sshadmin user: ${SSHADMIN_USER})..."

    PAYLOAD=$(printf '{"user":"%s","user_key":"%s","valid_days":%s}' \
        "$REMOTE_USER" "$REMOTE_USER_KEY" "$VALID_DAYS" | b64enc)

    set +e
    RESPONSE=$(ssh -o BatchMode=yes -o StrictHostKeyChecking=accept-new \
        -p "${SSHADMIN_SSH_PORT}" "${SSHADMIN_USER}@${SSHADMIN_HOST}" \
        "renew_user_cert ${PAYLOAD}" 2>&1)
    SSH_EXIT=$?
    set -e
    [ "$SSH_EXIT" = "0" ] || die "sshadmin renewal failed (exit ${SSH_EXIT}): ${RESPONSE}"

    USER_CERT=$(printf '%s' "$RESPONSE" | json_get user_cert)
    [ -n "$USER_CERT" ] || die "sshadmin returned no user_cert: ${RESPONSE}"

    USER_CERT_B64=$(printf '%s' "$USER_CERT" | b64enc)
    REMOTE_KEY_FILE_B64=$(printf '%s' "$REMOTE_USER_KEY_FILE" | b64enc)
    ssh -o BatchMode=yes -o StrictHostKeyChecking=accept-new "$TARGET" sh <<INSTALL
USER_CERT=\$(printf '%s' "${USER_CERT_B64}" | base64 -d)
USER_KEY_FILE=\$(printf '%s' "${REMOTE_KEY_FILE_B64}" | base64 -d)
mkdir -p "\$HOME/.ssh"
chmod 700 "\$HOME/.ssh"
CERT_FILE="\${USER_KEY_FILE}-cert.pub"
printf '%s\n' "\$USER_CERT" > "\$CERT_FILE"
chmod 644 "\$CERT_FILE"
echo "User cert installed at \$CERT_FILE"
INSTALL

    info "User cert renewed on ${REMOTE_HOST}."
}

_cmd_updatehost() {
    info "Checking host cert on ${REMOTE_HOST}..."
    HOST_CERT_PATH="/etc/ssh/ssh_host_sshadmin_ecdsa_key-cert.pub"
    DAYS_LEFT=$(_remote_cert_days_left "$HOST_CERT_PATH")
    info "Host cert days remaining: ${DAYS_LEFT}"
    if [ "$FORCE_RENEW" = "0" ] && [ "$DAYS_LEFT" -gt "$RENEW_THRESHOLD_DAYS" ]; then
        info "Host cert is valid for ${DAYS_LEFT} more days (threshold: ${RENEW_THRESHOLD_DAYS}). No renewal needed."
        info "Use -f to force renewal."
        exit 0
    fi
    info "Renewing host cert for ${REMOTE_HOST} (sshadmin user: ${SSHADMIN_USER})..."

    HOST_KEY=$(ssh -o BatchMode=yes -o StrictHostKeyChecking=accept-new "$TARGET" \
        "sudo cat ${HOST_CERT_PATH%%-cert.pub}.pub 2>/dev/null || echo ''")
    [ -n "$HOST_KEY" ] || die "No host key found at ${HOST_CERT_PATH%%-cert.pub}.pub on ${REMOTE_HOST}."

    FQDN=$(ssh -o BatchMode=yes -o StrictHostKeyChecking=accept-new "$TARGET" \
        "hostname -f 2>/dev/null || hostname")

    PAYLOAD=$(printf '{"hostname":"%s","host_key":"%s","valid_days":%s}' \
        "$FQDN" "$HOST_KEY" "$VALID_DAYS" | b64enc)

    set +e
    RESPONSE=$(ssh -o BatchMode=yes -o StrictHostKeyChecking=accept-new \
        -p "${SSHADMIN_SSH_PORT}" "${SSHADMIN_USER}@${SSHADMIN_HOST}" \
        "renew_host_cert ${PAYLOAD}" 2>&1)
    SSH_EXIT=$?
    set -e
    [ "$SSH_EXIT" = "0" ] || die "sshadmin host renewal failed (exit ${SSH_EXIT}): ${RESPONSE}"

    HOST_CERT=$(printf '%s' "$RESPONSE" | json_get host_cert)
    [ -n "$HOST_CERT" ] || die "sshadmin returned no host_cert: ${RESPONSE}"

    HOST_CERT_B64=$(printf '%s' "$HOST_CERT" | b64enc)
    ssh -o BatchMode=yes -o StrictHostKeyChecking=accept-new "$TARGET" sh <<INSTALL
HOST_CERT=\$(printf '%s' "${HOST_CERT_B64}" | base64 -d)
printf '%s\n' "\$HOST_CERT" | sudo tee ${HOST_CERT_PATH} > /dev/null
sudo chmod 644 ${HOST_CERT_PATH}
echo "Host cert installed at ${HOST_CERT_PATH}"
if command -v systemctl >/dev/null 2>&1; then
    sudo systemctl reload sshd 2>/dev/null || sudo systemctl reload ssh 2>/dev/null || true
fi
echo "sshd reloaded."
INSTALL

    info "Host cert renewed and sshd reloaded on ${REMOTE_HOST}."
}

# ── alias subcommand ─────────────────────────────────────────────────────────
# Adds REMOTE_HOST as an alias for the host (stored server-side) and re-issues
# the host cert so the new alias is included in the principals (strict mode).
# In non-strict mode the alias is stored but the cert remains a wildcard.

_cmd_alias() {
    info "Registering alias '${REMOTE_HOST}' for host on sshadmin (${SSHADMIN_USER}@${SSHADMIN_HOST})..."

    HOST_KEY=$(ssh -o BatchMode=yes -o StrictHostKeyChecking=accept-new "$TARGET" \
        "cat /etc/ssh/ssh_host_sshadmin_ecdsa_key.pub 2>/dev/null || echo ''")
    [ -n "$HOST_KEY" ] || die "No sshadmin host key at /etc/ssh/ssh_host_sshadmin_ecdsa_key.pub on ${REMOTE_HOST}. Run 'sshadmin ${TARGET}' first."

    FQDN=$(ssh -o BatchMode=yes -o StrictHostKeyChecking=accept-new "$TARGET" \
        "hostname -f 2>/dev/null || hostname")

    PAYLOAD=$(printf '{"hostname":"%s","host_key":"%s","alias":"%s","valid_days":%s}' \
        "$FQDN" "$HOST_KEY" "$REMOTE_HOST" "$VALID_DAYS" | b64enc)

    set +e
    RESPONSE=$(ssh -o BatchMode=yes -o StrictHostKeyChecking=accept-new \
        -p "${SSHADMIN_SSH_PORT}" "${SSHADMIN_USER}@${SSHADMIN_HOST}" \
        "add_alias ${PAYLOAD}" 2>&1)
    SSH_EXIT=$?
    set -e

    if [ "$SSH_EXIT" != "0" ]; then
        ERR=$(printf '%s' "$RESPONSE" | json_get error 2>/dev/null) || ERR=""
        [ -n "$ERR" ] && die "sshadmin rejected: ${ERR}"
        die "sshadmin command failed (exit ${SSH_EXIT}): ${RESPONSE}"
    fi

    OK=$(printf '%s' "$RESPONSE" | json_get ok)
    [ "$OK" = "True" ] || die "sshadmin returned error: $(printf '%s' "$RESPONSE" | json_get error)"

    HOST_CERT=$(printf '%s' "$RESPONSE" | json_get host_cert)
    [ -n "$HOST_CERT" ] || die "sshadmin returned no host_cert: ${RESPONSE}"

    ALIASES=$(printf '%s' "$RESPONSE" | json_get aliases 2>/dev/null || echo "")
    info "Alias registered. Stored aliases: ${ALIASES:-$REMOTE_HOST}"

    HOST_CERT_B64=$(printf '%s' "$HOST_CERT" | b64enc)
    ssh -o BatchMode=yes -o StrictHostKeyChecking=accept-new "$TARGET" sh <<INSTCERT
HOST_CERT=\$(printf '%s' "${HOST_CERT_B64}" | base64 -d)
TARGET_CERT=/etc/ssh/ssh_host_sshadmin_ecdsa_key-cert.pub
_have_priv=0
if [ "\$(id -u)" = "0" ]; then _have_priv=1; _priv() { "\$@"; }
elif command -v sudo >/dev/null 2>&1 && sudo -n true 2>/dev/null; then _have_priv=1; _priv() { sudo "\$@"; }
fi
if [ "\$_have_priv" = "1" ]; then
    printf '%s\n' "\$HOST_CERT" | _priv tee "\$TARGET_CERT" > /dev/null
    _priv chmod 644 "\$TARGET_CERT"
    if command -v systemctl >/dev/null 2>&1 && _priv systemctl is-active --quiet sshd 2>/dev/null; then
        _priv systemctl reload sshd 2>/dev/null || true
    elif command -v systemctl >/dev/null 2>&1 && _priv systemctl is-active --quiet ssh 2>/dev/null; then
        _priv systemctl reload ssh 2>/dev/null || true
    elif command -v rc-service >/dev/null 2>&1; then
        _priv rc-service sshd reload 2>/dev/null || _priv rc-service sshd restart 2>/dev/null || true
    fi
    echo "  Host cert updated at \$TARGET_CERT"
else
    printf '%s\n' "\$HOST_CERT" > "\$HOME/.sshadmin_host_cert.pub"
    echo "  Staged new host cert at \$HOME/.sshadmin_host_cert.pub"
    echo "  Install as root: cp \$HOME/.sshadmin_host_cert.pub \$TARGET_CERT && rc-service sshd reload"
fi
INSTCERT

    info "Done. Alias '${REMOTE_HOST}' added for ${FQDN}."
}

# ── update_cert subcommand ───────────────────────────────────────────────────
# Re-issues the host cert using all currently stored aliases. In strict mode
# the cert will include all registered principals; in non-strict it remains a
# wildcard. Optionally adds REMOTE_HOST as a new alias first.

_cmd_update_cert() {
    info "Updating host cert for ${REMOTE_HOST} with all registered aliases..."

    HOST_KEY=$(ssh -o BatchMode=yes -o StrictHostKeyChecking=accept-new "$TARGET" \
        "cat /etc/ssh/ssh_host_sshadmin_ecdsa_key.pub 2>/dev/null || echo ''")
    [ -n "$HOST_KEY" ] || die "No sshadmin host key on ${REMOTE_HOST}. Run 'sshadmin ${TARGET}' first."

    FQDN=$(ssh -o BatchMode=yes -o StrictHostKeyChecking=accept-new "$TARGET" \
        "hostname -f 2>/dev/null || hostname")

    # Also register REMOTE_HOST as alias if it differs from FQDN.
    if [ "$REMOTE_HOST" != "$FQDN" ]; then
        info "  Adding ${REMOTE_HOST} as alias for ${FQDN}..."
        ALIAS_PAYLOAD=$(printf '{"hostname":"%s","host_key":"%s","alias":"%s","valid_days":%s}' \
            "$FQDN" "$HOST_KEY" "$REMOTE_HOST" "$VALID_DAYS" | b64enc)
        set +e
        ALIAS_RESP=$(ssh -o BatchMode=yes -o StrictHostKeyChecking=accept-new \
            -p "${SSHADMIN_SSH_PORT}" "${SSHADMIN_USER}@${SSHADMIN_HOST}" \
            "add_alias ${ALIAS_PAYLOAD}" 2>&1)
        ALIAS_EXIT=$?
        set -e
        if [ "$ALIAS_EXIT" = "0" ]; then
            ALIASES=$(printf '%s' "$ALIAS_RESP" | json_get aliases 2>/dev/null || echo "")
            info "  Stored aliases: ${ALIASES}"
        fi
    fi

    PAYLOAD=$(printf '{"hostname":"%s","host_key":"%s","valid_days":%s}' \
        "$FQDN" "$HOST_KEY" "$VALID_DAYS" | b64enc)

    set +e
    RESPONSE=$(ssh -o BatchMode=yes -o StrictHostKeyChecking=accept-new \
        -p "${SSHADMIN_SSH_PORT}" "${SSHADMIN_USER}@${SSHADMIN_HOST}" \
        "renew_host_cert ${PAYLOAD}" 2>&1)
    SSH_EXIT=$?
    set -e

    if [ "$SSH_EXIT" != "0" ]; then
        ERR=$(printf '%s' "$RESPONSE" | json_get error 2>/dev/null) || ERR=""
        [ -n "$ERR" ] && die "sshadmin rejected: ${ERR}"
        die "sshadmin command failed (exit ${SSH_EXIT}): ${RESPONSE}"
    fi

    HOST_CERT=$(printf '%s' "$RESPONSE" | json_get host_cert)
    [ -n "$HOST_CERT" ] || die "sshadmin returned no host_cert: ${RESPONSE}"

    HOST_CERT_B64=$(printf '%s' "$HOST_CERT" | b64enc)
    ssh -o BatchMode=yes -o StrictHostKeyChecking=accept-new "$TARGET" sh <<INSTCERT
HOST_CERT=\$(printf '%s' "${HOST_CERT_B64}" | base64 -d)
TARGET_CERT=/etc/ssh/ssh_host_sshadmin_ecdsa_key-cert.pub
_have_priv=0
if [ "\$(id -u)" = "0" ]; then _have_priv=1; _priv() { "\$@"; }
elif command -v sudo >/dev/null 2>&1 && sudo -n true 2>/dev/null; then _have_priv=1; _priv() { sudo "\$@"; }
fi
if [ "\$_have_priv" = "1" ]; then
    printf '%s\n' "\$HOST_CERT" | _priv tee "\$TARGET_CERT" > /dev/null
    _priv chmod 644 "\$TARGET_CERT"
    if command -v systemctl >/dev/null 2>&1 && _priv systemctl is-active --quiet sshd 2>/dev/null; then
        _priv systemctl reload sshd 2>/dev/null || true
    elif command -v systemctl >/dev/null 2>&1 && _priv systemctl is-active --quiet ssh 2>/dev/null; then
        _priv systemctl reload ssh 2>/dev/null || true
    elif command -v rc-service >/dev/null 2>&1; then
        _priv rc-service sshd reload 2>/dev/null || _priv rc-service sshd restart 2>/dev/null || true
    fi
    echo "  Host cert updated at \$TARGET_CERT"
else
    printf '%s\n' "\$HOST_CERT" > "\$HOME/.sshadmin_host_cert.pub"
    echo "  Staged at \$HOME/.sshadmin_host_cert.pub — install as root to complete update."
fi
INSTCERT

    info "Host cert updated on ${REMOTE_HOST}."
}

# ── Argument parsing ──────────────────────────────────────────────────────────

SUBCOMMAND="add"
FORCE_RENEW=0

# Detect optional subcommand as first non-flag word
if [ $# -gt 0 ]; then
    case "$1" in
        update|updatehost|alias|update_cert) SUBCOMMAND="$1"; shift ;;
    esac
fi

while getopts "u:d:fh" opt; do
    case "$opt" in
        u) SSHADMIN_USER="$OPTARG" ;;
        d) VALID_DAYS="$OPTARG" ;;
        f) FORCE_RENEW=1 ;;
        h) usage; exit 0 ;;
        *) usage >&2; exit 1 ;;
    esac
done
shift $((OPTIND - 1))
[ $# -eq 1 ] || { usage >&2; exit 1; }

TARGET="$1"
case "$TARGET" in
    *@*)
        REMOTE_USER="${TARGET%%@*}"
        REMOTE_HOST="${TARGET##*@}"
        ;;
    *)
        REMOTE_USER="${USER}"
        REMOTE_HOST="$TARGET"
        TARGET="${USER}@${TARGET}"
        ;;
esac

# ── Dispatch ──────────────────────────────────────────────────────────────────

case "$SUBCOMMAND" in
    update)      _cmd_update;      exit 0 ;;
    updatehost)  _cmd_updatehost;  exit 0 ;;
    alias)       _cmd_alias;       exit 0 ;;
    update_cert) _cmd_update_cert; exit 0 ;;
esac

# Fallthrough: add (enroll)
info "Enrolling ${REMOTE_HOST} (remote user: ${REMOTE_USER}, sshadmin user: ${SSHADMIN_USER})"

# ── Step 1: Collect keys from remote machine ──────────────────────────────────

info "Collecting keys from ${REMOTE_HOST}..."

# Remove any stale known_hosts entry for this host before connecting.
# This prevents "REMOTE HOST IDENTIFICATION HAS CHANGED" errors when the host
# key has changed or the host now presents a CA-signed certificate.
# Once enrollment completes, the @cert-authority line we write to known_hosts
# will authenticate the host without needing a per-host entry.
ssh-keygen -R "${REMOTE_HOST}" 2>/dev/null || true

# Run with sh — works on Alpine (busybox ash), Debian, Ubuntu, etc.
# accept-new: auto-accept unknown host keys (stale entry cleared above).
# BatchMode: fail fast instead of hanging on a passphrase prompt.
REMOTE_JSON=$(ssh -o BatchMode=yes -o StrictHostKeyChecking=accept-new "$TARGET" sh <<'GATHER'
set -e

# ── Host key ──────────────────────────────────────────────────────────────────
# sshadmin uses a dedicated key file so it never conflicts with existing host keys.
HOST_KEY_FILE="/etc/ssh/ssh_host_sshadmin_ecdsa_key"
HOST_KEY=""

if [ -f "${HOST_KEY_FILE}.pub" ]; then
    ktype=$(awk '{print $1}' < "${HOST_KEY_FILE}.pub")
    [ "$ktype" = "ecdsa-sha2-nistp521" ] && HOST_KEY=$(cat "${HOST_KEY_FILE}.pub")
fi

if [ -z "$HOST_KEY" ]; then
    echo "Attempting to generate ecdsa-sha2-nistp521 host key (needs NOPASSWD sudo)..." >&2
    # sudo -n: non-interactive — succeeds only if the user has NOPASSWD for this.
    # If it fails (password required) we skip host enrollment rather than aborting.
    if sudo -n ssh-keygen -t ecdsa -b 521 -f "$HOST_KEY_FILE" -N "" -C "" -q 2>/dev/null; then
        HOST_KEY=$(cat "${HOST_KEY_FILE}.pub")
    else
        echo "Note: sudo requires a password — skipping host key generation." >&2
        echo "      To enroll this host, run the enrollment script from the sshadmin" >&2
        echo "      web UI as root, or configure NOPASSWD sudo for ssh-keygen." >&2
    fi
fi

# ── User key ──────────────────────────────────────────────────────────────────
# Look for an existing suitable key before generating a new one.
# Search order: id_sshadmin (preferred), legacy names, then any P-521/Ed25519 key.
USER_KEY=""
SSHADMIN_USER_KEY_FILE="$HOME/.ssh/id_sshadmin"

for _candidate in \
    "$HOME/.ssh/id_sshadmin.pub" \
    "$HOME/.ssh/id_sshadmin_ecdsa_521.pub" \
    "$HOME/.ssh/id_sshadmin_ed25519.pub"; do
    if [ -f "$_candidate" ]; then
        _kt=$(awk '{print $1}' < "$_candidate")
        case "$_kt" in
            ecdsa-sha2-nistp521|ecdsa-sha2-nistp384|ssh-ed25519)
                USER_KEY=$(cat "$_candidate")
                SSHADMIN_USER_KEY_FILE="${_candidate%.pub}"
                break ;;
        esac
    fi
done

# Fallback: scan all .pub files for any accepted type
if [ -z "$USER_KEY" ] && [ -d "$HOME/.ssh" ]; then
    for _pub in "$HOME"/.ssh/*.pub; do
        [ -f "$_pub" ] || continue
        _kt=$(awk '{print $1}' < "$_pub")
        case "$_kt" in
            ecdsa-sha2-nistp521|ecdsa-sha2-nistp384|ssh-ed25519)
                USER_KEY=$(cat "$_pub")
                SSHADMIN_USER_KEY_FILE="${_pub%.pub}"
                echo "Found existing suitable key: $_pub" >&2
                break ;;
        esac
    done
fi

if [ -z "$USER_KEY" ]; then
    echo "Generating sshadmin ecdsa-sha2-nistp521 user key at $HOME/.ssh/id_sshadmin..." >&2
    mkdir -p "$HOME/.ssh"
    chmod 700 "$HOME/.ssh"
    ssh-keygen -t ecdsa -b 521 -f "$HOME/.ssh/id_sshadmin" -N "" -q
    USER_KEY=$(cat "$HOME/.ssh/id_sshadmin.pub")
    SSHADMIN_USER_KEY_FILE="$HOME/.ssh/id_sshadmin"
fi

# ── Emit JSON ─────────────────────────────────────────────────────────────────
FQDN=$(hostname -f 2>/dev/null || hostname)

if command -v python3 >/dev/null 2>&1; then
    python3 - "$HOST_KEY" "$USER_KEY" "$FQDN" "$USER" "$SSHADMIN_USER_KEY_FILE" <<'PYSCRIPT'
import sys, json
host_key, user_key, hostname, user, user_key_file = sys.argv[1:]
d = {"hostname": hostname, "user": user, "user_key": user_key, "user_key_file": user_key_file}
if host_key:
    d["host_key"] = host_key
print(json.dumps(d))
PYSCRIPT
elif command -v jq >/dev/null 2>&1; then
    if [ -n "$HOST_KEY" ]; then
        jq -n --arg hostname "$FQDN" --arg host_key "$HOST_KEY" \
               --arg user "$USER" --arg user_key "$USER_KEY" \
               --arg user_key_file "$SSHADMIN_USER_KEY_FILE" \
            '{"hostname":$hostname,"host_key":$host_key,"user":$user,"user_key":$user_key,"user_key_file":$user_key_file}'
    else
        jq -n --arg hostname "$FQDN" --arg user "$USER" --arg user_key "$USER_KEY" \
               --arg user_key_file "$SSHADMIN_USER_KEY_FILE" \
            '{"hostname":$hostname,"user":$user,"user_key":$user_key,"user_key_file":$user_key_file}'
    fi
else
    if [ -n "$HOST_KEY" ]; then
        printf '{"hostname":"%s","host_key":"%s","user":"%s","user_key":"%s","user_key_file":"%s"}\n' \
            "$FQDN" "$HOST_KEY" "$USER" "$USER_KEY" "$SSHADMIN_USER_KEY_FILE"
    else
        printf '{"hostname":"%s","user":"%s","user_key":"%s","user_key_file":"%s"}\n' \
            "$FQDN" "$USER" "$USER_KEY" "$SSHADMIN_USER_KEY_FILE"
    fi
fi
GATHER
)

info "Keys collected."

# Extract the user key file path so the INSTALL step puts the cert in the right place.
USER_KEY_FILE=$(printf '%s' "$REMOTE_JSON" | json_get user_key_file)

# ── Step 2: Send to sshadmin ──────────────────────────────────────────────────

info "Sending to sshadmin (${SSHADMIN_HOST}:${SSHADMIN_SSH_PORT} as ${SSHADMIN_USER})..."

PAYLOAD=$(printf '%s' "$REMOTE_JSON" | build_payload)

set +e
RESPONSE=$(ssh -o BatchMode=yes -o StrictHostKeyChecking=accept-new \
    -p "${SSHADMIN_SSH_PORT}" "${SSHADMIN_USER}@${SSHADMIN_HOST}" \
    "add_machine ${PAYLOAD}" 2>&1)
SSH_EXIT=$?
set -e

if [ "$SSH_EXIT" != "0" ]; then
    # The ssh_auth_server exits 1 on logical errors (host exists, bad key, etc.)
    # and still returns a JSON body. Try to extract the real error before falling
    # back to the generic connection-failure message.
    ERR=$(printf '%s' "$RESPONSE" | json_get error 2>/dev/null) || ERR=""
    if [ -n "$ERR" ]; then
        die "sshadmin rejected: ${ERR}"
    fi
    die "sshadmin command failed (exit ${SSH_EXIT}). Check your sshadmin credentials and that the SSH server is reachable on port ${SSHADMIN_SSH_PORT}."
fi

OK=$(printf '%s' "$RESPONSE" | json_get ok)
if [ "$OK" != "True" ]; then
    ERR=$(printf '%s' "$RESPONSE" | json_get error)
    die "sshadmin rejected: ${ERR:-unknown error}"
fi

info "Enrolled. Extracting certificates..."

HOST_CERT=$(printf '%s' "$RESPONSE" | json_get host_cert)
USER_CERT=$(printf '%s' "$RESPONSE" | json_get user_cert)
CA_PUBKEY=$(printf '%s' "$RESPONSE" | json_get ca_pubkey)

# ── Step 3: Install on remote machine ─────────────────────────────────────────

info "Installing certificates and configuring sshd on ${REMOTE_HOST}..."

# Encode cert data as single-line base64 for safe transport into the heredoc.
# USER_KEY_FILE is the remote path (e.g. /home/alice/.ssh/id_sshadmin_ecdsa_521);
# SSH looks for <keyfile>-cert.pub so the cert must land at that exact path.
HOST_CERT_B64=$(printf '%s' "$HOST_CERT" | b64enc)
USER_CERT_B64=$(printf '%s' "$USER_CERT" | b64enc)
CA_PUBKEY_B64=$(printf '%s' "$CA_PUBKEY" | b64enc)
USER_KEY_FILE_B64=$(printf '%s' "$USER_KEY_FILE" | b64enc)

# Unquoted <<INSTALL: local variables (${..._B64}) expand here;
# escaped \$VAR references run on the remote side.
# Run with sh so this works on Alpine (no bash required on remote).
ssh -o BatchMode=yes -o StrictHostKeyChecking=accept-new "$TARGET" sh <<INSTALL
set -e

HOST_CERT=\$(printf '%s' "${HOST_CERT_B64}" | base64 -d)
USER_CERT=\$(printf '%s' "${USER_CERT_B64}" | base64 -d)
CA_PUBKEY=\$(printf '%s' "${CA_PUBKEY_B64}" | base64 -d)
USER_KEY_FILE=\$(printf '%s' "${USER_KEY_FILE_B64}" | base64 -d)

# Install user cert first — no sudo required; always needed.
echo "  Installing user certificate..."
mkdir -p "\$HOME/.ssh"
chmod 700 "\$HOME/.ssh"
CERT_FILE="\${USER_KEY_FILE}-cert.pub"
printf '%s\n' "\$USER_CERT" > "\$CERT_FILE"
chmod 644 "\$CERT_FILE"
echo "  User cert: \$CERT_FILE"

# Determine if we have privileged access (root or passwordless sudo).
_have_priv=0
if [ "\$(id -u)" = "0" ]; then
    _have_priv=1
    _priv() { "\$@"; }
elif command -v sudo >/dev/null 2>&1 && sudo -n true 2>/dev/null; then
    _have_priv=1
    _priv() { sudo "\$@"; }
fi

if [ "\$_have_priv" = "1" ]; then
    # Install CA public key and configure sshd.
    echo "  Installing CA public key..."
    printf '%s\n' "\$CA_PUBKEY" | _priv tee /etc/ssh/sshadmin_ca.pub > /dev/null
    _priv chmod 644 /etc/ssh/sshadmin_ca.pub

    # Always configure TrustedUserCAKeys so cert-based user auth works.
    # Only add HostCertificate when we actually have a host cert to install.
    echo "  Configuring sshd..."
    _priv mkdir -p /etc/ssh/sshd_config.d
    printf '%s\n' \
        "# Managed by sshadmin — do not edit manually" \
        "TrustedUserCAKeys /etc/ssh/sshadmin_ca.pub" \
        | _priv tee /etc/ssh/sshd_config.d/99-sshadmin.conf > /dev/null
    if [ -n "\$HOST_CERT" ]; then
        printf '%s\n' \
            "HostKey /etc/ssh/ssh_host_sshadmin_ecdsa_key" \
            "HostCertificate /etc/ssh/ssh_host_sshadmin_ecdsa_key-cert.pub" \
            | _priv tee -a /etc/ssh/sshd_config.d/99-sshadmin.conf > /dev/null
        echo "  Installing host certificate..."
        printf '%s\n' "\$HOST_CERT" | _priv tee /etc/ssh/ssh_host_sshadmin_ecdsa_key-cert.pub > /dev/null
        _priv chmod 644 /etc/ssh/ssh_host_sshadmin_ecdsa_key-cert.pub
    fi

    echo "  Adding CA to global ssh_known_hosts..."
    _priv touch /etc/ssh/ssh_known_hosts
    grep -v "sshadmin-ca\$" /etc/ssh/ssh_known_hosts > /tmp/sshadmin_kh.tmp 2>/dev/null || true
    printf '@cert-authority * %s sshadmin-ca\n' "\$CA_PUBKEY" >> /tmp/sshadmin_kh.tmp
    _priv mv /tmp/sshadmin_kh.tmp /etc/ssh/ssh_known_hosts
    _priv chmod 644 /etc/ssh/ssh_known_hosts

    echo "  Reloading sshd..."
    if command -v systemctl >/dev/null 2>&1 && _priv systemctl is-active --quiet sshd 2>/dev/null; then
        _priv systemctl reload sshd 2>/dev/null || true
    elif command -v systemctl >/dev/null 2>&1 && _priv systemctl is-active --quiet ssh 2>/dev/null; then
        _priv systemctl reload ssh 2>/dev/null || true
    elif command -v rc-service >/dev/null 2>&1; then
        _priv rc-service sshd reload 2>/dev/null || _priv rc-service sshd restart 2>/dev/null || true
    elif [ -f /var/run/sshd.pid ]; then
        _priv kill -HUP \$(cat /var/run/sshd.pid) 2>/dev/null || true
    fi
else
    echo ""
    echo "  NOTE: no root or passwordless sudo access — sshd configuration skipped."
    if [ -f /etc/ssh/sshd_config.d/99-sshadmin.conf ]; then
        echo "  sshd already configured for certificate auth (TrustedUserCAKeys present)."
    else
        echo "  To finish host setup, log in as root on \$(hostname) and run the"
        echo "  enrollment script from the sshadmin web UI (Hosts page)."
    fi
    if [ -n "\$HOST_CERT" ]; then
        _STAGED="\$HOME/.sshadmin_host_cert.pub"
        printf '%s\n' "\$HOST_CERT" > "\$_STAGED"
        echo ""
        echo "  A new host certificate has been staged at: \$_STAGED"
        echo "  Install it as root (replaces the old cert and reloads sshd):"
        echo ""
        echo "    cp \$_STAGED /etc/ssh/ssh_host_sshadmin_ecdsa_key-cert.pub"
        echo "    chmod 644 /etc/ssh/ssh_host_sshadmin_ecdsa_key-cert.pub"
        echo "    rc-service sshd reload 2>/dev/null || systemctl reload sshd"
        echo "    rm \$_STAGED"
    fi
    echo ""
fi

echo "  Done!"
INSTALL

# ── Step 4: Update local known_hosts and ~/.ssh/config ───────────────────────

info "Updating local known_hosts..."

# Fetch FQDN first so we can clean up all known name variants in one pass.
LOCAL_FQDN=$(ssh -o BatchMode=yes -o StrictHostKeyChecking=accept-new "$TARGET" \
    "hostname -f 2>/dev/null || hostname" 2>/dev/null || true)

# Remove raw host key entries for all names this host answers to.
# This prevents cert-failure fallback to "do you trust this unknown raw key?".
ssh-keygen -R "${REMOTE_HOST}" 2>/dev/null || true
[ -n "$LOCAL_FQDN" ] && [ "$LOCAL_FQDN" != "$REMOTE_HOST" ] && \
    ssh-keygen -R "${LOCAL_FQDN}" 2>/dev/null || true

LOCAL_KH="${HOME}/.ssh/known_hosts"
touch "$LOCAL_KH"
# Strip any existing sshadmin CA line (idempotent) then add the current one.
grep -v "sshadmin-ca$" "$LOCAL_KH" > "${LOCAL_KH}.tmp" 2>/dev/null || true
printf '@cert-authority * %s sshadmin-ca\n' "$CA_PUBKEY" >> "${LOCAL_KH}.tmp"
mv "${LOCAL_KH}.tmp" "$LOCAL_KH"

SSH_CONFIG="${HOME}/.ssh/config"
touch "$SSH_CONFIG"
chmod 600 "$SSH_CONFIG"

# Build the Host pattern: always include REMOTE_HOST; add FQDN if distinct.
HOST_PATTERN="${REMOTE_HOST}"
if [ -n "$LOCAL_FQDN" ] && [ "$LOCAL_FQDN" != "$REMOTE_HOST" ]; then
    HOST_PATTERN="${LOCAL_FQDN} ${REMOTE_HOST}"
fi

# Use FQDN as the canonical block marker so re-running with IP or FQDN both
# find and replace the same block.  Clean by both names before writing.
BLOCK_MARKER="${LOCAL_FQDN:-$REMOTE_HOST}"

_config_clean() {
    awk -v host="$1" '
        /^# sshadmin:BEGIN / { if ($3 == host) skip=1 }
        !skip { print }
        /^# sshadmin:END /  { if ($3 == host) skip=0 }
    ' "$SSH_CONFIG" > "${SSH_CONFIG}.tmp" && mv "${SSH_CONFIG}.tmp" "$SSH_CONFIG"
}
_config_clean "${BLOCK_MARKER}"
[ "$REMOTE_HOST" != "$BLOCK_MARKER" ] && _config_clean "${REMOTE_HOST}"

cat >> "$SSH_CONFIG" <<SSHCONF
# sshadmin:BEGIN ${BLOCK_MARKER}
Host ${HOST_PATTERN}
    IdentityFile ${USER_KEY_FILE}
    StrictHostKeyChecking yes
# sshadmin:END ${BLOCK_MARKER}
SSHCONF

info "Updated ~/.ssh/config: IdentityFile ${USER_KEY_FILE} for ${HOST_PATTERN}"

# ── Done ──────────────────────────────────────────────────────────────────────

info ""
info "Done: ${REMOTE_HOST} enrolled successfully."
info "  Host cert : /etc/ssh/ssh_host_sshadmin_ecdsa_key-cert.pub  (on ${REMOTE_HOST})"
info "  User cert : ${USER_KEY_FILE}-cert.pub  (on ${REMOTE_HOST})"
info "  CA trusted: ${REMOTE_HOST} sshd + your local known_hosts"
info ""
info "  NOTE: sshd on ${REMOTE_HOST} must be reloaded as root for the host"
info "        certificate to take effect. On Alpine: /etc/init.d/sshd restart"
info "        On systemd: systemctl reload sshd"
info ""
info "  After sshd reload: ssh ${REMOTE_USER}@${REMOTE_HOST}"
