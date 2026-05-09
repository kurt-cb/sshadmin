#!/bin/sh
# sshadmin_add — Zero-touch machine enrollment and certificate renewal for sshadmin
#
# RUN THIS SCRIPT ON YOUR CURRENT (ALREADY ENROLLED) MACHINE.
# It will reach out to the target machine over SSH on your behalf.
# Do NOT run it on the machine you are trying to enroll.
#
# Commands:
#   sshadmin_add [options] user@host           Enroll a new host
#   sshadmin_add update [options] user@host    Renew the USER cert on an already-enrolled host
#   sshadmin_add updatehost [options] user@host  Renew the HOST cert on an already-enrolled host (needs sudo)
#
# What each command does:
#  add:        Collect/generate keys, enroll host with sshadmin, install host+user certs, configure sshd
#  update:     Check if the user cert on the remote machine is expiring soon; renew if needed
#  updatehost: Check if the host cert is expiring soon; renew if needed (requires sudo on remote)
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
SSHADMIN_USER="${USER}"
VALID_DAYS=365
RENEW_THRESHOLD_DAYS=30

die()  { echo "ERROR: $*" >&2; exit 1; }
info() { echo "[sshadmin_add] $*"; }

usage() {
    cat <<EOF
sshadmin_add — manage SSH certificates via sshadmin.
Run on your CURRENT (enrolled) machine to operate on a remote machine.

Commands:
  sshadmin_add [options] user@host              Enroll a new host
  sshadmin_add update [options] user@host       Renew expiring user cert on remote
  sshadmin_add updatehost [options] user@host   Renew expiring host cert on remote

Options:
  -u USER    Your sshadmin username (default: \$USER)
  -d DAYS    Certificate validity in days (default: 365)
  -f         Force renewal even if the cert is not near expiry
  -h         Show this help

Examples:
  sshadmin_add alice@newserver.example.com          # enroll newserver
  sshadmin_add update alice@server1.example.com     # renew user cert if expiring within 30d
  sshadmin_add updatehost alice@server1.example.com # renew host cert if expiring within 30d
  sshadmin_add -f update alice@server1.example.com  # force-renew user cert regardless of expiry
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

# build_payload: read raw JSON from stdin, inject valid_days, output as base64
build_payload() {
    if [ "$HAVE_PYTHON" = "1" ]; then
        python3 -c "
import sys, json, base64
d = json.load(sys.stdin)
d['valid_days'] = int('${VALID_DAYS}')
sys.stdout.write(base64.b64encode(json.dumps(d).encode()).decode())
"
    else
        # shellcheck disable=SC2086
        jq -c ". + {valid_days: ${VALID_DAYS}}" | base64 ${_B64_WRAP}
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
    USER_CERT_PATH="\$HOME/.ssh/id_sshadmin-cert.pub"
    DAYS_LEFT=$(_remote_cert_days_left "$USER_CERT_PATH")
    info "User cert days remaining: ${DAYS_LEFT}"
    if [ "$FORCE_RENEW" = "0" ] && [ "$DAYS_LEFT" -gt "$RENEW_THRESHOLD_DAYS" ]; then
        info "User cert is valid for ${DAYS_LEFT} more days (threshold: ${RENEW_THRESHOLD_DAYS}). No renewal needed."
        info "Use -f to force renewal."
        exit 0
    fi
    info "Renewing user cert (remote user: ${REMOTE_USER}, sshadmin user: ${SSHADMIN_USER})..."

    # Collect current user key from remote
    REMOTE_USER_KEY=$(ssh -o BatchMode=yes -o StrictHostKeyChecking=accept-new "$TARGET" \
        "cat \$HOME/.ssh/id_sshadmin.pub 2>/dev/null || echo ''")
    [ -n "$REMOTE_USER_KEY" ] || die "No id_sshadmin.pub found on ${REMOTE_HOST}. Run 'sshadmin_add ${TARGET}' first."

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
    ssh -o BatchMode=yes -o StrictHostKeyChecking=accept-new "$TARGET" sh <<INSTALL
USER_CERT=\$(printf '%s' "${USER_CERT_B64}" | base64 -d)
mkdir -p "\$HOME/.ssh"
chmod 700 "\$HOME/.ssh"
printf '%s\n' "\$USER_CERT" > "\$HOME/.ssh/id_sshadmin-cert.pub"
chmod 644 "\$HOME/.ssh/id_sshadmin-cert.pub"
echo "User cert installed at \$HOME/.ssh/id_sshadmin-cert.pub"
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

# ── Argument parsing ──────────────────────────────────────────────────────────

SUBCOMMAND="add"
FORCE_RENEW=0

# Detect optional subcommand as first non-flag word
if [ $# -gt 0 ]; then
    case "$1" in
        update|updatehost) SUBCOMMAND="$1"; shift ;;
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
    update)     _cmd_update;     exit 0 ;;
    updatehost) _cmd_updatehost; exit 0 ;;
esac

# Fallthrough: add (enroll)
info "Enrolling ${REMOTE_HOST} (remote user: ${REMOTE_USER}, sshadmin user: ${SSHADMIN_USER})"

# ── Step 1: Collect keys from remote machine ──────────────────────────────────

info "Collecting keys from ${REMOTE_HOST}..."

# Run with sh — works on Alpine (busybox ash), Debian, Ubuntu, etc.
# accept-new: auto-accept unknown host keys but reject changed ones (TOFU).
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
    echo "Generating ecdsa-sha2-nistp521 host key (requires sudo)..." >&2
    sudo ssh-keygen -t ecdsa -b 521 -f "$HOST_KEY_FILE" -N "" -C "" -q
    HOST_KEY=$(cat "${HOST_KEY_FILE}.pub")
fi

# ── User key ──────────────────────────────────────────────────────────────────
# sshadmin uses a dedicated key file so it never conflicts with existing user keys.
SSHADMIN_USER_KEY_FILE="$HOME/.ssh/id_sshadmin"
USER_KEY=""

if [ -f "${SSHADMIN_USER_KEY_FILE}.pub" ]; then
    USER_KEY=$(cat "${SSHADMIN_USER_KEY_FILE}.pub")
fi

if [ -z "$USER_KEY" ]; then
    echo "Generating sshadmin ecdsa-sha2-nistp521 user key..." >&2
    mkdir -p "$HOME/.ssh"
    chmod 700 "$HOME/.ssh"
    ssh-keygen -t ecdsa -b 521 -f "$SSHADMIN_USER_KEY_FILE" -N "" -q
    USER_KEY=$(cat "${SSHADMIN_USER_KEY_FILE}.pub")
fi

# ── Emit JSON ─────────────────────────────────────────────────────────────────
FQDN=$(hostname -f 2>/dev/null || hostname)

if command -v python3 >/dev/null 2>&1; then
    python3 - "$HOST_KEY" "$USER_KEY" "$FQDN" "$USER" <<'PYSCRIPT'
import sys, json
host_key, user_key, hostname, user = sys.argv[1:]
print(json.dumps({"hostname": hostname, "host_key": host_key,
                  "user": user, "user_key": user_key}))
PYSCRIPT
elif command -v jq >/dev/null 2>&1; then
    jq -n \
        --arg hostname "$FQDN" \
        --arg host_key "$HOST_KEY" \
        --arg user     "$USER" \
        --arg user_key "$USER_KEY" \
        '{"hostname":$hostname,"host_key":$host_key,"user":$user,"user_key":$user_key}'
else
    # SSH public keys are base64+algorithm — no double-quotes or backslashes,
    # so manual JSON construction is safe here.
    printf '{"hostname":"%s","host_key":"%s","user":"%s","user_key":"%s"}\n' \
        "$FQDN" "$HOST_KEY" "$USER" "$USER_KEY"
fi
GATHER
)

info "Keys collected."

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
    die "sshadmin command failed (exit ${SSH_EXIT}).\nCheck your sshadmin credentials and that the SSH server is reachable on port ${SSHADMIN_SSH_PORT}."
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

# Encode cert data as single-line base64 for safe transport into the heredoc
HOST_CERT_B64=$(printf '%s' "$HOST_CERT" | b64enc)
USER_CERT_B64=$(printf '%s' "$USER_CERT" | b64enc)
CA_PUBKEY_B64=$(printf '%s' "$CA_PUBKEY" | b64enc)

# Unquoted <<INSTALL: local variables (${..._B64}) expand here;
# escaped \$VAR references run on the remote side.
# Run with sh so this works on Alpine (no bash required on remote).
ssh -o BatchMode=yes -o StrictHostKeyChecking=accept-new "$TARGET" sh <<INSTALL
set -e

HOST_CERT=\$(printf '%s' "${HOST_CERT_B64}" | base64 -d)
USER_CERT=\$(printf '%s' "${USER_CERT_B64}" | base64 -d)
CA_PUBKEY=\$(printf '%s' "${CA_PUBKEY_B64}" | base64 -d)

echo "  Installing host certificate..."
printf '%s\n' "\$HOST_CERT" | sudo tee /etc/ssh/ssh_host_sshadmin_ecdsa_key-cert.pub > /dev/null
sudo chmod 644 /etc/ssh/ssh_host_sshadmin_ecdsa_key-cert.pub

echo "  Installing CA public key..."
printf '%s\n' "\$CA_PUBKEY" | sudo tee /etc/ssh/sshadmin_ca.pub > /dev/null
sudo chmod 644 /etc/ssh/sshadmin_ca.pub

echo "  Configuring sshd..."
sudo mkdir -p /etc/ssh/sshd_config.d
printf '%s\n' \
    "# Managed by sshadmin_add — do not edit manually" \
    "HostCertificate /etc/ssh/ssh_host_sshadmin_ecdsa_key-cert.pub" \
    "TrustedUserCAKeys /etc/ssh/sshadmin_ca.pub" \
    | sudo tee /etc/ssh/sshd_config.d/99-sshadmin.conf > /dev/null

echo "  Adding CA to global ssh_known_hosts..."
sudo touch /etc/ssh/ssh_known_hosts
sudo grep -v "sshadmin-ca\$" /etc/ssh/ssh_known_hosts > /tmp/sshadmin_kh.tmp 2>/dev/null || true
printf '@cert-authority * %s sshadmin-ca\n' "\$CA_PUBKEY" >> /tmp/sshadmin_kh.tmp
sudo mv /tmp/sshadmin_kh.tmp /etc/ssh/ssh_known_hosts
sudo chmod 644 /etc/ssh/ssh_known_hosts

echo "  Installing user certificate..."
mkdir -p "\$HOME/.ssh"
chmod 700 "\$HOME/.ssh"
printf '%s\n' "\$USER_CERT" > "\$HOME/.ssh/id_sshadmin-cert.pub"
chmod 644 "\$HOME/.ssh/id_sshadmin-cert.pub"

echo "  Reloading sshd..."
if command -v systemctl >/dev/null 2>&1; then
    sudo systemctl reload sshd 2>/dev/null || sudo systemctl reload ssh 2>/dev/null || true
elif [ -f /var/run/sshd.pid ]; then
    sudo kill -HUP \$(cat /var/run/sshd.pid) 2>/dev/null || true
fi

echo "  Done!"
INSTALL

# ── Step 4: Update local known_hosts ─────────────────────────────────────────

info "Updating local known_hosts..."

ssh-keygen -R "${REMOTE_HOST}" 2>/dev/null || true

LOCAL_KH="${HOME}/.ssh/known_hosts"
touch "$LOCAL_KH"
grep -v "sshadmin-ca$" "$LOCAL_KH" > "${LOCAL_KH}.tmp" 2>/dev/null || true
printf '@cert-authority * %s sshadmin-ca\n' "$CA_PUBKEY" >> "${LOCAL_KH}.tmp"
mv "${LOCAL_KH}.tmp" "$LOCAL_KH"

# ── Done ──────────────────────────────────────────────────────────────────────

info ""
info "Done: ${REMOTE_HOST} enrolled successfully."
info "  Host cert : /etc/ssh/ssh_host_sshadmin_ecdsa_key-cert.pub  (on ${REMOTE_HOST})"
info "  User cert : ~/.ssh/id_sshadmin-cert.pub                   (on ${REMOTE_HOST})"
info "  CA trusted: ${REMOTE_HOST} sshd + your local known_hosts"
info ""
info "  Test: ssh ${REMOTE_USER}@${REMOTE_HOST}"
