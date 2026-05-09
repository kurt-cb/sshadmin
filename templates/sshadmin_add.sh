#!/bin/sh
# sshadmin_add — Zero-touch machine enrollment for sshadmin
#
# RUN THIS SCRIPT ON YOUR CURRENT (ALREADY ENROLLED) MACHINE.
# It will reach out to the new machine over SSH on your behalf.
# Do NOT run it on the machine you are trying to enroll.
#
# Usage: sshadmin_add [-u sshadmin_user] [-d valid_days] remote_user@remote_host
#
#   remote_user@remote_host  —  the NEW machine you want to enroll
#                               (you must currently have SSH access to it)
#
# What it does:
#  1. SSHs to the NEW machine and collects/generates its host key + your user key
#  2. Sends both to sshadmin (auth via your existing SSH key — no token needed)
#  3. sshadmin enrolls the host, issues host + user certs, and returns them
#  4. Installs the certs on the NEW machine and configures sshd to trust the CA
#  5. Updates your local known_hosts to trust CA-signed host certs
#
# Requirements (on THIS machine):
#  - A registered sshadmin account using the same SSH key as your default identity
#  - SSH access to the new machine (password or existing key — any auth works)
#  - python3 OR jq  (for JSON handling)
#
# Requirements (on the NEW machine):
#  - sudo (for writing sshd config and generating the host key if needed)
#  - python3 OR jq  (for JSON handling; at least one is usually present)

set -eu

SSHADMIN_HOST="{{ ssh_host }}"
SSHADMIN_SSH_PORT="{{ ssh_port }}"
SSHADMIN_USER="${USER}"
VALID_DAYS=365

die()  { echo "ERROR: $*" >&2; exit 1; }
info() { echo "[sshadmin_add] $*"; }

usage() {
    cat <<EOF
sshadmin_add — run on your CURRENT machine to enroll a NEW machine remotely.

Usage: sshadmin_add [-u sshadmin_user] [-d valid_days] remote_user@remote_host

  remote_user@remote_host   The machine you want to add to sshadmin.
                            You need existing SSH access to it (password or key).
                            This script connects to it on your behalf.

Options:
  -u USER    Your sshadmin username (default: \$USER)
  -d DAYS    Certificate validity in days (default: 365)
  -h         Show this help

Examples:
  sshadmin_add alice@newserver.example.com    # enroll newserver, log in as alice
  sshadmin_add -u bob alice@10.0.0.100        # enroll 10.0.0.100; bob is sshadmin account
  sshadmin_add -d 90 deploy@staging.internal  # issue 90-day cert
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

# ── Argument parsing ──────────────────────────────────────────────────────────

while getopts "u:d:h" opt; do
    case "$opt" in
        u) SSHADMIN_USER="$OPTARG" ;;
        d) VALID_DAYS="$OPTARG" ;;
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
