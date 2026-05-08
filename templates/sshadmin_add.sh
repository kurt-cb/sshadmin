#!/bin/bash
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
#
# Requirements (on the NEW machine):
#  - sudo (for writing sshd config and generating the host key if needed)
#  - python3 (for JSON handling; nearly always present)

set -euo pipefail

SSHADMIN_HOST="{{ ssh_host }}"
SSHADMIN_SSH_PORT="{{ ssh_port }}"
SSHADMIN_USER="${USER}"
VALID_DAYS=365

die()  { echo "ERROR: $*" >&2; exit 1; }
info() { echo "[sshadmin_add] $*"; }

b64enc() {
    python3 -c "import sys,base64; sys.stdout.write(base64.b64encode(sys.stdin.buffer.read()).decode())"
}

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
  sshadmin_add alice@newserver.example.com   # enroll newserver, log in as alice
  sshadmin_add -u bob alice@10.0.0.100       # enroll 10.0.0.100; bob is the sshadmin account
  sshadmin_add -d 90 deploy@staging.internal # issue 90-day cert
EOF
}

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
if [[ "$TARGET" == *@* ]]; then
    REMOTE_USER="${TARGET%%@*}"
    REMOTE_HOST="${TARGET##*@}"
else
    REMOTE_USER="${USER}"
    REMOTE_HOST="$TARGET"
    TARGET="${USER}@${TARGET}"
fi

info "Enrolling ${REMOTE_HOST} (remote user: ${REMOTE_USER}, sshadmin user: ${SSHADMIN_USER})"

# ── Step 1: Collect keys from remote machine ──────────────────────────────────

info "Collecting keys from ${REMOTE_HOST}..."

REMOTE_JSON=$(ssh "$TARGET" bash <<'GATHER'
set -e

# ── Host key ──────────────────────────────────────────────────────────────────
# sshadmin requires ecdsa-sha2-nistp521; generate it if missing or wrong type
HOST_KEY_FILE="/etc/ssh/ssh_host_ecdsa_key"
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
# Accept ecdsa-sha2-nistp521, ssh-ed25519, or ecdsa-sha2-nistp384; else generate
ALLOWED="ecdsa-sha2-nistp521 ssh-ed25519 ecdsa-sha2-nistp384"
USER_KEY=""

for kf in ~/.ssh/id_ecdsa ~/.ssh/id_ed25519 ~/.ssh/id_ecdsa_384 ~/.ssh/id_rsa; do
    if [ -f "${kf}.pub" ]; then
        ktype=$(awk '{print $1}' < "${kf}.pub")
        if echo "$ALLOWED" | grep -qw "$ktype"; then
            USER_KEY=$(cat "${kf}.pub")
            break
        fi
    fi
done

if [ -z "$USER_KEY" ]; then
    echo "Generating ed25519 user key..." >&2
    ssh-keygen -t ed25519 -f ~/.ssh/id_ed25519 -N "" -q
    USER_KEY=$(cat ~/.ssh/id_ed25519.pub)
fi

# ── Emit JSON via python3 (handles quoting safely) ────────────────────────────
FQDN=$(hostname -f 2>/dev/null || hostname)
python3 - "$HOST_KEY" "$USER_KEY" "$FQDN" "$USER" <<'PYSCRIPT'
import sys, json
host_key, user_key, hostname, user = sys.argv[1:]
print(json.dumps({"hostname": hostname, "host_key": host_key,
                  "user": user, "user_key": user_key}))
PYSCRIPT
GATHER
)

info "Keys collected."

# ── Step 2: Send to sshadmin ──────────────────────────────────────────────────

info "Sending to sshadmin (${SSHADMIN_HOST}:${SSHADMIN_SSH_PORT} as ${SSHADMIN_USER})..."

PAYLOAD=$(printf '%s' "$REMOTE_JSON" | python3 -c "
import sys, json, base64
d = json.load(sys.stdin)
d['valid_days'] = int('${VALID_DAYS}')
sys.stdout.write(base64.b64encode(json.dumps(d).encode()).decode())
")

set +e
RESPONSE=$(ssh -p "${SSHADMIN_SSH_PORT}" "${SSHADMIN_USER}@${SSHADMIN_HOST}" \
    "add_machine ${PAYLOAD}" 2>&1)
SSH_EXIT=$?
set -e

if [ $SSH_EXIT -ne 0 ]; then
    die "sshadmin command failed (exit ${SSH_EXIT}). Check your sshadmin credentials and that the SSH server is reachable."
fi

OK=$(printf '%s' "$RESPONSE" | python3 -c "import sys,json; print(json.load(sys.stdin).get('ok',''))" 2>/dev/null || echo "")
if [ "$OK" != "True" ]; then
    ERR=$(printf '%s' "$RESPONSE" | python3 -c "import sys,json; print(json.load(sys.stdin).get('error','unknown error'))" 2>/dev/null || echo "$RESPONSE")
    die "sshadmin rejected: $ERR"
fi

info "Enrolled. Extracting certificates..."

HOST_CERT=$(printf '%s' "$RESPONSE" | python3 -c "import sys,json; print(json.load(sys.stdin)['host_cert'])")
USER_CERT=$(printf '%s' "$RESPONSE" | python3 -c "import sys,json; print(json.load(sys.stdin)['user_cert'])")
CA_PUBKEY=$(printf '%s' "$RESPONSE" | python3 -c "import sys,json; print(json.load(sys.stdin)['ca_pubkey'])")

# ── Step 3: Install on remote machine ─────────────────────────────────────────

info "Installing certificates and configuring sshd on ${REMOTE_HOST}..."

# Encode cert data as base64 so we can pass it safely into the heredoc
HOST_CERT_B64=$(printf '%s' "$HOST_CERT" | b64enc)
USER_CERT_B64=$(printf '%s' "$USER_CERT" | b64enc)
CA_PUBKEY_B64=$(printf '%s' "$CA_PUBKEY" | b64enc)

# The unquoted <<INSTALL heredoc expands local variables (${..._B64}) but
# the escaped \$VAR references are evaluated on the remote side.
ssh "$TARGET" bash <<INSTALL
set -e

HOST_CERT=\$(echo "${HOST_CERT_B64}" | base64 -d)
USER_CERT=\$(echo "${USER_CERT_B64}" | base64 -d)
CA_PUBKEY=\$(echo "${CA_PUBKEY_B64}" | base64 -d)

echo "  Installing host certificate..."
printf '%s\n' "\$HOST_CERT" | sudo tee /etc/ssh/ssh_host_ecdsa_key-cert.pub > /dev/null
sudo chmod 644 /etc/ssh/ssh_host_ecdsa_key-cert.pub

echo "  Installing CA public key..."
printf '%s\n' "\$CA_PUBKEY" | sudo tee /etc/ssh/sshadmin_ca.pub > /dev/null
sudo chmod 644 /etc/ssh/sshadmin_ca.pub

echo "  Configuring sshd..."
sudo mkdir -p /etc/ssh/sshd_config.d
cat <<SSHD_CONF | sudo tee /etc/ssh/sshd_config.d/99-sshadmin.conf > /dev/null
# Managed by sshadmin_add — do not edit manually
HostCertificate /etc/ssh/ssh_host_ecdsa_key-cert.pub
TrustedUserCAKeys /etc/ssh/sshadmin_ca.pub
SSHD_CONF

echo "  Adding CA to global ssh_known_hosts (for outbound SSH from this host)..."
sudo touch /etc/ssh/ssh_known_hosts
# Remove any previous sshadmin CA line, then append fresh one
sudo grep -v "sshadmin-ca$" /etc/ssh/ssh_known_hosts > /tmp/ssh_known_hosts.tmp 2>/dev/null || true
printf '@cert-authority * %s sshadmin-ca\n' "\$CA_PUBKEY" >> /tmp/ssh_known_hosts.tmp
sudo mv /tmp/ssh_known_hosts.tmp /etc/ssh/ssh_known_hosts
sudo chmod 644 /etc/ssh/ssh_known_hosts

echo "  Installing user certificate..."
mkdir -p "\$HOME/.ssh"
chmod 700 "\$HOME/.ssh"
printf '%s\n' "\$USER_CERT" > "\$HOME/.ssh/id_ecdsa-cert.pub"
chmod 644 "\$HOME/.ssh/id_ecdsa-cert.pub"

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

# Remove stale raw host key entries for the remote host/IP
ssh-keygen -R "${REMOTE_HOST}" 2>/dev/null || true

# Add/refresh the CA as trusted for all hosts in local known_hosts
LOCAL_KH="${HOME}/.ssh/known_hosts"
touch "$LOCAL_KH"
grep -v "sshadmin-ca$" "$LOCAL_KH" > "${LOCAL_KH}.tmp" 2>/dev/null || true
printf '@cert-authority * %s sshadmin-ca\n' "$CA_PUBKEY" >> "${LOCAL_KH}.tmp"
mv "${LOCAL_KH}.tmp" "$LOCAL_KH"

# ── Done ──────────────────────────────────────────────────────────────────────

info ""
info "✓ ${REMOTE_HOST} enrolled successfully."
info "  Host cert : /etc/ssh/ssh_host_ecdsa_key-cert.pub  (on ${REMOTE_HOST})"
info "  User cert : ~/.ssh/id_ecdsa-cert.pub              (on ${REMOTE_HOST})"
info "  CA trusted: ${REMOTE_HOST} sshd + your local known_hosts"
info ""
info "  Test connection: ssh ${REMOTE_USER}@${REMOTE_HOST}"
