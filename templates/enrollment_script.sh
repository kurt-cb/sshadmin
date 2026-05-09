#!/usr/bin/env bash
# SSH host enrollment for {{ hostname }}
# Run as root on the target host. The token below is one-time-use and expires.
set -euo pipefail

SSHADMIN_URL="{{ server_url }}"
ENROLL_TOKEN="{{ token }}"
KEY_TYPE="{{ key_type }}"
HOST_KEY="/etc/ssh/ssh_host_sshadmin_ecdsa_key"
HOST_PUB="${HOST_KEY}.pub"
CA_PUB="/etc/ssh/sshadmin_ca.pub"
SSHD_CONFIG="/etc/ssh/sshd_config"
SSHD_DROPIN="/etc/ssh/sshd_config.d/99-sshadmin.conf"

if [ "${EUID:-$(id -u)}" -ne 0 ]; then
  echo "ERROR: this script must run as root." >&2
  exit 1
fi

for bin in ssh-keygen curl awk; do
  command -v "$bin" >/dev/null || { echo "ERROR: missing required command: $bin" >&2; exit 1; }
done

# Reads a yes/no answer; falls back to /dev/tty when stdin is not a terminal
# (e.g. when this script is piped from curl).
prompt_yn() {
  local prompt_text="$1"
  local reply=""
  if [ -t 0 ]; then
    read -r -p "$prompt_text" reply
  elif [ -r /dev/tty ]; then
    read -r -p "$prompt_text" reply < /dev/tty
  else
    echo "ERROR: cannot prompt — no controlling TTY. Re-run interactively or set SSHADMIN_FORCE_REKEY=1." >&2
    return 2
  fi
  case "$reply" in
    [yY]|[yY][eE][sS]) return 0 ;;
    *) return 1 ;;
  esac
}

generate_host_key() {
  echo "Generating new $KEY_TYPE host key at $HOST_KEY"
  ssh-keygen -t ecdsa -b 521 -f "$HOST_KEY" -N "" -C "host:{{ hostname }}" >/dev/null
  chmod 600 "$HOST_KEY"
  chmod 644 "$HOST_PUB"
  echo "  created $HOST_KEY"
  echo "  created $HOST_PUB"
}

# Generate ecdsa-sha2-nistp521 host key if absent; if an existing key is the
# wrong type, prompt the user (or honor SSHADMIN_FORCE_REKEY=1) before moving
# it aside.
if [ -f "$HOST_PUB" ]; then
  EXISTING_TYPE="$(awk '{print $1}' "$HOST_PUB")"
  if [ "$EXISTING_TYPE" != "$KEY_TYPE" ]; then
    echo "WARNING: $HOST_PUB exists with key type '$EXISTING_TYPE'; required '$KEY_TYPE'." >&2
    if [ "${SSHADMIN_FORCE_REKEY:-0}" = "1" ]; then
      echo "SSHADMIN_FORCE_REKEY=1 set — proceeding without prompt."
    elif ! prompt_yn "Move the conflicting key aside and generate a new $KEY_TYPE key? [y/N] "; then
      echo "Aborted. Move $HOST_KEY{,.pub} aside manually and re-run this script." >&2
      exit 1
    fi
    BACKUP_SUFFIX=".sshadmin.bak.$(date +%Y%m%d%H%M%S)"
    echo "Moving conflicting files aside (suffix: $BACKUP_SUFFIX):"
    for f in "$HOST_KEY" "$HOST_PUB" "${HOST_KEY}-cert.pub"; do
      if [ -e "$f" ]; then
        mv "$f" "$f$BACKUP_SUFFIX"
        echo "  $f -> $f$BACKUP_SUFFIX"
      fi
    done
    generate_host_key
  else
    echo "Using existing $KEY_TYPE host key at $HOST_PUB"
  fi
else
  generate_host_key
fi

PUBKEY="$(cat "$HOST_PUB")"

# Install CA public key (used so this host trusts user certificates issued by sshadmin).
echo "Fetching CA public key from $SSHADMIN_URL/api/ca-pubkey"
curl -fsSL "$SSHADMIN_URL/api/ca-pubkey" -o "$CA_PUB.tmp"
mv "$CA_PUB.tmp" "$CA_PUB"
chmod 644 "$CA_PUB"

mkdir -p "$(dirname "$SSHD_DROPIN")"
cat > "$SSHD_DROPIN" <<EOF
# Managed by sshadmin enrollment
HostKey ${HOST_KEY}
HostCertificate ${HOST_KEY}-cert.pub
TrustedUserCAKeys $CA_PUB
EOF
chmod 644 "$SSHD_DROPIN"

# Ensure the main sshd_config includes the drop-in directory.
# Modern OpenSSH distro packages add this automatically, but minimal/Alpine
# installs sometimes omit it, causing the drop-in to be silently ignored.
if ! grep -qE '^[[:space:]]*Include[[:space:]].*sshd_config\.d' "$SSHD_CONFIG" 2>/dev/null; then
  echo "Adding 'Include /etc/ssh/sshd_config.d/*.conf' to $SSHD_CONFIG..."
  printf '\n# Added by sshadmin enrollment\nInclude /etc/ssh/sshd_config.d/*.conf\n' >> "$SSHD_CONFIG"
fi

# Register this host's public key with sshadmin.
echo "Registering host with sshadmin..."
RESPONSE="$(curl -fsS -X POST "$SSHADMIN_URL/api/enroll/host" \
  --data-urlencode "token=$ENROLL_TOKEN" \
  --data-urlencode "public_key=$PUBKEY")"

# Extract and install the auto-issued host certificate if the server returned one.
CERT_DATA=""
if command -v python3 >/dev/null 2>&1; then
  CERT_DATA="$(printf '%s' "$RESPONSE" | \
    python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('cert_data') or '')" \
    2>/dev/null || true)"
elif command -v jq >/dev/null 2>&1; then
  CERT_DATA="$(printf '%s' "$RESPONSE" | jq -r '.cert_data // empty' 2>/dev/null || true)"
fi

if [ -n "$CERT_DATA" ]; then
  echo "Installing host certificate..."
  printf '%s\n' "$CERT_DATA" > "${HOST_KEY}-cert.pub"
  chmod 644 "${HOST_KEY}-cert.pub"
  echo "  Certificate installed at ${HOST_KEY}-cert.pub"
else
  echo "NOTE: certificate not yet issued."
  echo "      Go to the sshadmin web UI and issue a host certificate for {{ hostname }},"
  echo "      then install it at ${HOST_KEY}-cert.pub"
fi

# Reload sshd so the new key, drop-in, and certificate take effect.
if command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet ssh 2>/dev/null; then
  systemctl reload ssh
elif command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet sshd 2>/dev/null; then
  systemctl reload sshd
elif command -v rc-service >/dev/null 2>&1; then
  rc-service sshd reload 2>/dev/null || rc-service sshd restart 2>/dev/null || true
elif [ -f /var/run/sshd.pid ]; then
  kill -HUP "$(cat /var/run/sshd.pid)" 2>/dev/null || true
else
  echo "NOTE: reload sshd manually to pick up the new configuration."
  echo "      Alpine/OpenRC: rc-service sshd reload"
  echo "      systemd:       systemctl reload sshd"
fi

echo "Enrollment complete."
