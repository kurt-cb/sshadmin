#!/usr/bin/env bash
# SSH challenge-response for {{ purpose }} of user "{{ username }}"
# Token below is single-use and expires shortly. Do not share.
set -euo pipefail

SSHADMIN_URL="{{ server_url }}"
TOKEN="{{ token }}"
NONCE="{{ nonce }}"
NAMESPACE="{{ sshsig_namespace }}"
REGISTERED_PUBKEY="{{ public_key }}"
PURPOSE="{{ purpose }}"
{% if include_host_enrollment %}
HOST_KEY_TYPE="{{ host_key_type }}"
HOST_KEY="/etc/ssh/ssh_host_ecdsa_key"
HOST_PUB="${HOST_KEY}.pub"
CA_PUB="/etc/ssh/sshadmin_ca.pub"
SSHD_DROPIN="/etc/ssh/sshd_config.d/99-sshadmin.conf"
{% endif %}

for bin in ssh-keygen curl awk; do
  command -v "$bin" >/dev/null || { echo "ERROR: missing required command: $bin" >&2; exit 1; }
done

# ---------- detect runtime user / sudo state ----------
CAN_DO_HOST=0
RUN_USER=""
USER_HOME=""
if [ "${EUID:-$(id -u)}" -eq 0 ]; then
  CAN_DO_HOST=1
  if [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != "root" ]; then
    RUN_USER="$SUDO_USER"
    USER_HOME="$(getent passwd "$SUDO_USER" | cut -d: -f6)"
  else
    RUN_USER="root"
    USER_HOME="${HOME:-/root}"
  fi
else
  RUN_USER="$(id -un)"
  USER_HOME="${HOME:-/home/$RUN_USER}"
fi

# ---------- locate the private key matching the registered public key ----------
REGISTERED_PARTS="$(printf '%s' "$REGISTERED_PUBKEY" | awk '{print $1, $2}')"
PRIVATE_KEY="${SSHADMIN_PRIVATE_KEY:-}"

if [ -z "$PRIVATE_KEY" ]; then
  if [ -d "$USER_HOME/.ssh" ]; then
    for pub in "$USER_HOME"/.ssh/*.pub; do
      [ -f "$pub" ] || continue
      if [ "$(awk '{print $1, $2}' "$pub")" = "$REGISTERED_PARTS" ]; then
        PRIVATE_KEY="${pub%.pub}"
        break
      fi
    done
  fi
fi

if [ -z "$PRIVATE_KEY" ] || [ ! -f "$PRIVATE_KEY" ]; then
  echo "ERROR: could not find a private key matching the registered public key in $USER_HOME/.ssh/" >&2
  echo "       Set SSHADMIN_PRIVATE_KEY=/path/to/key and re-run." >&2
  exit 1
fi
echo "Using private key: $PRIVATE_KEY"

# ---------- sign the challenge ----------
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT
NONCE_FILE="$TMP_DIR/nonce"
printf '%s' "$NONCE" > "$NONCE_FILE"

if [ "${EUID:-$(id -u)}" -eq 0 ] && [ "$RUN_USER" != "root" ]; then
  # Drop privileges so the user's ssh-agent / config is honored.
  chown "$RUN_USER" "$NONCE_FILE" "$TMP_DIR"
  sudo -u "$RUN_USER" ssh-keygen -Y sign -f "$PRIVATE_KEY" -n "$NAMESPACE" "$NONCE_FILE" >/dev/null
else
  ssh-keygen -Y sign -f "$PRIVATE_KEY" -n "$NAMESPACE" "$NONCE_FILE" >/dev/null
fi

SIGNATURE="$(cat "$NONCE_FILE.sig")"
echo "Challenge signed."

{% if include_host_enrollment %}
# ---------- optional host enrollment (registration only, requires root) ----------
HOSTNAME_FQDN=""
HOST_PUBKEY=""
if [ "$CAN_DO_HOST" = "1" ] && [ "${SSHADMIN_SKIP_HOST:-0}" != "1" ]; then
  HOSTNAME_FQDN="$(hostname -f 2>/dev/null || hostname)"
  echo "Enrolling host $HOSTNAME_FQDN ..."

  if [ -f "$HOST_PUB" ]; then
    EXISTING_TYPE="$(awk '{print $1}' "$HOST_PUB")"
    if [ "$EXISTING_TYPE" != "$HOST_KEY_TYPE" ]; then
      BACKUP_SUFFIX=".sshadmin.bak.$(date +%Y%m%d%H%M%S)"
      echo "Existing host key is type '$EXISTING_TYPE'; required '$HOST_KEY_TYPE'. Moving aside (suffix: $BACKUP_SUFFIX)."
      for f in "$HOST_KEY" "$HOST_PUB" "${HOST_KEY}-cert.pub"; do
        if [ -e "$f" ]; then
          mv "$f" "$f$BACKUP_SUFFIX"
          echo "  $f -> $f$BACKUP_SUFFIX"
        fi
      done
    fi
  fi

  if [ ! -f "$HOST_PUB" ]; then
    echo "Generating ECDSA P-521 host key at $HOST_KEY"
    ssh-keygen -t ecdsa -b 521 -f "$HOST_KEY" -N "" -C "host:$HOSTNAME_FQDN" >/dev/null
    chmod 600 "$HOST_KEY"
    chmod 644 "$HOST_PUB"
  fi
  HOST_PUBKEY="$(cat "$HOST_PUB")"

  echo "Fetching CA public key from $SSHADMIN_URL/api/ca-pubkey"
  if curl -fsSL "$SSHADMIN_URL/api/ca-pubkey" -o "$CA_PUB.tmp"; then
    mv "$CA_PUB.tmp" "$CA_PUB"
    chmod 644 "$CA_PUB"
    mkdir -p "$(dirname "$SSHD_DROPIN")"
    cat > "$SSHD_DROPIN" <<EOF
# Managed by sshadmin enrollment
TrustedUserCAKeys $CA_PUB
HostCertificate ${HOST_KEY}-cert.pub
EOF
    chmod 644 "$SSHD_DROPIN"
  else
    echo "WARNING: could not fetch CA public key (server may not have one yet); skipping sshd_config drop-in."
  fi
elif [ "$PURPOSE" = "register" ]; then
  echo "Skipping host enrollment (not running as root, or SSHADMIN_SKIP_HOST=1)."
fi
{% endif %}

# ---------- submit signature (and optional host info) ----------
echo "Submitting challenge response..."
ARGS=(--data-urlencode "token=$TOKEN" --data-urlencode "signature=$SIGNATURE")
{% if include_host_enrollment %}
if [ -n "${HOSTNAME_FQDN:-}" ] && [ -n "${HOST_PUBKEY:-}" ]; then
  ARGS+=(--data-urlencode "hostname=$HOSTNAME_FQDN")
  ARGS+=(--data-urlencode "host_public_key=$HOST_PUBKEY")
fi
{% endif %}

RESPONSE="$(curl -fsS -X POST "$SSHADMIN_URL/api/challenge_response" "${ARGS[@]}")"
echo "$RESPONSE"

{% if include_host_enrollment %}
# Reload sshd if we wrote a drop-in.
if [ "$CAN_DO_HOST" = "1" ] && [ -f "$SSHD_DROPIN" ]; then
  if command -v systemctl >/dev/null && systemctl is-active --quiet ssh 2>/dev/null; then
    systemctl reload ssh
  elif command -v systemctl >/dev/null && systemctl is-active --quiet sshd 2>/dev/null; then
    systemctl reload sshd
  else
    echo "NOTE: reload sshd manually so the new config takes effect."
  fi
fi
{% endif %}

echo "Done. Return to the sshadmin browser tab — the page should redirect once verified."
