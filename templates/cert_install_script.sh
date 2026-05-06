#!/usr/bin/env bash
# sshadmin signed-certificate installer for {{ cert_type }} certificate
# Target: {{ target_name }}
# Token below is single-use and time-limited; do not share.
set -euo pipefail

SERVER_URL="{{ server_url }}"
TOKEN="{{ token }}"
CERT_TYPE="{{ cert_type }}"          # 'user' or 'host'
CERT_PUBKEY_LINE='{{ cert_pubkey_line }}'

for bin in curl awk install; do
  command -v "$bin" >/dev/null || { echo "ERROR: missing required command: $bin" >&2; exit 1; }
done

# Fetch the signed certificate (OpenSSH format) using the install token.
CERT_DATA="$(curl -fsSL "$SERVER_URL/api/cert/install/data?token=$TOKEN")" || {
  echo "ERROR: could not fetch certificate from sshadmin." >&2
  exit 1
}

if [ -z "$CERT_DATA" ]; then
  echo "ERROR: server returned an empty certificate body." >&2
  exit 1
fi

write_cert() {
  local dest="$1"
  install -m 0644 -D /dev/null "$dest"
  printf '%s\n' "$CERT_DATA" > "$dest"
  chmod 0644 "$dest"
  echo "  wrote $dest"
}

if [ "$CERT_TYPE" = "host" ]; then
  if [ "${EUID:-$(id -u)}" -ne 0 ]; then
    echo "ERROR: host-cert install must run as root (re-run with sudo)." >&2
    exit 1
  fi

  # Standard host-key path for ECDSA P-521 (matches what the enrollment
  # script generates). Adjust if you use a different host key path.
  HOST_KEY="${SSHADMIN_HOST_KEY:-/etc/ssh/ssh_host_ecdsa_key}"
  HOST_PUB="${HOST_KEY}.pub"
  CERT_PATH="${HOST_KEY}-cert.pub"

  if [ ! -f "$HOST_PUB" ]; then
    echo "ERROR: host public key not found at $HOST_PUB." >&2
    echo "       Set SSHADMIN_HOST_KEY=/path/to/ssh_host_xxx_key and re-run." >&2
    exit 1
  fi

  # Sanity check: the cert's underlying pubkey should match this host's pubkey.
  HOST_PUB_FIELDS="$(awk '{print $1, $2}' "$HOST_PUB")"
  EXPECTED_FIELDS="$(printf '%s' "$CERT_PUBKEY_LINE" | awk '{print $1, $2}')"
  if [ "$HOST_PUB_FIELDS" != "$EXPECTED_FIELDS" ]; then
    echo "WARNING: host pubkey at $HOST_PUB does not match the certificate's"
    echo "         underlying key. Did you regenerate the host key after issuing?"
    echo "         Continuing anyway; sshd may reject the cert until they match."
  fi

  write_cert "$CERT_PATH"

  # Ensure sshd_config references the cert via a drop-in file (idempotent).
  DROPIN="/etc/ssh/sshd_config.d/99-sshadmin-hostcert.conf"
  mkdir -p "$(dirname "$DROPIN")"
  if ! grep -qsF "HostCertificate $CERT_PATH" "$DROPIN" 2>/dev/null; then
    {
      echo "# Managed by sshadmin"
      echo "HostCertificate $CERT_PATH"
    } > "$DROPIN"
    chmod 0644 "$DROPIN"
    echo "  wrote $DROPIN"
  fi

  if command -v systemctl >/dev/null && systemctl is-active --quiet ssh 2>/dev/null; then
    systemctl reload ssh
    echo "  reloaded ssh"
  elif command -v systemctl >/dev/null && systemctl is-active --quiet sshd 2>/dev/null; then
    systemctl reload sshd
    echo "  reloaded sshd"
  else
    echo "NOTE: reload sshd manually so the new HostCertificate takes effect."
  fi

  echo "Done. Verify with: sudo sshd -T | grep -i hostcertificate"

else
  # ----- USER CERT INSTALL -----
  SSH_DIR="${HOME}/.ssh"
  mkdir -p "$SSH_DIR"
  chmod 0700 "$SSH_DIR"

  # Find the matching .pub in ~/.ssh whose algo+base64 equals the cert's
  # underlying key, and write the cert next to it as <basename>-cert.pub
  # (which is the path ssh consults automatically).
  EXPECTED_FIELDS="$(printf '%s' "$CERT_PUBKEY_LINE" | awk '{print $1, $2}')"
  TARGET=""
  for pub in "$SSH_DIR"/*.pub; do
    [ -f "$pub" ] || continue
    if [ "$(awk '{print $1, $2}' "$pub")" = "$EXPECTED_FIELDS" ]; then
      TARGET="${pub%.pub}-cert.pub"
      break
    fi
  done

  if [ -z "$TARGET" ]; then
    # Fallback: write to a generic location and tell the user to point ssh at it.
    TARGET="$SSH_DIR/sshadmin-cert.pub"
    echo "NOTE: could not find a matching public key in $SSH_DIR/*.pub."
    echo "      Wrote the cert to $TARGET; either move it next to your"
    echo "      private key (so the basename matches), or add this line to"
    echo "      ~/.ssh/config:"
    echo ""
    echo "        Host <target>"
    echo "            CertificateFile $TARGET"
    echo "            IdentityFile <path-to-matching-private-key>"
    echo ""
  fi

  write_cert "$TARGET"
  echo "Done. Verify with: ssh-keygen -L -f $TARGET"
fi
