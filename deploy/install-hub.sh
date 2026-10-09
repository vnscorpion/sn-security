#!/usr/bin/env bash
# SN Secure hub (master) installer — for a fresh Ubuntu 24.04 / Debian 12 server.
#
#   curl -fsSL https://raw.githubusercontent.com/vnscorpion/sn-security/main/deploy/install-hub.sh | sudo bash -s -- \
#       --public-url https://a.example.net
#
# Installs the snhub binary + systemd service, seeds the agent installer/binaries
# the hub serves to VPSes, generates keys, and prints the next steps.
set -eu

REPO_RAW="https://raw.githubusercontent.com/vnscorpion/sn-security/main"
VERSION="main"
BIND="127.0.0.1:8099"
PUBLIC_URL=""
DATA_DIR="/var/lib/snhub"
CONFIG="/etc/snhub/snhub.toml"

while [ $# -gt 0 ]; do
  case "$1" in
    --public-url) PUBLIC_URL="$2"; shift 2;;
    --bind) BIND="$2"; shift 2;;
    --data-dir) DATA_DIR="$2"; shift 2;;
    --repo-raw) REPO_RAW="$2"; shift 2;;
    --version) VERSION="$2"; shift 2;;
    *) echo "unknown arg: $1" >&2; exit 2;;
  esac
done

[ "$(id -u)" -eq 0 ] || { echo "run as root (sudo)"; exit 1; }

arch="$(uname -m)"
case "$arch" in
  x86_64|amd64) ARCH=x86_64;;
  aarch64|arm64) ARCH=aarch64;;
  *) echo "unsupported arch: $arch"; exit 1;;
esac

echo ">> SN Secure hub installer (arch=$ARCH)"

# Dependencies for fetching + verifying.
if command -v apt-get >/dev/null 2>&1; then
  apt-get update -qq || true
  apt-get install -y -qq curl ca-certificates coreutils >/dev/null 2>&1 || true
fi

DIST="$REPO_RAW/dist"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

fetch() { curl -fsSL "$1" -o "$2"; }

echo ">> downloading binaries"
fetch "$DIST/SHA256SUMS" "$TMP/SHA256SUMS"
for f in "snhub-$ARCH" "sn-x86_64" "sn-aarch64" "install.sh"; do
  fetch "$DIST/$f" "$TMP/$f"
done

echo ">> verifying checksums"
( cd "$TMP" && for f in "snhub-$ARCH" sn-x86_64 sn-aarch64 install.sh; do
    grep " $f\$" SHA256SUMS | sha256sum -c - >/dev/null \
      || { echo "checksum FAILED for $f"; exit 1; }
  done )

echo ">> installing snhub"
install -m 0755 "$TMP/snhub-$ARCH" /usr/local/bin/snhub

# Dedicated system user.
if ! id snhub >/dev/null 2>&1; then
  useradd --system --home "$DATA_DIR" --shell /usr/sbin/nologin snhub || true
fi
mkdir -p "$DATA_DIR/public" /etc/snhub
# Seed what the hub serves to agents.
install -m 0755 "$TMP/sn-x86_64" "$DATA_DIR/public/sn-x86_64"
install -m 0755 "$TMP/sn-aarch64" "$DATA_DIR/public/sn-aarch64"
install -m 0644 "$TMP/install.sh" "$DATA_DIR/public/install.sh"
# Serve a SHA256SUMS covering just the agent artifacts.
grep -E ' (sn-x86_64|sn-aarch64|install.sh)$' "$TMP/SHA256SUMS" > "$DATA_DIR/public/SHA256SUMS"

echo ">> initialising hub (keys, db, config)"
PUB_ARG=""
[ -n "$PUBLIC_URL" ] && PUB_ARG="--public-url $PUBLIC_URL"
# shellcheck disable=SC2086
snhub --config "$CONFIG" init --bind "$BIND" --data-dir "$DATA_DIR" $PUB_ARG

chown -R snhub:snhub "$DATA_DIR" /etc/snhub
chmod 0640 "$CONFIG"
chmod 0600 "$DATA_DIR/hub.key" 2>/dev/null || true

echo ">> installing systemd service"
fetch "$REPO_RAW/deploy/systemd/snhub.service" /etc/systemd/system/snhub.service
systemctl daemon-reload
systemctl enable --now snhub.service

cat <<EOF

================= SN Secure hub ready =================
Service:  systemctl status snhub
Listening: $BIND  (public: ${PUBLIC_URL:-<set --public-url>})

Next:
  1) Set the admin password:
       sudo -u snhub snhub --config $CONFIG set-admin-password --password 'YOUR_PASSWORD'
     (or: SNHUB_ADMIN_PASSWORD=... sudo -E -u snhub snhub --config $CONFIG set-admin-password)
       sudo systemctl restart snhub

  2) Put a TLS reverse proxy / VPN in front of $BIND, then open the UI and
     use "Thêm VPS" to enroll each VPS. Keep the OFFLINE ROOT SECRET printed
     above somewhere safe and OFF this server.
======================================================
EOF
