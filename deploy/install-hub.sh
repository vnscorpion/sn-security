#!/usr/bin/env bash
# SN Secure hub (master) installer — for a fresh Ubuntu 24.04 / Debian 12 server.
#
# Public repo (one-liner):
#   curl -fsSL https://raw.githubusercontent.com/vnscorpion/sn-security/main/deploy/install-hub.sh \
#       | sudo bash -s -- --public-url https://a.example.net
#
# Private repo (clone, then install from the local checkout — no raw download):
#   git clone https://github.com/vnscorpion/sn-security
#   cd sn-security
#   sudo bash deploy/install-hub.sh --local --public-url https://a.example.net
#
# Installs the snhub binary + systemd service, seeds the agent installer/binaries
# the hub serves to VPSes, generates keys, and prints the next steps.
set -eu

REPO_RAW="https://raw.githubusercontent.com/vnscorpion/sn-security/main"
BIND="127.0.0.1:8099"
PUBLIC_URL=""
DATA_DIR="/var/lib/snhub"
CONFIG="/etc/snhub/snhub.toml"
LOCAL=0

while [ $# -gt 0 ]; do
  case "$1" in
    --local) LOCAL=1; shift;;
    --public-url) PUBLIC_URL="$2"; shift 2;;
    --bind) BIND="$2"; shift 2;;
    --data-dir) DATA_DIR="$2"; shift 2;;
    --repo-raw) REPO_RAW="$2"; shift 2;;
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

echo ">> SN Secure hub installer (arch=$ARCH, mode=$([ "$LOCAL" = 1 ] && echo local || echo download))"

if command -v apt-get >/dev/null 2>&1; then
  apt-get update -qq || true
  apt-get install -y -qq curl ca-certificates coreutils >/dev/null 2>&1 || true
fi

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

# STAGE holds the artifacts to install; SYSTEMD_SRC holds the unit file.
if [ "$LOCAL" = 1 ]; then
  SELF="$(readlink -f "$0" 2>/dev/null || echo "$0")"
  DEPLOY_DIR="$(cd "$(dirname "$SELF")" && pwd)"
  REPO_ROOT="$(cd "$DEPLOY_DIR/.." && pwd)"
  STAGE="$REPO_ROOT/dist"
  SYSTEMD_SRC="$DEPLOY_DIR/systemd/snhub.service"
  [ -f "$STAGE/SHA256SUMS" ] || {
    echo "!! --local needs a repo checkout: $STAGE/SHA256SUMS not found."
    echo "   git clone the repo and run: sudo bash deploy/install-hub.sh --local ..."
    exit 1
  }
else
  DIST="$REPO_RAW/dist"
  STAGE="$TMP"
  SYSTEMD_SRC="$TMP/snhub.service"
  echo ">> downloading binaries"
  dl() {
    curl -fsSL "$1" -o "$2" || {
      echo "!! download failed: $1"
      echo "   If the repo is PRIVATE, raw.githubusercontent returns 404."
      echo "   Clone it and re-run with --local (see the header of this script)."
      exit 1
    }
  }
  dl "$DIST/SHA256SUMS" "$TMP/SHA256SUMS"
  for f in "snhub-$ARCH" "sn-x86_64" "sn-aarch64" "install.sh"; do
    dl "$DIST/$f" "$TMP/$f"
  done
  dl "$REPO_RAW/deploy/systemd/snhub.service" "$TMP/snhub.service"
fi

echo ">> verifying checksums"
( cd "$STAGE" && for f in "snhub-$ARCH" sn-x86_64 sn-aarch64 install.sh; do
    grep " $f\$" SHA256SUMS | sha256sum -c - >/dev/null \
      || { echo "checksum FAILED for $f"; exit 1; }
  done )

echo ">> installing snhub"
install -m 0755 "$STAGE/snhub-$ARCH" /usr/local/bin/snhub

if ! id snhub >/dev/null 2>&1; then
  useradd --system --home "$DATA_DIR" --shell /usr/sbin/nologin snhub || true
fi
mkdir -p "$DATA_DIR/public" /etc/snhub
install -m 0755 "$STAGE/sn-x86_64" "$DATA_DIR/public/sn-x86_64"
install -m 0755 "$STAGE/sn-aarch64" "$DATA_DIR/public/sn-aarch64"
install -m 0644 "$STAGE/install.sh" "$DATA_DIR/public/install.sh"
grep -E ' (sn-x86_64|sn-aarch64|install.sh)$' "$STAGE/SHA256SUMS" > "$DATA_DIR/public/SHA256SUMS"

echo ">> initialising hub (keys, db, config)"
PUB_ARG=""
[ -n "$PUBLIC_URL" ] && PUB_ARG="--public-url $PUBLIC_URL"
# shellcheck disable=SC2086
snhub --config "$CONFIG" init --bind "$BIND" --data-dir "$DATA_DIR" $PUB_ARG

chown -R snhub:snhub "$DATA_DIR" /etc/snhub
chmod 0640 "$CONFIG"
chmod 0600 "$DATA_DIR/hub.key" 2>/dev/null || true

echo ">> installing systemd service"
install -m 0644 "$SYSTEMD_SRC" /etc/systemd/system/snhub.service
systemctl daemon-reload
systemctl enable --now snhub.service

cat <<EOF

================= SN Secure hub ready =================
Service:  systemctl status snhub
Listening: $BIND  (public: ${PUBLIC_URL:-<set --public-url>})

Next:
  1) Set the admin password:
       sudo -u snhub snhub --config $CONFIG set-admin-password --password 'YOUR_PASSWORD'   (at least 10 characters)
       sudo systemctl restart snhub

  2) Put a TLS reverse proxy / VPN in front of $BIND, then open the UI and
     use "Thêm VPS" to enroll each VPS. Keep the OFFLINE ROOT SECRET printed
     above somewhere safe and OFF this server.
======================================================
EOF
