#!/usr/bin/env bash
# Update an installed SN Secure hub in place.
#
#   curl -fsSL https://raw.githubusercontent.com/vnscorpion/sn-security/main/deploy/update-hub.sh | sudo bash
#
# Replaces the snhub binary AND refreshes the agent binaries/installer that the hub
# serves to VPSes (/var/lib/snhub/public), so `install.sh --upgrade` on a VPS gets
# the new agent. Data, keys, config and the admin password are left untouched.
# All downloads are sha256-verified before anything is replaced.
set -eu

REPO_RAW="https://raw.githubusercontent.com/vnscorpion/sn-security/main"
DATA_DIR="/var/lib/snhub"

while [ $# -gt 0 ]; do
  case "$1" in
    --data-dir) DATA_DIR="$2"; shift 2;;
    --repo-raw) REPO_RAW="$2"; shift 2;;
    *) echo "unknown arg: $1" >&2; exit 2;;
  esac
done

[ "$(id -u)" -eq 0 ] || { echo "run as root (sudo)"; exit 1; }
[ -x /usr/local/bin/snhub ] || { echo "snhub is not installed (use install-hub.sh first)"; exit 1; }

case "$(uname -m)" in
  x86_64|amd64) ARCH=x86_64;;
  aarch64|arm64) ARCH=aarch64;;
  *) echo "unsupported arch: $(uname -m)"; exit 1;;
esac

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
DIST="$REPO_RAW/dist"
FILES="snhub-$ARCH sn-x86_64 sn-aarch64 install.sh"

echo ">> downloading ($ARCH)"
curl -fsSL "$DIST/SHA256SUMS" -o "$TMP/SHA256SUMS" \
  || { echo "!! download failed (is the repo public?)"; exit 1; }
for f in $FILES; do
  curl -fsSL "$DIST/$f" -o "$TMP/$f" || { echo "!! download failed: $f"; exit 1; }
done

echo ">> verifying checksums"
( cd "$TMP" && for f in $FILES; do
    grep " $f\$" SHA256SUMS | sha256sum -c - >/dev/null \
      || { echo "checksum FAILED for $f"; exit 1; }
  done )

OLD="$(/usr/local/bin/snhub --version 2>/dev/null || echo unknown)"
cp -f /usr/local/bin/snhub /usr/local/bin/snhub.bak
install -m 0755 "$TMP/snhub-$ARCH" /usr/local/bin/snhub

echo ">> refreshing the agent files served to VPSes"
mkdir -p "$DATA_DIR/public"
install -m 0755 "$TMP/sn-x86_64" "$DATA_DIR/public/sn-x86_64"
install -m 0755 "$TMP/sn-aarch64" "$DATA_DIR/public/sn-aarch64"
install -m 0644 "$TMP/install.sh" "$DATA_DIR/public/install.sh"
grep -E ' (sn-x86_64|sn-aarch64|install.sh)$' "$TMP/SHA256SUMS" > "$DATA_DIR/public/SHA256SUMS"
chown -R snhub:snhub "$DATA_DIR/public" 2>/dev/null || true

echo ">> restarting snhub"
systemctl restart snhub
sleep 1
if systemctl is-active --quiet snhub; then
  # The address VPSes use to reach this hub, from the hub's own config.
  HUB_URL="$(sed -n 's/^public_url *= *"\(.*\)"/\1/p' /etc/snhub/snhub.toml 2>/dev/null | head -n1)"
  HUB_URL="${HUB_URL%/}"
  [ -n "$HUB_URL" ] || HUB_URL="https://YOUR-HUB-ADDRESS"
  echo ">> OK: $OLD -> $(/usr/local/bin/snhub --version)"
  echo "   Rollback: cp /usr/local/bin/snhub.bak /usr/local/bin/snhub && systemctl restart snhub"
  echo
  echo "   The hub is updated. Next, upgrade the agent on EACH VPS (not on this master)."
  echo "   Run this on every VPS, as root:"
  echo
  echo "   curl -fsSL $HUB_URL/install.sh | sudo sh -s -- --hub $HUB_URL --upgrade"
else
  echo "!! snhub failed to start, rolling back"
  cp -f /usr/local/bin/snhub.bak /usr/local/bin/snhub
  systemctl restart snhub || true
  journalctl -u snhub -n 20 --no-pager || true
  exit 1
fi
