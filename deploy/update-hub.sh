#!/usr/bin/env bash
# Update an installed SN Secure hub in place.
#
#   curl -fsSL https://raw.githubusercontent.com/vnscorpion/sn-security/main/deploy/update-hub.sh | sudo bash
#
# Replaces the snhub binary AND refreshes the agent binaries/installer that the hub
# serves to VPSes (/var/lib/snhub/public), so `install.sh --upgrade` on a VPS gets
# the new agent. Data, keys, config and the admin password are left untouched.
# All downloads are sha256-verified before anything is replaced. File permissions
# are brought in line with a fresh install (see lock_down below).
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
STOPPED=0
cleanup() {
  rm -rf "$TMP"
  # A failure between stop and start must not leave the hub down.
  if [ "$STOPPED" = 1 ] && ! systemctl is-active --quiet snhub; then
    systemctl start snhub || true
  fi
}
trap cleanup EXIT
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

# The agent binaries, install.sh and SHA256SUMS that every VPS runs as root are
# written by root only. Older versions let the hub's user own public/, so a link
# left in its place must not redirect root's writes.
refresh_public() {
  pub="$DATA_DIR/public"
  if [ -L "$pub" ] || { [ -e "$pub" ] && [ ! -d "$pub" ]; }; then rm -f "$pub"; fi
  mkdir -p "$pub"
  for f in sn-x86_64 sn-aarch64 install.sh SHA256SUMS; do rm -f "$pub/$f"; done
  install -m 0755 "$1/sn-x86_64" "$pub/sn-x86_64"
  install -m 0755 "$1/sn-aarch64" "$pub/sn-aarch64"
  install -m 0644 "$1/install.sh" "$pub/install.sh"
  grep -E ' (sn-x86_64|sn-aarch64|install.sh)$' "$1/SHA256SUMS" > "$TMP/SHA256SUMS.public"
  install -m 0644 "$TMP/SHA256SUMS.public" "$pub/SHA256SUMS"
  chown -R root:root "$pub"
  chmod 0755 "$pub"
}

# Only the hub's user may enter the data dir: the database holds the AI API keys,
# the 2FA secret, the admin password hash and live enrollment tokens. hub.key is
# root's, readable by the service but not replaceable by it.
lock_down() {
  chmod 0700 "$DATA_DIR"
  for f in "$DATA_DIR"/snhub.sqlite*; do
    if [ -f "$f" ] && [ ! -L "$f" ]; then chmod 0600 "$f"; fi
  done
  if [ -f "$DATA_DIR/hub.key" ] && [ ! -L "$DATA_DIR/hub.key" ]; then
    chown root:snhub "$DATA_DIR/hub.key"
    chmod 0640 "$DATA_DIR/hub.key"
  fi
  chmod 0750 /etc/snhub
}

OLD="$(/usr/local/bin/snhub --version 2>/dev/null || echo unknown)"
# Stopped, not restarted: the running hub must not change the files below while
# root rewrites them.
echo ">> stopping snhub"
systemctl stop snhub
STOPPED=1
cp -f /usr/local/bin/snhub /usr/local/bin/snhub.bak
install -m 0755 "$TMP/snhub-$ARCH" /usr/local/bin/snhub

echo ">> refreshing the agent files served to VPSes"
refresh_public "$TMP"
lock_down

# An installed snhub.service may predate these settings; a drop-in adds them
# without overwriting local edits to the unit.
mkdir -p /etc/systemd/system/snhub.service.d
cat > /etc/systemd/system/snhub.service.d/10-hardening.conf <<EOF
# Written by update-hub.sh: settings a fresh snhub.service already has.
[Service]
UMask=0077
ReadOnlyPaths=$DATA_DIR/public
ReadOnlyPaths=-$DATA_DIR/hub.key
EOF
chmod 0644 /etc/systemd/system/snhub.service.d/10-hardening.conf
systemctl daemon-reload

echo ">> starting snhub"
systemctl start snhub
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
