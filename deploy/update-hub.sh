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
#
# The sha256 check catches a damaged or mixed download, not a malicious one:
# SHA256SUMS comes from the same branch as the binaries, so whoever can push there
# decides what the hub and every VPS run (signed releases: SEC-5, docs/REVIEW.md).
# To install only a commit you have reviewed, fetch this script from that commit
# and pass --repo-raw https://raw.githubusercontent.com/vnscorpion/sn-security/COMMIT
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
NEWPUB=""
# Start the hub and wait until it is really running. Repeated stops and starts
# (a re-run, a failed run) can leave the unit "failed" or rate-limited, which a
# plain start does not clear.
start_hub() {
  systemctl reset-failed snhub >/dev/null 2>&1 || true
  systemctl start snhub >/dev/null 2>&1 || true
  for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15; do
    systemctl is-active --quiet snhub && return 0
    sleep 1
  done
  return 1
}
cleanup() {
  rm -rf "$TMP"
  [ -z "$NEWPUB" ] || rm -rf -- "$NEWPUB"
  # A failure between stop and start must not leave the hub down: start it, and
  # if the new binary will not run, the previous one.
  if [ "$STOPPED" = 1 ] && ! systemctl is-active --quiet snhub; then
    echo "!! update failed; starting snhub again" >&2
    if ! start_hub && [ -x /usr/local/bin/snhub.bak ]; then
      echo "!! the new snhub does not start; going back to the previous one" >&2
      cp -f /usr/local/bin/snhub.bak /usr/local/bin/snhub
      start_hub || journalctl -u snhub -n 20 --no-pager >&2 || true
    fi
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
# root's alone. Older versions let the hub's user own public/, so it is built anew
# in a root-made directory and swapped in whole: no link, directory or extra file
# left there (/sn/<file> serves anything in it) survives or redirects root's writes.
refresh_public() {
  pub="$DATA_DIR/public"
  NEWPUB="$(mktemp -d "$DATA_DIR/.public.XXXXXX")"
  install -m 0755 "$1/sn-x86_64" "$NEWPUB/sn-x86_64"
  install -m 0755 "$1/sn-aarch64" "$NEWPUB/sn-aarch64"
  install -m 0644 "$1/install.sh" "$NEWPUB/install.sh"
  grep -E ' (sn-x86_64|sn-aarch64|install.sh)$' "$1/SHA256SUMS" > "$NEWPUB/SHA256SUMS"
  chmod 0644 "$NEWPUB/SHA256SUMS"
  chmod 0755 "$NEWPUB"
  rm -rf -- "$pub"
  mv -T -- "$NEWPUB" "$pub"
  NEWPUB=""
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

# Permissions and the service hardening come before public/: if anything below
# fails, the hub that cleanup() starts again already runs locked down.
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

echo ">> refreshing the agent files served to VPSes"
refresh_public "$TMP"

echo ">> starting snhub"
if start_hub; then
  STOPPED=0
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
  journalctl -u snhub -n 20 --no-pager || true
  cp -f /usr/local/bin/snhub.bak /usr/local/bin/snhub
  start_hub || true
  STOPPED=0
  exit 1
fi
