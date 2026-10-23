#!/usr/bin/env bash
# Put a backup made by backup-hub.sh onto a hub: the same server after a mishap, or a
# NEW server (docs/RUNBOOK.md, "Sao lưu và chuyển master sang máy chủ mới").
#
# On a new server, first install the hub the usual way and at the same version (or a
# newer one) as the backup, so the user, the service and the binary exist:
#     curl -fsSL https://raw.githubusercontent.com/vnscorpion/sn-security/COMMIT/deploy/install-hub.sh \
#       | sudo bash -s -- --repo-raw https://raw.githubusercontent.com/vnscorpion/sn-security/COMMIT --public-url https://YOUR-HUB
# then:
#     sudo bash restore-hub.sh snhub-backup-….tar.gz.enc --caddy
#
# What it does: checks the file (checksums, the database's own check, the version),
# stops snhub, sets the fresh install's own files aside in <data_dir>.before-restore-<time>
# (nothing is deleted), puts the backup's config, hub key and database in place with the
# right owners, and starts snhub again. VPSes keep working unchanged as long as they
# reach the hub at the same address (point the name at the new server).
#
# Options:
#   --pass-file FILE    read the passphrase from the first line of FILE
#                       (or set SNHUB_BACKUP_PASSPHRASE)
#   --caddy             also put the backup's Caddyfile in place (and certificates, if saved)
#                       and reload Caddy; the old Caddyfile is kept as Caddyfile.before-restore
#   --ignore-version    restore even though this snhub is OLDER than the backup's (the
#                       database may then not open: update the hub first instead)
set -euo pipefail
umask 077

BACKUP=""
PASS_FILE=""
CADDY=0
IGNORE_VERSION=0
# For the tests only: every path is under this folder; nothing is started, stopped or chowned.
ROOT="${SNHUB_ROOT:-}"

die() { echo "!! $*" >&2; exit 1; }
say() { echo ">> $*"; }
p() { printf '%s%s' "$ROOT" "$1"; }

while [ $# -gt 0 ]; do
  case "$1" in
    --pass-file) PASS_FILE="$2"; shift 2;;
    --caddy) CADDY=1; shift;;
    --ignore-version) IGNORE_VERSION=1; shift;;
    -h|--help) awk 'NR>1 && /^#/ {sub(/^# ?/, ""); print; next} NR>1 {exit}' "$0"; exit 0;;
    -*) die "unknown option: $1 (see --help)";;
    *) [ -z "$BACKUP" ] || die "one backup file only"; BACKUP="$1"; shift;;
  esac
done
[ -n "$BACKUP" ] || die "usage: restore-hub.sh BACKUP-FILE [--caddy] [--pass-file FILE]"
[ -f "$BACKUP" ] || die "no such file: $BACKUP"
[ -n "$ROOT" ] || [ "$(id -u)" -eq 0 ] || die "run as root (sudo)"
SNHUB="$(p /usr/local/bin/snhub)"
[ -x "$SNHUB" ] || die "snhub is not installed here: run install-hub.sh first (see the top of this script)"
if [ -z "$ROOT" ]; then id snhub >/dev/null 2>&1 || die "no 'snhub' user: run install-hub.sh first"; fi

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

# ---- open the file ----------------------------------------------------------
if [ "$(head -c 8 "$BACKUP")" = "Salted__" ]; then
  command -v openssl >/dev/null 2>&1 || die "openssl is needed to open this file"
  if [ -n "$PASS_FILE" ]; then
    [ -r "$PASS_FILE" ] || die "cannot read $PASS_FILE"
    SNHUB_BACKUP_PASSPHRASE="$(head -n 1 "$PASS_FILE")"
  fi
  if [ -z "${SNHUB_BACKUP_PASSPHRASE:-}" ]; then
    [ -t 0 ] || die "no passphrase: set SNHUB_BACKUP_PASSPHRASE or use --pass-file"
    read -rsp "Passphrase of the backup: " SNHUB_BACKUP_PASSPHRASE; echo
  fi
  export SNHUB_BACKUP_PASSPHRASE
  openssl enc -d -aes-256-cbc -pbkdf2 -iter 600000 -pass env:SNHUB_BACKUP_PASSPHRASE -in "$BACKUP" \
    | tar -C "$TMP" -xzf - 2>/dev/null \
    || die "cannot open the backup: wrong passphrase, or the file is damaged"
else
  tar -C "$TMP" -xzf "$BACKUP" || die "cannot read the backup: the file is damaged"
fi
[ -f "$TMP/MANIFEST" ] && [ -f "$TMP/files.sha256" ] || die "this is not a backup of snhub (no MANIFEST)"
mf() { sed -n "s/^$1=//p" "$TMP/MANIFEST" | head -n 1; }
[ "$(mf format)" = "snhub-backup-1" ] || die "unknown backup format: $(mf format)"
( cd "$TMP/files" && sha256sum -c --quiet "$TMP/files.sha256" ) || die "a file in the backup does not match its checksum: the backup is damaged"

DATA_DIR="$(mf data_dir)"; DATA_DIR="${DATA_DIR:-/var/lib/snhub}"
say "backup of $(mf host), made $(mf created): snhub $(mf snhub_version), $(mf agents) VPS, $(mf public_url)"

if command -v python3 >/dev/null 2>&1 || command -v sqlite3 >/dev/null 2>&1; then
  cp "$TMP/files/data/snhub.sqlite" "$TMP/check.sqlite"
  if command -v sqlite3 >/dev/null 2>&1; then r="$(sqlite3 "$TMP/check.sqlite" 'pragma integrity_check' | head -n 1)"
  else r="$(python3 -c "import sqlite3,sys;print(sqlite3.connect(sys.argv[1]).execute('pragma integrity_check').fetchone()[0])" "$TMP/check.sqlite")"; fi
  [ "$r" = "ok" ] || die "the database in the backup fails SQLite's check ($r)"
  rm -f "$TMP/check.sqlite"*
fi

# The database only ever moves forward: a hub older than the one that wrote it may not open it.
have="$("$SNHUB" --version 2>/dev/null | awk '{print $2}')"; want="$(mf snhub_version)"
if [ -n "$have" ] && [ -n "$want" ] && [ "$want" != "unknown" ] && [ "$IGNORE_VERSION" -eq 0 ]; then
  newest="$(printf '%s\n%s\n' "$have" "$want" | sort -V | tail -n 1)"
  if [ "$newest" != "$have" ]; then
    die "this snhub is $have, older than the backup's $want. Update the hub first (update-hub.sh from the same commit), or use --ignore-version"
  fi
fi

# ---- put it in place --------------------------------------------------------
DATA="$(p "$DATA_DIR")"
CONF="$(p /etc/snhub/snhub.toml)"
STAMP="$(date +%Y%m%d-%H%M%S)"
SAVE="$DATA.before-restore-$STAMP"

if [ -z "$ROOT" ] && systemctl is-active --quiet snhub; then
  say "stopping snhub"
  systemctl stop snhub
fi
mkdir -p "$DATA" "$(dirname "$CONF")" "$SAVE"
chmod 700 "$SAVE"
for f in hub.key snhub.sqlite snhub.sqlite-wal snhub.sqlite-shm; do
  [ -e "$DATA/$f" ] && mv "$DATA/$f" "$SAVE/"
done
[ -e "$CONF" ] && cp -p "$CONF" "$SAVE/snhub.toml"
say "the files that were here are kept in $SAVE"

own() { # own USER:GROUP MODE FILE
  chmod "$2" "$3"
  if [ -z "$ROOT" ]; then chown "$1" "$3"; fi
}
install -m 0640 "$TMP/files/etc/snhub/snhub.toml" "$CONF"; own snhub:snhub 0640 "$CONF"
install -m 0640 "$TMP/files/data/hub.key" "$DATA/hub.key"; own root:snhub 0640 "$DATA/hub.key"
install -m 0600 "$TMP/files/data/snhub.sqlite" "$DATA/snhub.sqlite"; own snhub:snhub 0600 "$DATA/snhub.sqlite"
if [ -z "$ROOT" ]; then chown snhub:snhub "$DATA"; fi
chmod 700 "$DATA"

# The service's own settings (hardening drop-ins), when the backup has any.
for d in "$TMP/files/etc/systemd/system/snhub.service.d"/*.conf; do
  [ -f "$d" ] || continue
  mkdir -p "$(p /etc/systemd/system/snhub.service.d)"
  install -m 0644 "$d" "$(p /etc/systemd/system/snhub.service.d)/$(basename "$d")"
done
if [ -z "$ROOT" ]; then systemctl daemon-reload; fi

if [ "$CADDY" -eq 1 ]; then
  CF="$(p /etc/caddy/Caddyfile)"
  if [ -f "$TMP/files/etc/caddy/Caddyfile" ]; then
    mkdir -p "$(dirname "$CF")"
    [ -f "$CF" ] && cp -p "$CF" "$CF.before-restore"
    install -m 0644 "$TMP/files/etc/caddy/Caddyfile" "$CF"
    if command -v caddy >/dev/null 2>&1 && ! caddy validate --config "$CF" --adapter caddyfile >/dev/null 2>&1; then
      [ -f "$CF.before-restore" ] && cp -p "$CF.before-restore" "$CF"
      die "the backup's Caddyfile does not validate on this Caddy: the old one is back. Fix it by hand."
    fi
    say "Caddyfile restored (the old one: $CF.before-restore)"
  else
    echo "?? the backup holds no Caddyfile" >&2
  fi
  if [ -d "$TMP/files/caddy-data" ]; then
    CD="$(p /var/lib/caddy/.local/share/caddy)"
    mkdir -p "$CD"
    cp -a "$TMP/files/caddy-data/." "$CD/"
    if [ -z "$ROOT" ]; then chown -R caddy:caddy /var/lib/caddy/.local 2>/dev/null || true; fi
    say "certificates restored"
  fi
  if [ -z "$ROOT" ] && systemctl is-active --quiet caddy; then systemctl reload caddy; fi
fi

# ---- start and check --------------------------------------------------------
if [ -z "$ROOT" ]; then
  systemctl start snhub
  BIND="$(sed -n 's/^bind[[:space:]]*=[[:space:]]*"\(.*\)"/\1/p' "$CONF" | head -n 1)"
  ok=0
  for _ in $(seq 1 30); do
    if curl -fsS "http://${BIND:-127.0.0.1:8099}/healthz" >/dev/null 2>&1; then ok=1; break; fi
    sleep 1
  done
  [ "$ok" -eq 1 ] || die "snhub did not answer after the restore: journalctl -u snhub -n 50"
  say "snhub is running again"
fi

cat <<EOF

Done. The hub is back with $(mf agents) VPS.
Next, when this is a new server:
  1. Point the name $(mf public_url) at this server's address (DNS). Nothing changes on the VPSes:
     they keep calling the same address, and the hub key is the same.
  2. Open the hub, sign in with your old password and second factor (passkeys work because the name is the same).
  3. Check "Tổng quan": every VPS should show a report within ~5 minutes.
  4. Switch the old server off only when they all have. Keep this backup until then.
EOF
