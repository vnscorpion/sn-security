#!/usr/bin/env bash
# Back up everything that makes this hub *this* hub, into one encrypted file you
# can keep off the server or carry to a new one (see docs/RUNBOOK.md, "Sao lưu và
# chuyển master sang máy chủ mới").
#
#   sudo bash backup-hub.sh                       # asks for a passphrase twice
#   SNHUB_BACKUP_PASSPHRASE=... sudo -E bash backup-hub.sh --keep 14   # from cron
#
# What goes in (nothing else is needed to bring the hub back):
#   snhub.toml          the hub's settings and the admin password hash
#   hub.key             the key every VPS trusts (lose it and every VPS must re-enroll)
#   snhub.sqlite        VPSes, reports, orders, AI providers and keys, Hermes tokens,
#                       passkeys, the authenticator-app secret, recovery codes, WAF rules
#   Caddyfile + the systemd drop-ins of snhub (and, with --with-certs, Caddy's certificates)
# What stays out, on purpose:
#   the OFFLINE root key (printed once by `snhub init`: keep it where you keep it now),
#   the snhub binary and the agent files it serves (install-hub.sh / update-hub.sh
#   rebuild them from the repository).
#
# The file holds the hub key and the AI API keys: it is encrypted (AES-256, key from
# your passphrase) unless you pass --plain.
#
# Options:
#   --out FILE          write here (default: /var/backups/snhub/snhub-backup-<time>.tar.gz.enc)
#   --keep N            with the default folder, keep the newest N files (default 14)
#   --pass-file FILE    read the passphrase from the first line of FILE
#   --plain             do NOT encrypt (the file is then as secret as the hub key)
#   --with-certs        also save Caddy's certificates (saves re-issuing them on the new server)
#   --quiesce           stop snhub for a moment and copy the database: a point in time that
#                       is exact, as the last backup before moving to another server should be
#   --leave-stopped     with --quiesce: do not start snhub again. For the last backup before
#                       moving to a new server: the old hub then cannot sign anything the
#                       backup does not have (disable it once the file is on the new server)
#   --config FILE       the hub's config (default /etc/snhub/snhub.toml)
set -euo pipefail
umask 077

CONFIG="/etc/snhub/snhub.toml"
OUT=""
OUT_DIR="/var/backups/snhub"
KEEP=14
ENCRYPT=1
PASS_FILE=""
WITH_CERTS=0
QUIESCE=0
LEAVE_STOPPED=0
# For the tests only: every path is looked up under this folder, and nothing is
# started, stopped or chowned.
ROOT="${SNHUB_ROOT:-}"

die() { echo "!! $*" >&2; exit 1; }
say() { echo ">> $*"; }
p() { printf '%s%s' "$ROOT" "$1"; }
# The service, when this is a real server (the tests may stand a fake systemctl in: SNHUB_SYSTEMCTL).
svc_on() { [ -z "$ROOT" ] || [ -n "${SNHUB_SYSTEMCTL:-}" ]; }
svc() { "${SNHUB_SYSTEMCTL:-systemctl}" "$@"; }

while [ $# -gt 0 ]; do
  case "$1" in
    --out) OUT="$2"; shift 2;;
    --keep) KEEP="$2"; shift 2;;
    --pass-file) PASS_FILE="$2"; shift 2;;
    --plain) ENCRYPT=0; shift;;
    --with-certs) WITH_CERTS=1; shift;;
    --quiesce) QUIESCE=1; shift;;
    --leave-stopped) LEAVE_STOPPED=1; shift;;
    --config) CONFIG="$2"; shift 2;;
    -h|--help) awk 'NR>1 && /^#/ {sub(/^# ?/, ""); print; next} NR>1 {exit}' "$0"; exit 0;;
    *) die "unknown option: $1 (see --help)";;
  esac
done

[ -n "$ROOT" ] || [ "$(id -u)" -eq 0 ] || die "run as root (sudo): the hub's files belong to root and snhub"
case "$KEEP" in ''|*[!0-9]*) die "--keep wants a number";; esac
[ "$LEAVE_STOPPED" -eq 0 ] || [ "$QUIESCE" -eq 1 ] || die "--leave-stopped goes with --quiesce"

CFG="$(p "$CONFIG")"
[ -f "$CFG" ] || die "no hub config at $CFG (is this the master? use --config)"
conf() { sed -n "s/^$1[[:space:]]*=[[:space:]]*\"\\(.*\\)\"[[:space:]]*\$/\\1/p" "$CFG" | head -n 1; }
DATA_DIR="$(conf data_dir)"; DATA_DIR="${DATA_DIR:-/var/lib/snhub}"
PUBLIC_URL="$(conf public_url)"
DATA="$(p "$DATA_DIR")"
[ -f "$DATA/hub.key" ] || die "no hub key at $DATA/hub.key"
[ -f "$DATA/snhub.sqlite" ] || die "no database at $DATA/snhub.sqlite"

# ---- passphrase -------------------------------------------------------------
if [ "$ENCRYPT" -eq 1 ]; then
  command -v openssl >/dev/null 2>&1 || die "openssl is needed to encrypt (apt install openssl), or pass --plain"
  if [ -n "$PASS_FILE" ]; then
    [ -r "$PASS_FILE" ] || die "cannot read $PASS_FILE"
    SNHUB_BACKUP_PASSPHRASE="$(head -n 1 "$PASS_FILE")"
  fi
  if [ -z "${SNHUB_BACKUP_PASSPHRASE:-}" ]; then
    [ -t 0 ] || die "no passphrase: set SNHUB_BACKUP_PASSPHRASE or use --pass-file (nothing to ask on, no terminal)"
    read -rsp "Passphrase for the backup: " SNHUB_BACKUP_PASSPHRASE; echo
    read -rsp "Again: " again; echo
    [ "$SNHUB_BACKUP_PASSPHRASE" = "$again" ] || die "the two passphrases differ"
  fi
  [ "${#SNHUB_BACKUP_PASSPHRASE}" -ge 12 ] || die "use a passphrase of at least 12 characters"
  export SNHUB_BACKUP_PASSPHRASE
fi

# ---- stage ------------------------------------------------------------------
STAGE="$(mktemp -d)"
STOPPED=0
cleanup() {
  rm -rf "$STAGE"
  if [ "$STOPPED" -eq 1 ]; then svc start snhub || echo "!! snhub did not start again: systemctl status snhub" >&2; fi
}
trap cleanup EXIT
F="$STAGE/files"
mkdir -p "$F/data" "$F/etc/snhub" "$F/etc/systemd/system/snhub.service.d" "$F/etc/caddy"

cp -p "$CFG" "$F/etc/snhub/snhub.toml"
cp -p "$DATA/hub.key" "$F/data/hub.key"

# The database: a copy that is whole even while the hub writes. SQLite's backup
# call takes it live; --quiesce stops the hub and copies the files instead.
sql() { # sql DB "statement"  -> first column of the rows, one per line
  if command -v sqlite3 >/dev/null 2>&1; then
    sqlite3 "$1" "$2"
  elif command -v python3 >/dev/null 2>&1; then
    python3 - "$1" "$2" <<'PY'
import sqlite3, sys
c = sqlite3.connect(sys.argv[1])
for row in c.execute(sys.argv[2]):
    print(row[0])
PY
  else
    return 127
  fi
}
snapshot_live() { # snapshot_live SRC DST
  if command -v sqlite3 >/dev/null 2>&1; then
    sqlite3 "$1" ".timeout 60000" ".backup '$2'"
  elif command -v python3 >/dev/null 2>&1; then
    python3 - "$1" "$2" <<'PY'
import sqlite3, sys
src = sqlite3.connect(sys.argv[1], timeout=60)
dst = sqlite3.connect(sys.argv[2])
src.backup(dst)
dst.close()
src.close()
PY
  else
    return 127
  fi
}

DB_OUT="$F/data/snhub.sqlite"
if [ "$QUIESCE" -eq 1 ]; then
  say "stopping snhub for a moment (VPSes retry on their own)"
  if svc_on; then svc stop snhub; STOPPED=1; fi
  cp -p "$DATA/snhub.sqlite" "$DB_OUT"
  # A clean stop folds the log into the database; if a log is left, it goes along.
  if [ -s "$DATA/snhub.sqlite-wal" ]; then cp -p "$DATA/snhub.sqlite-wal" "$DB_OUT-wal"; fi
  if [ "$STOPPED" -eq 1 ]; then
    if [ "$LEAVE_STOPPED" -eq 1 ]; then
      # From here the hub stays down on purpose, whatever else goes wrong below.
      STOPPED=0
    else
      svc start snhub; STOPPED=0
    fi
  fi
else
  say "copying the database while the hub runs"
  snapshot_live "$DATA/snhub.sqlite" "$DB_OUT" \
    || die "need sqlite3 or python3 to copy a running database: install one, or use --quiesce"
fi

# Check the copy, not the original. A copy that does not check out is no backup.
AGENTS="?"
if sql "$DB_OUT" "select 1" >/dev/null 2>&1; then
  [ "$(sql "$DB_OUT" "pragma integrity_check" | head -n 1)" = "ok" ] || die "the database copy fails SQLite's own check; nothing was saved"
  AGENTS="$(sql "$DB_OUT" "select count(*) from agents" 2>/dev/null || echo '?')"
  rm -f "$DB_OUT-wal" "$DB_OUT-shm"
else
  echo "?? neither sqlite3 nor python3 here: the copy was not checked" >&2
fi

# Proxy and service settings.
[ -f "$(p /etc/caddy/Caddyfile)" ] && cp -p "$(p /etc/caddy/Caddyfile)" "$F/etc/caddy/Caddyfile"
[ -f "$(p /etc/systemd/system/snhub.service)" ] && cp -p "$(p /etc/systemd/system/snhub.service)" "$F/etc/systemd/system/snhub.service"
for d in "$(p /etc/systemd/system/snhub.service.d)"/*.conf; do
  [ -f "$d" ] && cp -p "$d" "$F/etc/systemd/system/snhub.service.d/"
done
if [ "$WITH_CERTS" -eq 1 ]; then
  CERTS="$(p /var/lib/caddy/.local/share/caddy)"
  if [ -d "$CERTS" ]; then
    mkdir -p "$F/caddy-data"
    cp -a "$CERTS/." "$F/caddy-data/"
  else
    echo "?? no Caddy certificates at $CERTS: skipped" >&2
  fi
fi

# ---- manifest ---------------------------------------------------------------
VERSION="$("$(p /usr/local/bin/snhub)" --version 2>/dev/null | awk '{print $2}' || true)"
{
  echo "format=snhub-backup-1"
  echo "created=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "host=$(hostname)"
  echo "snhub_version=${VERSION:-unknown}"
  echo "data_dir=$DATA_DIR"
  echo "public_url=$PUBLIC_URL"
  echo "agents=$AGENTS"
  echo "quiesced=$QUIESCE"
  echo "with_certs=$WITH_CERTS"
} > "$STAGE/MANIFEST"
( cd "$F" && find . -type f | LC_ALL=C sort | xargs -d '\n' sha256sum ) > "$STAGE/files.sha256"

# ---- pack, encrypt, rotate ----------------------------------------------------
STAMP="$(date +%Y%m%d-%H%M%S)"
EXT=".tar.gz"; [ "$ENCRYPT" -eq 1 ] && EXT=".tar.gz.enc"
if [ -z "$OUT" ]; then
  OUT_DIR="$(p "$OUT_DIR")"
  mkdir -p "$OUT_DIR"; chmod 700 "$OUT_DIR"
  OUT="$OUT_DIR/snhub-backup-$STAMP$EXT"
  ROTATE=1
else
  ROTATE=0
  if [ ! -d "$(dirname "$OUT")" ]; then mkdir -p "$(dirname "$OUT")"; chmod 700 "$(dirname "$OUT")"; fi
fi
PART="$OUT.partial"
if [ "$ENCRYPT" -eq 1 ]; then
  tar -C "$STAGE" -czf - MANIFEST files.sha256 files \
    | openssl enc -aes-256-cbc -pbkdf2 -iter 600000 -salt -pass env:SNHUB_BACKUP_PASSPHRASE -out "$PART"
else
  echo "?? --plain: this file holds the hub key and the AI keys, unencrypted" >&2
  tar -C "$STAGE" -czf "$PART" MANIFEST files.sha256 files
fi
chmod 600 "$PART"
mv "$PART" "$OUT"

if [ "$ROTATE" -eq 1 ] && [ "$KEEP" -gt 0 ]; then
  # shellcheck disable=SC2012
  ls -1t "$OUT_DIR"/snhub-backup-*.tar.gz* 2>/dev/null | tail -n +"$((KEEP + 1))" | xargs -r rm -f -- || true
fi

SIZE="$(du -h "$OUT" | cut -f1)"
SUM="$(sha256sum "$OUT" | cut -c1-16)"
echo
say "backup written: $OUT  ($SIZE, sha256 $SUM…)"
say "contains: config, hub key, database ($AGENTS VPS), Caddyfile and service settings$([ "$WITH_CERTS" -eq 1 ] && echo ', certificates')"
if [ "$ENCRYPT" -eq 1 ]; then
  say "encrypted. The passphrase is not stored anywhere: without it the file cannot be opened."
fi
echo "   Take it off this server, e.g. from your own computer:"
echo "     scp root@THIS-SERVER:$OUT ."
echo "   On the new server, after install-hub.sh:  sudo bash restore-hub.sh $(basename "$OUT") --caddy"
echo "   The offline root key is NOT in this file: keep it where it is."
if [ "$LEAVE_STOPPED" -eq 1 ]; then
  echo
  say "snhub is STOPPED on this server, on purpose. Move the file, restore it on the new server, point the"
  say "name there, then:  systemctl disable snhub   (to bring this one back instead:  systemctl start snhub)"
fi
