#!/usr/bin/env bash
# Round trip of backup-hub.sh and restore-hub.sh on a made-up server tree (no root,
# no systemd): the data comes back whole, and the wrong passphrase, a damaged file
# and an older snhub are refused.
#
#   bash deploy/tests/hub-backup-restore.sh
set -euo pipefail

HERE="$(cd "$(dirname "$0")/.." && pwd)"
W="$(mktemp -d)"
trap 'rm -rf "$W"' EXIT
export SNHUB_BACKUP_PASSPHRASE="correct horse battery staple"

fail() { echo "FAIL: $*" >&2; exit 1; }
ok() { echo "ok: $*"; }

# A server: config, key, a database in WAL mode with a few VPSes, a Caddyfile, a drop-in.
mkserver() { # mkserver ROOT VERSION
  local r="$1" v="$2"
  mkdir -p "$r/etc/snhub" "$r/var/lib/snhub/public" "$r/usr/local/bin" "$r/etc/caddy" \
           "$r/etc/systemd/system/snhub.service.d"
  printf 'bind = "127.0.0.1:8099"\ndata_dir = "/var/lib/snhub"\npublic_url = "https://hub.example.test"\ntwo_factor = true\n' > "$r/etc/snhub/snhub.toml"
  printf '#!/bin/sh\necho "snhub %s"\n' "$v" > "$r/usr/local/bin/snhub"; chmod +x "$r/usr/local/bin/snhub"
}
mkdata() { # mkdata ROOT  (the "live" master)
  local r="$1"
  head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n' > "$r/var/lib/snhub/hub.key"
  cat > "$r/etc/caddy/Caddyfile" <<'CF'
:80 {
	respond "stock"
}
hub.example.test {
	encode zstd gzip
	handle /v1/* {
		reverse_proxy 127.0.0.1:8099 {
			header_up X-Real-IP {remote_host}
		}
	}
	header {
		-Server
	}
}
other.example.test {
	respond "not the hub"
}
CF
  for h in hub.example.test other.example.test; do d="$r/var/lib/caddy/.local/share/caddy/certificates/acme-v02.api.letsencrypt.org-directory/$h"; mkdir -p "$d"; echo "cert of $h" > "$d/$h.crt"; done
  printf '[Service]\nUMask=0077\n' > "$r/etc/systemd/system/snhub.service.d/10-hardening.conf"
  python3 - "$r/var/lib/snhub/snhub.sqlite" <<'PY'
import sqlite3, sys
c = sqlite3.connect(sys.argv[1])
c.execute("pragma journal_mode=wal")
c.execute("create table agents (id text primary key, name text)")
c.execute("create table ai_providers (id integer primary key, name text, api_key text)")
c.executemany("insert into agents values (?,?)", [("a1", "panel1"), ("a2", "duc122"), ("a3", "vm09")])
c.execute("insert into ai_providers values (1, 'Hermes', 'sk-secret-123')")
c.commit()
# Leave the hub "running": an open connection with a write the log still holds.
c.execute("insert into agents values ('a4', 'late')")
c.commit()
open(sys.argv[1] + ".keep", "w").write("x")
PY
  rm -f "$r/var/lib/snhub/snhub.sqlite.keep"
}
count() { python3 -c "import sqlite3,sys;print(sqlite3.connect(sys.argv[1]).execute('select count(*) from agents').fetchone()[0])" "$1"; }

# ---- the master, and a backup of it -------------------------------------------
OLD="$W/old"; mkserver "$OLD" 0.10.8; mkdata "$OLD"
BK="$W/backups"
SNHUB_ROOT="$OLD" bash "$HERE/backup-hub.sh" --out "$BK/one.tar.gz.enc" >/dev/null || fail "backup"
[ "$(head -c 8 "$BK/one.tar.gz.enc")" = "Salted__" ] || fail "the backup is not encrypted"
[ "$(stat -c %a "$BK/one.tar.gz.enc")" = "600" ] || fail "the backup is not private (0600)"
grep -q "sk-secret-123" "$BK/one.tar.gz.enc" && fail "an AI key is readable in the encrypted file"
ok "backup written, encrypted, private"

# The default folder with rotation: three runs, keep two.
for _ in 1 2 3; do sleep 1; SNHUB_ROOT="$OLD" bash "$HERE/backup-hub.sh" --keep 2 >/dev/null; done
[ "$(ls "$OLD/var/backups/snhub" | wc -l)" = "2" ] || fail "rotation: $(ls "$OLD/var/backups/snhub")"
ok "rotation keeps the newest 2"

SNHUB_ROOT="$OLD" bash "$HERE/backup-hub.sh" --out "$BK/q.tar.gz.enc" --quiesce >/dev/null || fail "quiesced backup"
ok "quiesced backup"
# What the service sees: a systemctl that only writes down what it is asked.
printf '#!/bin/sh\necho "$@" >> "%s/systemctl.log"\n' "$W" > "$W/fake-systemctl"; chmod +x "$W/fake-systemctl"
run_logged() { : > "$W/systemctl.log"; SNHUB_SYSTEMCTL="$W/fake-systemctl" SNHUB_ROOT="$OLD" bash "$HERE/backup-hub.sh" "$@" >/dev/null 2>&1; }
run_logged --out "$BK/live.tar.gz.enc" || fail "live backup"
[ ! -s "$W/systemctl.log" ] || fail "an online backup touched the service: $(cat "$W/systemctl.log")"
run_logged --out "$BK/q2.tar.gz.enc" --quiesce || fail "quiesce"
[ "$(tr '\n' ',' < "$W/systemctl.log")" = "stop snhub,start snhub," ] || fail "--quiesce: $(cat "$W/systemctl.log")"
run_logged --out "$BK/final.tar.gz.enc" --quiesce --leave-stopped || fail "leave-stopped"
[ "$(tr '\n' ',' < "$W/systemctl.log")" = "stop snhub," ] || fail "--leave-stopped: $(cat "$W/systemctl.log")"
run_logged --out "$BK/x.enc" --leave-stopped && fail "--leave-stopped without --quiesce was accepted"
ok "the service: untouched online, stop+start with --quiesce, stays stopped with --leave-stopped"

SNHUB_ROOT="$OLD" bash "$HERE/backup-hub.sh" --out "$BK/plain.tar.gz" --plain >/dev/null 2>&1 || fail "plain backup"
[ "$(head -c 2 "$BK/plain.tar.gz" | od -An -tx1 | tr -d ' ')" = "1f8b" ] || fail "plain backup is not a tar.gz"
ok "plain backup (only with --plain)"

# No passphrase and no terminal: refused, nothing written.
( unset SNHUB_BACKUP_PASSPHRASE; SNHUB_ROOT="$OLD" bash "$HERE/backup-hub.sh" --out "$BK/none.enc" </dev/null >/dev/null 2>&1 ) && fail "a backup was made without a passphrase"
[ ! -e "$BK/none.enc" ] || fail "a file was left behind"
ok "no passphrase, no backup"

# ---- a new server, freshly installed, and the restore --------------------------
NEW="$W/new"; mkserver "$NEW" 0.10.8
printf 'fresh-install-key' > "$NEW/var/lib/snhub/hub.key"
python3 -c "import sqlite3,sys;c=sqlite3.connect(sys.argv[1]);c.execute('create table agents (id text, name text)');c.commit()" "$NEW/var/lib/snhub/snhub.sqlite"
printf ':80 {\n\trespond "fresh"\n}\n' > "$W/fresh.Caddyfile"
cp "$W/fresh.Caddyfile" "$NEW/etc/caddy/Caddyfile"

# The wrong passphrase.
( SNHUB_BACKUP_PASSPHRASE="not the right one at all" SNHUB_ROOT="$NEW" bash "$HERE/restore-hub.sh" "$BK/one.tar.gz.enc" >/dev/null 2>&1 ) && fail "restored with a wrong passphrase"
[ "$(cat "$NEW/var/lib/snhub/hub.key")" = "fresh-install-key" ] || fail "a wrong passphrase touched the files"
ok "wrong passphrase refused, nothing touched"

# A damaged file.
cp "$BK/one.tar.gz.enc" "$BK/bad.enc"; printf '\377' | dd of="$BK/bad.enc" bs=1 seek=300 conv=notrunc 2>/dev/null
( SNHUB_ROOT="$NEW" bash "$HERE/restore-hub.sh" "$BK/bad.enc" >/dev/null 2>&1 ) && fail "restored a damaged file"
[ "$(cat "$NEW/var/lib/snhub/hub.key")" = "fresh-install-key" ] || fail "a damaged file touched the files"
ok "damaged file refused, nothing touched"

# An older snhub than the backup's.
OLDER="$W/older"; mkserver "$OLDER" 0.10.7
( SNHUB_ROOT="$OLDER" bash "$HERE/restore-hub.sh" "$BK/one.tar.gz.enc" >/dev/null 2>&1 ) && fail "restored onto an older snhub"
ok "older snhub refused"

# The real restore.
SNHUB_ROOT="$NEW" bash "$HERE/restore-hub.sh" "$BK/one.tar.gz.enc" --caddy > "$W/restore.log" 2>&1 || { cat "$W/restore.log"; fail "restore"; }
cmp "$OLD/var/lib/snhub/hub.key" "$NEW/var/lib/snhub/hub.key" || fail "hub key differs"
cmp "$OLD/etc/snhub/snhub.toml" "$NEW/etc/snhub/snhub.toml" || fail "config differs"
cmp "$OLD/etc/caddy/Caddyfile" "$NEW/etc/caddy/Caddyfile" || fail "Caddyfile differs"
cmp "$OLD/etc/systemd/system/snhub.service.d/10-hardening.conf" "$NEW/etc/systemd/system/snhub.service.d/10-hardening.conf" || fail "drop-in differs"
[ "$(count "$NEW/var/lib/snhub/snhub.sqlite")" = "4" ] || fail "the database lost rows (the one still in the log too?)"
[ "$(python3 -c "import sqlite3,sys;print(sqlite3.connect(sys.argv[1]).execute('select api_key from ai_providers').fetchone()[0])" "$NEW/var/lib/snhub/snhub.sqlite")" = "sk-secret-123" ] || fail "the AI key is gone"
[ "$(stat -c %a "$NEW/var/lib/snhub/snhub.sqlite")" = "600" ] || fail "database mode"
[ "$(stat -c %a "$NEW/var/lib/snhub/hub.key")" = "640" ] || fail "hub key mode"
SAVED="$(ls -d "$NEW"/var/lib/snhub.before-restore-* | head -n 1)"
[ "$(cat "$SAVED/hub.key")" = "fresh-install-key" ] || fail "the fresh install's key was not kept"
cmp "$W/fresh.Caddyfile" "$NEW/etc/caddy/Caddyfile.before-restore" || fail "the old Caddyfile was not kept"
grep -q "hub.example.test" "$W/restore.log" || fail "the closing notes do not name the hub address"
ok "restore: key, config, Caddyfile, drop-in, database (4 VPS, AI key) in place; the old files kept"

# The quiesced and the plain backups restore too.
for f in q.tar.gz.enc plain.tar.gz; do
  N2="$W/new-$f"; mkserver "$N2" 0.10.8
  SNHUB_ROOT="$N2" bash "$HERE/restore-hub.sh" "$BK/$f" >/dev/null 2>&1 || fail "restore of $f"
  [ "$(count "$N2/var/lib/snhub/snhub.sqlite")" = "4" ] || fail "$f lost rows"
done
ok "the quiesced and the plain backup restore as well"

# ---- a server whose Caddy serves other sites too ---------------------------------
SNHUB_ROOT="$OLD" bash "$HERE/backup-hub.sh" --out "$BK/certs.tar.gz.enc" --with-certs >/dev/null || fail "backup with certificates"
shared() { # shared ROOT : a server with a Caddyfile of other people's sites
  mkserver "$1" 0.10.8
  cat > "$1/etc/caddy/Caddyfile" <<'CF'
:80 {
	respond "stock"
}
router.example.test {
	reverse_proxy 127.0.0.1:20128
}
chat.example.test {
	reverse_proxy localhost:18080 {
		header_up Upgrade {http.request.header.Upgrade}
	}
}
CF
  printf 'fresh-install-key' > "$1/var/lib/snhub/hub.key"
}
SH="$W/shared"; shared "$SH"; cp "$SH/etc/caddy/Caddyfile" "$W/shared.Caddyfile"

# --caddy would replace the file and take the other sites down: refused, and nothing at all is changed.
( SNHUB_ROOT="$SH" bash "$HERE/restore-hub.sh" "$BK/certs.tar.gz.enc" --caddy >"$W/refuse.log" 2>&1 ) && fail "--caddy overwrote a Caddyfile that serves other sites"
grep -q "router.example.test" "$W/refuse.log" || fail "the refusal does not name the sites it would take down: $(cat "$W/refuse.log")"
cmp "$W/shared.Caddyfile" "$SH/etc/caddy/Caddyfile" || fail "a refused --caddy changed the Caddyfile"
[ "$(cat "$SH/var/lib/snhub/hub.key")" = "fresh-install-key" ] || fail "a refused --caddy changed the hub's files"
( SNHUB_ROOT="$SH" bash "$HERE/restore-hub.sh" "$BK/certs.tar.gz.enc" --caddy --caddy-add >/dev/null 2>&1 ) && fail "--caddy with --caddy-add was accepted"
ok "--caddy refuses a Caddyfile that serves other sites, before touching anything"

# Without either flag the Caddyfile is not touched.
SNHUB_ROOT="$SH" bash "$HERE/restore-hub.sh" "$BK/certs.tar.gz.enc" >/dev/null 2>&1 || fail "restore without a Caddy flag"
cmp "$W/shared.Caddyfile" "$SH/etc/caddy/Caddyfile" || fail "a restore without a Caddy flag changed the Caddyfile"

# --caddy-add: the other sites stay, the hub's block (and only its) is added once, with its certificate.
SNHUB_ROOT="$SH" bash "$HERE/restore-hub.sh" "$BK/certs.tar.gz.enc" --caddy-add >"$W/add.log" 2>&1 || { cat "$W/add.log"; fail "--caddy-add"; }
C="$SH/etc/caddy/Caddyfile"
grep -q '^router.example.test {' "$C" && grep -q '^chat.example.test {' "$C" || fail "--caddy-add lost a site that was there"
[ "$(grep -c '^hub.example.test {' "$C")" = 1 ] || fail "the hub's block is not there exactly once"
grep -q 'header_up X-Real-IP {remote_host}' "$C" || fail "the hub's block is cut short (nested blocks)"
grep -q 'other.example.test' "$C" && fail "--caddy-add also copied another site of the master's Caddyfile"
cmp "$W/shared.Caddyfile" "$C.before-restore" || fail "the Caddyfile as it was is not kept"
CERTS="$SH/var/lib/caddy/.local/share/caddy/certificates/acme-v02.api.letsencrypt.org-directory"
[ -f "$CERTS/hub.example.test/hub.example.test.crt" ] || fail "the hub's certificate was not restored"
[ ! -e "$CERTS/other.example.test" ] || fail "another site's certificate was restored"
# Again: nothing is added twice.
SNHUB_ROOT="$SH" bash "$HERE/restore-hub.sh" "$BK/certs.tar.gz.enc" --caddy-add >/dev/null 2>&1 || fail "--caddy-add the second time"
[ "$(grep -c '^hub.example.test {' "$C")" = 1 ] || fail "--caddy-add added the block twice"
ok "--caddy-add: the other sites stay, the hub's block and certificate come once"

# A server with no Caddyfile yet gets one with just the hub's block.
SN="$W/nocaddy"; mkserver "$SN" 0.10.8; rm -f "$SN/etc/caddy/Caddyfile"
SNHUB_ROOT="$SN" bash "$HERE/restore-hub.sh" "$BK/one.tar.gz.enc" --caddy-add >/dev/null 2>&1 || fail "--caddy-add without a Caddyfile"
grep -q '^hub.example.test {' "$SN/etc/caddy/Caddyfile" || fail "no Caddyfile with the hub's block"
ok "--caddy-add on a server with no Caddyfile"
echo "all good"
