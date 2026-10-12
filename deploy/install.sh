#!/bin/sh
# SN Secure agent installer. Generated install command comes from the hub UI:
#
#   curl -fsSL https://HUB/install.sh | sudo sh -s -- --hub https://HUB --name web-01
#
# It then asks on the terminal for the one-time enrollment token shown next to the
# command, so the token never sits in the process list or the sudo log. With no
# terminal (automation), pass it in the SN_ENROLL_TOKEN environment variable.
# `--token TOKEN` still works but every local user can read it while this runs.
#
# Downloads the sn binary from the hub (sha256-verified), detects the web server
# and logs, writes /etc/sn/agent.toml in OBSERVE mode, enrolls, and installs the
# watch + hunt timers. It never enables enforce — you do that from the hub once
# the baseline is tuned.
set -eu

HUB=""
NAME=""
TOKEN="${SN_ENROLL_TOKEN:-}"
# Handed to `sn enroll` alone, not to every command below.
unset SN_ENROLL_TOKEN
ARCH=""
UPGRADE=0

while [ $# -gt 0 ]; do
  case "$1" in
    --hub) HUB="$2"; shift 2;;
    --name) NAME="$2"; shift 2;;
    --token)
      TOKEN="$2"; shift 2
      echo "!! --token puts the token in the process list and the sudo log, readable by every local user." >&2
      echo "   Leave it out next time: the installer asks for it." >&2
      ;;
    --arch) ARCH="$2"; shift 2;;
    --upgrade) UPGRADE=1; shift;;
    # No longer needed: the hub decides what an installed agent does. Accepted so
    # older install commands keep working.
    --allow-clamav-install|--allow-remote-fix) shift;;
    *) echo "unknown arg: $1" >&2; exit 2;;
  esac
done

[ "$(id -u)" -eq 0 ] || { echo "run as root (sudo)"; exit 1; }
[ -n "$HUB" ] || { echo "--hub is required"; exit 1; }
if [ "$UPGRADE" -ne 1 ]; then
  [ -n "$NAME" ] || { echo "--name is required"; exit 1; }
  if [ -z "$TOKEN" ]; then
    # Under `curl | sh` stdin is the script itself: ask on the terminal.
    if ! (: </dev/tty) 2>/dev/null; then
      echo "no terminal to ask for the enrollment token: run the command in an interactive shell," >&2
      echo "or pass the token in the SN_ENROLL_TOKEN environment variable" >&2
      exit 1
    fi
    printf 'Enrollment token (shown on the hub next to this command): ' >/dev/tty
    read -r TOKEN </dev/tty || true
  fi
  TOKEN="$(printf '%s' "$TOKEN" | tr -d '[:space:]')"
  [ -n "$TOKEN" ] || { echo "no enrollment token given (type it when asked, or set SN_ENROLL_TOKEN)" >&2; exit 1; }
  case "$TOKEN" in
    *[!A-Za-z0-9_-]*) echo "that is not an enrollment token (paste only the token the hub shows)" >&2; exit 1;;
  esac
fi
HUB="${HUB%/}"

if [ -z "$ARCH" ]; then
  m="$(uname -m)"
  case "$m" in
    x86_64|amd64) ARCH=x86_64;;
    aarch64|arm64) ARCH=aarch64;;
    *) echo "unsupported arch: $m"; exit 1;;
  esac
fi

echo ">> SN Secure agent (arch=$ARCH, hub=$HUB)"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

# Evidence, reports and quarantined files are for root only. A `sn triage` run
# from a normal root shell before this installer leaves the directory 0755.
mkdir -p /var/lib/sn
chmod 0700 /var/lib/sn

# Download the agent binary from the hub, verify its sha256, install it.
install_binary() {
  echo ">> downloading agent binary"
  curl -fsSL "$HUB/sn/SHA256SUMS" -o "$TMP/SHA256SUMS"
  curl -fsSL "$HUB/sn/sn-$ARCH" -o "$TMP/sn"
  HASH="$(awk -v f="sn-$ARCH" '{n=$2; sub(/^\*/,"",n); if(n==f) print $1}' "$TMP/SHA256SUMS")"
  [ -n "$HASH" ] || { echo "no checksum for sn-$ARCH"; exit 1; }
  ( cd "$TMP" && echo "$HASH  sn" | sha256sum -c - >/dev/null ) \
    || { echo "checksum verification FAILED"; exit 1; }
  # Keep the previous binary so a bad upgrade can be rolled back.
  [ -x /usr/local/bin/sn ] && cp -f /usr/local/bin/sn /usr/local/bin/sn.bak
  install -m 0755 "$TMP/sn" /usr/local/bin/sn
  # RHEL-family sudo restricts PATH to secure_path (/sbin:/bin:/usr/sbin:/usr/bin),
  # which omits /usr/local/bin, so `sudo sn ...` would say "command not found".
  # Link it into /usr/bin (never replacing a real file someone put there).
  if [ ! -e /usr/bin/sn ] || [ -L /usr/bin/sn ]; then
    ln -sf /usr/local/bin/sn /usr/bin/sn
  fi
  echo ">> installed $(/usr/local/bin/sn --version)"
}

# --upgrade: replace the binary. Config, enrollment and timers are kept; the timers
# start the new binary on their next run, so no restart is needed. Small
# adjustments: the daily scan unit gets room for clamscan (it loads a >1 GB
# database), and the per-order `allow_*` switches of older versions are removed
# from the config (the hub decides now; see `[remote] hub_orders`).
if [ "$UPGRADE" -eq 1 ]; then
  install_binary
  if [ -f /etc/systemd/system/sn-hunt.service ] && grep -q '^MemoryMax=256M' /etc/systemd/system/sn-hunt.service; then
    sed -i 's/^MemoryMax=256M$/MemoryMax=2G/' /etc/systemd/system/sn-hunt.service
    systemctl daemon-reload || true
    echo ">> sn-hunt.service: memory cap raised to 2G (for ClamAV)"
  fi
  # Older configs carry one switch per order type, all off. They no longer do
  # anything; drop them so nobody reads them as a setting that still applies.
  if [ -f /etc/sn/agent.toml ]; then
    sed -i -E '/^(allow_mode_observe|allow_undo|allow_install_clamav|allow_evidence|allow_remediate)[[:space:]]*=/d' /etc/sn/agent.toml
  fi
  echo ">> upgraded. Rollback: cp /usr/local/bin/sn.bak /usr/local/bin/sn"
  exit 0
fi

# nftables is required for enforce; warn (don't fail) if missing.
if ! command -v nft >/dev/null 2>&1; then
  echo ">> nft not found; attempting install"
  if command -v apt-get >/dev/null 2>&1; then apt-get update -qq && apt-get install -y -qq nftables || true
  elif command -v dnf >/dev/null 2>&1; then dnf install -y -q nftables || true
  elif command -v yum >/dev/null 2>&1; then yum install -y -q nftables || true
  fi
fi
command -v nft >/dev/null 2>&1 || echo "!! nft still missing — watch will run report-only until installed"

# cgroup check (informational).
cg="$(stat -fc %T /sys/fs/cgroup 2>/dev/null || echo unknown)"
case "$cg" in
  cgroup2fs) echo ">> cgroup v2 detected";;
  tmpfs) echo ">> cgroup v1/hybrid detected (contain uses the v1 backend)";;
  *) echo "!! could not detect cgroup layout; contain may be limited";;
esac

install_binary

# --- config --------------------------------------------------------------------
# Access logs are NOT configured here. The agent works out, every cycle, which web
# server answers on :80/:443 and reads that server's logs (nginx, Apache,
# LiteSpeed; DirectAdmin, cPanel, aaPanel...). That is why the same agent works on
# every panel and keeps working after a web-server switch. `sn env` shows what it
# found; set `sources_mode = "manual"` plus [[watch.sources]] only for custom paths.
mkdir -p /etc/sn

ROOTS='["/home", "/var/www"]'
[ -d /www/wwwroot ] && ROOTS='["/home", "/var/www", "/www/wwwroot"]'

echo ">> writing /etc/sn/agent.toml (observe mode)"
umask 077
cat > /etc/sn/agent.toml <<EOF
# Written by install.sh. Mode starts at observe — switch to enforce from the hub
# after a few days, once would_ban looks clean.
[hub]
url         = "$HUB"
agent_id    = ""
agent_key   = ""
hub_pubkeys = []
root_pubkeys = []

[watch]
mode         = "observe"
k            = 5.0
min_requests = 120
trusted_proxies = ["cloudflare"]
cpu_alert_pct = 85.0
# auto = detect the web server's logs each cycle (recommended); manual = only the
# [[watch.sources]] listed in this file. A [[watch.sources]] table must come after
# every plain key of [watch]: keys placed below it belong to that entry.
sources_mode = "auto"

[fw]
whitelist = []
max_bans_per_cycle = 200
web_ports = [80, 443]

[hunt]
allowed_roots = $ROOTS
days = 7
max_file_mb = 5
clamav = "auto"

[remote]
# The hub decides what this agent does (bans, mode, scans, undo, evidence, ClamAV,
# incident response). Set to false to make this one VPS only report.
hub_orders = true
EOF
chmod 0600 /etc/sn/agent.toml

echo ">> enrolling with hub"
# The token goes in sn's environment, which only root can read, not in its
# arguments. An older sn only takes --token: it rejects this call as a usage
# error (exit 2) before contacting the hub, and gets the token the old way.
rc=0
SN_ENROLL_TOKEN="$TOKEN" /usr/local/bin/sn --config /etc/sn/agent.toml enroll --url "$HUB" --name "$NAME" 2>"$TMP/enroll.err" || rc=$?
case "$rc" in
  0) cat "$TMP/enroll.err" >&2;;
  2)
    echo "!! this sn takes the token only as an argument (visible in the process list)" >&2
    /usr/local/bin/sn --config /etc/sn/agent.toml enroll --url "$HUB" --name "$NAME" --token "$TOKEN"
    ;;
  *) cat "$TMP/enroll.err" >&2; exit "$rc";;
esac

# --- systemd units -----------------------------------------------------------
echo ">> installing systemd timers"
cat > /etc/systemd/system/sn-watch.service <<'EOF'
[Unit]
Description=SN Secure traffic watch (one cycle)
After=network.target nftables.service
Wants=nftables.service
[Service]
Type=oneshot
ExecStart=/usr/local/bin/sn watch
Nice=-5
IOSchedulingClass=best-effort
TimeoutStartSec=90
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=/var/lib/sn
ReadOnlyPaths=/etc/sn
PrivateTmp=yes
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK
CapabilityBoundingSet=CAP_NET_ADMIN CAP_DAC_READ_SEARCH CAP_SYS_PTRACE CAP_SYS_NICE CAP_KILL
MemoryMax=192M
[Install]
WantedBy=multi-user.target
EOF

cat > /etc/systemd/system/sn-watch.timer <<'EOF'
[Unit]
Description=SN Secure traffic watch timer
[Timer]
OnBootSec=2min
OnUnitActiveSec=5min
RandomizedDelaySec=30
AccuracySec=15s
[Install]
WantedBy=timers.target
EOF

cat > /etc/systemd/system/sn-hunt.service <<'EOF'
[Unit]
Description=SN Secure daily PHP web-shell hunt
After=network.target
[Service]
Type=oneshot
ExecStart=/usr/local/bin/sn hunt --days 1
Nice=15
IOSchedulingClass=idle
CPUQuota=40%
TimeoutStartSec=30min
NoNewPrivileges=yes
ProtectSystem=strict
ReadWritePaths=/var/lib/sn
ReadOnlyPaths=/etc/sn
PrivateTmp=yes
CapabilityBoundingSet=CAP_DAC_READ_SEARCH
MemoryMax=2G
[Install]
WantedBy=multi-user.target
EOF

cat > /etc/systemd/system/sn-hunt.timer <<'EOF'
[Unit]
Description=SN Secure daily hunt timer
[Timer]
OnCalendar=*-*-* 03:00:00
RandomizedDelaySec=1h
Persistent=true
[Install]
WantedBy=timers.target
EOF

systemctl daemon-reload
systemctl enable --now sn-watch.timer sn-hunt.timer

echo ">> running a first triage + watch cycle"
/usr/local/bin/sn triage || true
/usr/local/bin/sn watch || true

echo ">> access logs the agent detected (it re-detects every cycle):"
/usr/local/bin/sn --config /etc/sn/agent.toml env 2>/dev/null | sed -n '/^log sources/,$p' || true

cat <<EOF

================= SN Secure agent installed =================
Binary : /usr/local/bin/sn
Config : /etc/sn/agent.toml   (mode=observe)
Timers : sn-watch (5m), sn-hunt (03:00)

The VPS now appears on the hub and reports every cycle. It is in OBSERVE mode:
it bans nothing yet, only records would_ban. After a few days of clean
would_ban, switch it to enforce from the hub.

Emergency rescue (any time):   sn triage ; sn contain ; sn hunt
Undo everything:               sn undo
============================================================
EOF
