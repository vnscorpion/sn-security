#!/usr/bin/env bash
# Install fail2ban on the hub (master) and ban IPs that keep failing to sign in to
# the hub. The hub writes one line per wrong guess to its journal:
#     snhub-auth login-failed ip=203.0.113.9 method=password
# fail2ban reads that line from the snhub.service journal and blocks the address on
# ports 80/443 only (SSH is not touched).
#
#   curl -fsSL https://raw.githubusercontent.com/vnscorpion/sn-security/COMMIT/deploy/install-fail2ban.sh \
#       | sudo bash -s -- --ignoreip YOUR.OWN.IP
#
# Options:
#   --ignoreip "IP [IP...]"  addresses never banned (put YOUR OWN address here)
#   --maxretry N             wrong guesses before a ban (default 8)
#   --findtime 10m           window for those guesses (default 10m)
#   --bantime 1h             how long a ban lasts (default 1h)
#   --uninstall              remove the hub jail and filter (fail2ban itself stays)
#
# Needs the hub to be version 0.8.4 or newer (the log line is new).
set -eu

IGNOREIP=""
MAXRETRY=8
FINDTIME="10m"
BANTIME="1h"
UNINSTALL=0

while [ $# -gt 0 ]; do
  case "$1" in
    --ignoreip) IGNOREIP="$2"; shift 2;;
    --maxretry) MAXRETRY="$2"; shift 2;;
    --findtime) FINDTIME="$2"; shift 2;;
    --bantime) BANTIME="$2"; shift 2;;
    --uninstall) UNINSTALL=1; shift;;
    *) echo "unknown arg: $1" >&2; exit 2;;
  esac
done

[ "$(id -u)" -eq 0 ] || { echo "run as root (sudo)"; exit 1; }

FILTER=/etc/fail2ban/filter.d/snhub.conf
JAIL=/etc/fail2ban/jail.d/snhub.local

if [ "$UNINSTALL" -eq 1 ]; then
  rm -f "$FILTER" "$JAIL"
  command -v fail2ban-client >/dev/null 2>&1 && fail2ban-client reload || true
  echo "snhub jail removed."
  exit 0
fi

case "$MAXRETRY" in ''|*[!0-9]*) echo "--maxretry must be a number" >&2; exit 2;; esac
# Values end up in a config file: allow only what a time spec / address list needs.
case "$FINDTIME$BANTIME" in *[!0-9smhdw]*) echo "--findtime/--bantime look like 10m, 1h" >&2; exit 2;; esac
case "$IGNOREIP" in *[!0-9a-fA-F.:/\ ]*) echo "--ignoreip: addresses separated by spaces" >&2; exit 2;; esac

if ! command -v fail2ban-client >/dev/null 2>&1; then
  if command -v apt-get >/dev/null 2>&1; then
    DEBIAN_FRONTEND=noninteractive apt-get update -qq
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq fail2ban
  elif command -v dnf >/dev/null 2>&1; then
    dnf install -y -q fail2ban
  elif command -v yum >/dev/null 2>&1; then
    yum install -y -q fail2ban
  else
    echo "no apt/dnf/yum found: install fail2ban yourself, then re-run" >&2
    exit 1
  fi
fi

install -d /etc/fail2ban/filter.d /etc/fail2ban/jail.d

cat > "$FILTER" <<'EOF'
# SN Secure hub: one line per wrong sign-in guess.
[Definition]
failregex = snhub-auth login-failed ip=<HOST>
ignoreregex =
EOF

cat > "$JAIL" <<EOF
# SN Secure hub sign-in. Written by install-fail2ban.sh.
[snhub]
enabled   = true
filter    = snhub
backend   = systemd
journalmatch = _SYSTEMD_UNIT=snhub.service
port      = http,https
maxretry  = $MAXRETRY
findtime  = $FINDTIME
bantime   = $BANTIME
ignoreip  = 127.0.0.1/8 ::1 $IGNOREIP
EOF

# Prove the filter understands the line before relying on it.
SAMPLE='snhub-auth login-failed ip=203.0.113.9 method=password'
if command -v fail2ban-regex >/dev/null 2>&1; then
  fail2ban-regex "$SAMPLE" "$FILTER" | grep -E "Lines:" || true
fi

systemctl enable --now fail2ban >/dev/null 2>&1 || true
fail2ban-client reload >/dev/null 2>&1 || systemctl restart fail2ban
sleep 1

echo
fail2ban-client status snhub || { echo "jail did not start: check 'journalctl -u fail2ban -n 30'" >&2; exit 1; }
echo
echo "fail2ban is watching the hub sign-in: $MAXRETRY wrong guesses in $FINDTIME => banned for $BANTIME on ports 80/443."
echo "Your own address must be in --ignoreip, or a few typos will lock you out."
echo "Unban an address:  fail2ban-client set snhub unbanip ADDRESS"
echo "If the hub is behind Cloudflare, the address seen is Cloudflare's, so bans would hit the wrong"
echo "address: use Cloudflare's own rate limiting there instead, or make the proxy pass the real IP."
