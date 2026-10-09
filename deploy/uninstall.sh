#!/bin/sh
# Remove the SN Secure agent. Keeps /var/lib/sn (quarantine, state) unless
# --purge is given. Removes the firewall table and releases any cgroup jail.
set -eu

PURGE=0
[ "${1:-}" = "--purge" ] && PURGE=1

[ "$(id -u)" -eq 0 ] || { echo "run as root"; exit 1; }

systemctl disable --now sn-watch.timer sn-hunt.timer 2>/dev/null || true
rm -f /etc/systemd/system/sn-watch.service /etc/systemd/system/sn-watch.timer \
      /etc/systemd/system/sn-hunt.service /etc/systemd/system/sn-hunt.timer
systemctl daemon-reload 2>/dev/null || true

# Undo live effects: remove the sn firewall table and release any jail.
if command -v sn >/dev/null 2>&1; then
  sn disable 2>/dev/null || true
fi

rm -f /usr/local/bin/sn

if [ "$PURGE" -eq 1 ]; then
  rm -rf /var/lib/sn /etc/sn
  echo "agent removed and purged (/var/lib/sn deleted)."
else
  echo "agent removed. State kept in /var/lib/sn (use --purge to delete)."
fi
