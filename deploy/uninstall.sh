#!/bin/sh
# Remove the SN Secure agent. Keeps /var/lib/sn (quarantine, state) unless
# --purge is given. Removes the firewall table and releases any cgroup jail.
# ClamAV, if the hub installed it, is left in place (see the note at the end).
set -eu

PURGE=0
[ "${1:-}" = "--purge" ] && PURGE=1

[ "$(id -u)" -eq 0 ] || { echo "run as root"; exit 1; }

systemctl disable --now sn-watch.timer sn-hunt.timer sn-clamav-update.timer 2>/dev/null || true
# Transient units the hub may have started (a scan, a ClamAV install).
systemctl stop sn-hunt-job.service sn-install-clamav.service sn-clamav-update.service 2>/dev/null || true
rm -f /etc/systemd/system/sn-watch.service /etc/systemd/system/sn-watch.timer \
      /etc/systemd/system/sn-hunt.service /etc/systemd/system/sn-hunt.timer \
      /etc/systemd/system/sn-clamav-update.service /etc/systemd/system/sn-clamav-update.timer
systemctl daemon-reload 2>/dev/null || true

# Undo live effects: remove the sn firewall table and release any jail.
if command -v sn >/dev/null 2>&1; then
  sn disable 2>/dev/null || true
fi

rm -f /usr/local/bin/sn
# The /usr/bin/sn link made by install.sh (only if it is still our symlink).
[ -L /usr/bin/sn ] && rm -f /usr/bin/sn

if [ "$PURGE" -eq 1 ]; then
  rm -rf /var/lib/sn /etc/sn
  echo "agent removed and purged (/var/lib/sn deleted)."
else
  echo "agent removed. State kept in /var/lib/sn (use --purge to delete)."
fi

if command -v clamscan >/dev/null 2>&1; then
  echo "note: ClamAV stays installed. Remove it with your package manager if you no longer want it"
  echo "      (apt purge clamav  /  dnf remove clamav clamav-update)."
fi
