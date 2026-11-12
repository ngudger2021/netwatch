#!/usr/bin/env bash
# Removes services and application code. Asks before touching data, configuration or the service account.
# Usage: sudo ./uninstall.sh
set -euo pipefail
PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$PROJECT_DIR/scripts/common.sh"
need_root_for "uninstall" "$@"

say "Kali NetWatch uninstaller"
confirm "Stop and remove the services and the application in $INSTALL_DIR?" || exit 0

systemctl stop "${UNITS[@]}" 2>/dev/null || true
systemctl disable "${UNITS[@]}" 2>/dev/null || true
for unit in "${UNITS[@]}"; do rm -f "/etc/systemd/system/$unit"; done
systemctl daemon-reload
rm -rf "$INSTALL_DIR"
say "services and application removed"

if confirm "Preserve the database, reports and configuration? (recommended)" y; then
  say "kept: $DATA_DIR and $CONFIG_DIR. Reinstall later with install.sh to resume."
else
  if confirm "Create a final backup in /var/backups/kali-netwatch before deleting data?" y; then
    FINAL="/var/backups/kali-netwatch"
    install -d -m 0700 "$FINAL"
    if [[ -f "$DATA_DIR/netwatch.db" ]]; then
      runuser -u "$SERVICE_USER" -- python3 -c "import sqlite3,sys; s=sqlite3.connect(sys.argv[1]); d=sqlite3.connect(sys.argv[2]); s.backup(d); d.close(); s.close()" \
        "$DATA_DIR/netwatch.db" "$FINAL/final-netwatch-$(timestamp).db" 2>/dev/null || warn "could not create final database copy"
      chmod 600 "$FINAL"/final-netwatch-*.db 2>/dev/null || true
    fi
    [[ -f "$CONFIG_FILE" ]] && cp -a "$CONFIG_FILE" "$FINAL/final-netwatch-$(timestamp).toml"
    say "final copy in $FINAL"
  fi
  warn "deleting $DATA_DIR and $CONFIG_DIR"
  confirm "Permanently delete the database, scan history and configuration?" || exit 0
  rm -rf "$DATA_DIR" "$CONFIG_DIR"
  if id -u "$SERVICE_USER" >/dev/null 2>&1 && confirm "Remove the '$SERVICE_USER' service account?"; then
    userdel "$SERVICE_USER" 2>/dev/null || warn "could not remove $SERVICE_USER"
  fi
fi
say "uninstall finished"
