#!/usr/bin/env bash
# Upgrades an installed Kali NetWatch from this source tree.
# Steps: backup -> copy code -> upgrade dependencies -> apply migrations -> restart -> health check.
# Configuration and data are never overwritten. Usage: sudo ./update.sh
set -euo pipefail
PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$PROJECT_DIR/scripts/common.sh"

[[ -x "$INSTALL_DIR/.venv/bin/python" ]] || die "not installed; run install.sh first"
need_root_for "update" "$@"
say "updating $INSTALL_DIR from $PROJECT_DIR"

if confirm "Create a backup before updating (recommended)?" y; then
  "$PROJECT_DIR/backup.sh" "/var/backups/kali-netwatch"
fi

if confirm "Stop services during the update?" y; then
  systemctl stop "${UNITS[@]}" || true
fi

if command -v rsync >/dev/null 2>&1; then
  rsync -a --delete --exclude '.venv' --exclude 'data' --exclude '__pycache__' --exclude '.pytest_cache' \
    --exclude 'config/netwatch.toml' "$PROJECT_DIR/" "$INSTALL_DIR/"
else
  cp -a "$PROJECT_DIR/." "$INSTALL_DIR/"
fi
"$INSTALL_DIR/.venv/bin/pip" install --quiet -r "$INSTALL_DIR/requirements.txt"
"$INSTALL_DIR/.venv/bin/pip" uninstall -y --quiet kali-netwatch 2>/dev/null || true
chown -R root:root "$INSTALL_DIR"; chmod -R go-w "$INSTALL_DIR"

say "applying database migrations"
runuser -u "$SERVICE_USER" -- env PYTHONPATH="$INSTALL_DIR" NETWATCH_CONFIG="$CONFIG_FILE" NETWATCH_DATA_DIR="$DATA_DIR" \
  "$INSTALL_DIR/.venv/bin/python" -m app.cli init-db

for unit in "${UNITS[@]}"; do
  backup_if_exists "/etc/systemd/system/$unit" >/dev/null 2>&1 || true
  install -m 0644 "$INSTALL_DIR/systemd/$unit" "/etc/systemd/system/$unit"
done
systemctl daemon-reload
systemctl start "${UNITS[@]}"
sleep 3
if command -v curl >/dev/null 2>&1 && curl -fsS "http://127.0.0.1:$WEB_PORT/api/v1/health" >/dev/null 2>&1; then
  say "update complete; health check passed"
else
  warn "update installed but health check failed. Roll back with: sudo ./restore.sh <backup> --restore-config"
  exit 1
fi
