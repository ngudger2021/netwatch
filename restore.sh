#!/usr/bin/env bash
# Restores a backup created by backup.sh. Services are stopped during the restore.
# Usage: sudo ./restore.sh ARCHIVE.tar.gz [--restore-config]
set -euo pipefail
PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$PROJECT_DIR/scripts/common.sh"

ARCHIVE="${1:-}"; shift || true
RESTORE_CONFIG=0
for arg in "$@"; do [[ "$arg" == "--restore-config" ]] && RESTORE_CONFIG=1; done
[[ -n "$ARCHIVE" && -f "$ARCHIVE" ]] || die "usage: sudo $0 ARCHIVE.tar.gz [--restore-config]"
need_root_for "restore" "$@"

if [[ -f "$ARCHIVE.sha256" ]]; then
  say "verifying checksum"
  ( cd "$(dirname "$ARCHIVE")" && sha256sum -c "$(basename "$ARCHIVE").sha256" ) || die "checksum mismatch; refusing to restore"
else
  warn "no .sha256 file next to the archive; integrity cannot be verified"
  confirm "Continue without checksum verification?" || exit 1
fi

STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT
tar -C "$STAGE" -xzf "$ARCHIVE"
[[ -f "$STAGE/netwatch.db" ]] || die "archive does not contain netwatch.db"
chmod 0644 "$STAGE/netwatch.db"

warn "this replaces the current database (a copy of it is kept as netwatch.db.pre-restore-*)"
confirm "Stop the services and restore from $(basename "$ARCHIVE")?" || exit 1

systemctl stop "${UNITS[@]}" 2>/dev/null || true
install -o "$SERVICE_USER" -g "$SERVICE_USER" -m 0600 "$STAGE/netwatch.db" "$DATA_DIR/.restore-candidate.db"
runuser -u "$SERVICE_USER" -- env PYTHONPATH="$INSTALL_DIR" NETWATCH_CONFIG="$CONFIG_FILE" NETWATCH_DATA_DIR="$DATA_DIR" \
  "$INSTALL_DIR/.venv/bin/python" -m app.cli restore-db "$DATA_DIR/.restore-candidate.db"
rm -f "$DATA_DIR/.restore-candidate.db"

if (( RESTORE_CONFIG )) && [[ -f "$STAGE/config/netwatch.toml" ]]; then
  backup_if_exists "$CONFIG_FILE"
  install -o root -g "$SERVICE_USER" -m 0640 "$STAGE/config/netwatch.toml" "$CONFIG_FILE"
  say "configuration restored"
fi

systemctl start "${UNITS[@]}"
sleep 3
if command -v curl >/dev/null 2>&1 && curl -fsS "http://127.0.0.1:$WEB_PORT/api/v1/health" >/dev/null 2>&1; then
  say "restore complete; health check passed"
else
  warn "restore complete but health check failed: journalctl -u kali-netwatch-web -n 50"
fi
