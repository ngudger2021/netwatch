#!/usr/bin/env bash
# Creates a consistent backup: SQLite online-backup copy + configuration (+ optional secrets).
# Usage: sudo ./backup.sh [DEST_DIR] [--include-secrets]
# The archive is written with mode 600 and a SHA-256 sidecar file.
set -euo pipefail
PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$PROJECT_DIR/scripts/common.sh"

DEST_DIR="/var/backups/kali-netwatch"
INCLUDE_SECRETS=0
for arg in "$@"; do
  case "$arg" in
    --include-secrets) INCLUDE_SECRETS=1 ;;
    -h|--help) sed -n '2,4p' "$0"; exit 0 ;;
    *) DEST_DIR="$arg" ;;
  esac
done

[[ -x "$INSTALL_DIR/.venv/bin/python" ]] || die "not installed in $INSTALL_DIR"
need_root_for "backup (to read the data directory)" "$@"
install -d -m 0700 "$DEST_DIR"

STAGE="$DATA_DIR/.backup-stage-$$"
install -d -m 0700 -o "$SERVICE_USER" -g "$SERVICE_USER" "$STAGE"
trap 'rm -rf "$STAGE"' EXIT

say "copying database with the SQLite backup API (safe while services run)"
runuser -u "$SERVICE_USER" -- env PYTHONPATH="$INSTALL_DIR" NETWATCH_CONFIG="$CONFIG_FILE" NETWATCH_DATA_DIR="$DATA_DIR" \
  "$INSTALL_DIR/.venv/bin/python" -m app.cli backup-db "$STAGE/netwatch.db"

mkdir -p "$STAGE/config"
cp -a "$CONFIG_FILE" "$STAGE/config/netwatch.toml"
if (( INCLUDE_SECRETS )); then
  warn "including $ENV_FILE: the archive then contains Telegram secrets"
  cp -a "$ENV_FILE" "$STAGE/config/netwatch.env"
else
  printf '# Secrets intentionally not included. Re-create from /etc/kali-netwatch/netwatch.env.\n' > "$STAGE/config/SECRETS-EXCLUDED.txt"
fi

ARCHIVE="$DEST_DIR/netwatch-backup-$(timestamp).tar.gz"
tar -C "$STAGE" -czf "$ARCHIVE" .
chmod 600 "$ARCHIVE"
( cd "$DEST_DIR" && sha256sum "$(basename "$ARCHIVE")" > "$(basename "$ARCHIVE").sha256" )
chmod 600 "$ARCHIVE.sha256"
say "backup written: $ARCHIVE"
say "checksum: $ARCHIVE.sha256"
