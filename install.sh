#!/usr/bin/env bash
# Kali NetWatch installer. Idempotent: existing configuration is backed up, never overwritten silently.
# Every system change is announced and needs confirmation. Run with: sudo ./install.sh
set -euo pipefail
PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$PROJECT_DIR/scripts/common.sh"

say "Kali NetWatch installer (source: $PROJECT_DIR, target: $INSTALL_DIR)"

# 1. Operating system and architecture -------------------------------------
[[ -r /etc/os-release ]] || die "cannot read /etc/os-release"
. /etc/os-release
case "${ID:-}${ID_LIKE:-}" in
  *kali*|*debian*) ;;
  *) warn "unsupported OS '${PRETTY_NAME:-unknown}'. Kali/Debian is expected."
     confirm "Continue anyway?" || exit 1 ;;
esac
ARCH="$(uname -m)"
if [[ "$ARCH" != "aarch64" ]]; then
  warn "architecture is $ARCH (target is ARM64 / aarch64)."
  confirm "Continue anyway?" || exit 1
fi
say "OS: ${PRETTY_NAME:-unknown}, arch: $ARCH"

# 2. Dependencies -----------------------------------------------------------
PY=""
for candidate in python3.13 python3.12 python3.11 python3; do
  if command -v "$candidate" >/dev/null 2>&1; then
    if "$candidate" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)' 2>/dev/null; then
      PY="$(command -v "$candidate")"; break
    fi
  fi
done
[[ -n "$PY" ]] || die "Python 3.11 or newer is required"
say "python: $PY ($("$PY" -V))"

MISSING=()
command -v nmap >/dev/null 2>&1 || MISSING+=(nmap)
command -v ip   >/dev/null 2>&1 || MISSING+=(iproute2)
"$PY" -m venv --help >/dev/null 2>&1 || MISSING+=(python3-venv)
command -v systemctl >/dev/null 2>&1 || die "systemd is required"
if (( ${#MISSING[@]} )); then
  warn "missing packages: ${MISSING[*]}"
  need_root_for "installing packages" "$@"
  if confirm "Install them now with apt-get?"; then
    apt-get update
    apt-get install -y "${MISSING[@]}"
  else
    die "cannot continue without: ${MISSING[*]}"
  fi
fi
say "dependencies present"

# 3. Privileges and service account ------------------------------------------
need_root_for "installation" "$@"
if ! id -u "$SERVICE_USER" >/dev/null 2>&1; then
  if confirm "Create the unprivileged service account '$SERVICE_USER'?" y; then
    useradd --system --home-dir "$DATA_DIR" --shell /usr/sbin/nologin --user-group "$SERVICE_USER"
  else
    die "a service account is required"
  fi
fi

# 4. Copy application and build a virtualenv (system Python is not modified) -----
if confirm "Copy the application to $INSTALL_DIR and (re)create its virtualenv?" y; then
  mkdir -p "$INSTALL_DIR"
  if command -v rsync >/dev/null 2>&1; then
    rsync -a --delete --exclude '.venv' --exclude 'data' --exclude '__pycache__' --exclude '.pytest_cache' \
      --exclude 'config/netwatch.toml' "$PROJECT_DIR/" "$INSTALL_DIR/"
  else
    cp -a "$PROJECT_DIR/." "$INSTALL_DIR/"
  fi
  [[ -d "$INSTALL_DIR/.venv" ]] || "$PY" -m venv "$INSTALL_DIR/.venv"
  "$INSTALL_DIR/.venv/bin/pip" install --quiet --upgrade pip
  "$INSTALL_DIR/.venv/bin/pip" install --quiet -r "$INSTALL_DIR/requirements.txt"
  # The package is run from $INSTALL_DIR (WorkingDirectory), not installed into site-packages,
  # so migrations/ and templates resolve next to the code. Remove any stale installed copy.
  "$INSTALL_DIR/.venv/bin/pip" uninstall -y --quiet kali-netwatch 2>/dev/null || true
  chown -R root:root "$INSTALL_DIR"
  chmod -R go-w "$INSTALL_DIR"
fi
say "application installed in $INSTALL_DIR"

# 5. Directories and configuration -------------------------------------------
install -d -m 0750 -o "$SERVICE_USER" -g "$SERVICE_USER" "$DATA_DIR"
install -d -m 0750 -o root -g "$SERVICE_USER" "$CONFIG_DIR"
if [[ ! -f "$CONFIG_FILE" ]]; then
  sed "s#^data_dir = .*#data_dir = \"$DATA_DIR\"#" "$INSTALL_DIR/config/netwatch.example.toml" > "$CONFIG_FILE"
  chown root:"$SERVICE_USER" "$CONFIG_FILE"; chmod 0640 "$CONFIG_FILE"
  say "wrote $CONFIG_FILE"
else
  say "keeping existing $CONFIG_FILE (not modified)"
fi
if [[ ! -f "$ENV_FILE" ]]; then
  sed "s#^NETWATCH_CONFIG=.*#NETWATCH_CONFIG=$CONFIG_FILE#; s#^NETWATCH_DATA_DIR=.*#NETWATCH_DATA_DIR=$DATA_DIR#" \
    "$INSTALL_DIR/.env.example" > "$ENV_FILE"
  chown root:"$SERVICE_USER" "$ENV_FILE"; chmod 0640 "$ENV_FILE"
  say "wrote $ENV_FILE (add Telegram secrets here later; never in the TOML file)"
else
  say "keeping existing $ENV_FILE (not modified)"
fi

# 6. Database and administrator --------------------------------------------
run_as_service() {
  runuser -u "$SERVICE_USER" -- env PYTHONPATH="$INSTALL_DIR" NETWATCH_CONFIG="$CONFIG_FILE" NETWATCH_DATA_DIR="$DATA_DIR" \
    "$INSTALL_DIR/.venv/bin/python" -m app.cli "$@"
}
run_as_service init-db
USER_COUNT="$(runuser -u "$SERVICE_USER" -- "$INSTALL_DIR/.venv/bin/python" -c \
  "import sqlite3,sys; c=sqlite3.connect(sys.argv[1]); print(c.execute('SELECT COUNT(*) FROM users').fetchone()[0])" \
  "$DATA_DIR/netwatch.db")"
if [[ "$USER_COUNT" == "0" ]]; then
  say "no administrator account exists yet"
  read -r -p "Administrator username [admin]: " ADMIN_USER
  ADMIN_USER="${ADMIN_USER:-admin}"
  while :; do
    read -r -s -p "Password (min 12 characters): " PW1; echo
    read -r -s -p "Repeat password: " PW2; echo
    [[ "$PW1" == "$PW2" ]] || { warn "passwords do not match"; continue; }
    (( ${#PW1} >= 12 )) || { warn "password too short"; continue; }
    break
  done
  printf '%s\n' "$PW1" | run_as_service create-user "$ADMIN_USER" --role admin --password-stdin
  unset PW1 PW2
else
  say "administrator account already exists; leaving users unchanged"
fi

# 7. systemd units and scheduling --------------------------------------------
if confirm "Install and enable systemd units (web + scheduler, start at boot)?" y; then
  for unit in "${UNITS[@]}"; do
    backup_if_exists "/etc/systemd/system/$unit"
    install -m 0644 "$INSTALL_DIR/systemd/$unit" "/etc/systemd/system/$unit"
  done
  systemctl daemon-reload
  systemctl enable --now "${UNITS[@]}"
  say "services enabled at boot"
else
  warn "services not installed; start manually with: $INSTALL_DIR/.venv/bin/python -m app.cli serve"
fi

# 8. Summary -------------------------------------------------------------------
sleep 3
say "service status:"
for unit in "${UNITS[@]}"; do
  printf '  %-34s %s\n' "$unit" "$(systemctl is-active "$unit" 2>/dev/null || echo unknown)"
done
if command -v curl >/dev/null 2>&1 && curl -fsS "http://127.0.0.1:$WEB_PORT/api/v1/health" >/dev/null 2>&1; then
  say "health check passed"
else
  warn "health check failed; see: journalctl -u kali-netwatch-web -n 50"
fi
cat <<MSG

Dashboard (this Pi only): http://127.0.0.1:$WEB_PORT/
API documentation:        http://127.0.0.1:$WEB_PORT/api/docs
Check the installation:   sudo runuser -u $SERVICE_USER -- env PYTHONPATH=$INSTALL_DIR NETWATCH_CONFIG=$CONFIG_FILE $INSTALL_DIR/.venv/bin/python -m app.cli doctor
Logs:                     journalctl -u kali-netwatch-web -u kali-netwatch-scheduler -f

Remote access: see README "Exposing the dashboard on the trusted LAN" before changing bind_host.
MSG
