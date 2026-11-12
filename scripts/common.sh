# shellcheck shell=bash
# Shared helpers for install/update/backup/restore/uninstall. Sourced, not executed.

APP_NAME="kali-netwatch"
INSTALL_DIR="${NETWATCH_INSTALL_DIR:-/opt/kali-netwatch}"
CONFIG_DIR="/etc/kali-netwatch"
CONFIG_FILE="$CONFIG_DIR/netwatch.toml"
ENV_FILE="$CONFIG_DIR/netwatch.env"
DATA_DIR="/var/lib/kali-netwatch"
SERVICE_USER="kalinetwatch"
UNITS=(kali-netwatch-web.service kali-netwatch-scheduler.service)
WEB_PORT=8787

say()  { printf '\033[1;36m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33mwarning:\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }

# confirm "question" [default: n]  -> returns 0 for yes
confirm() {
  local prompt="$1" default="${2:-n}" reply hint="[y/N]"
  [[ "$default" == "y" ]] && hint="[Y/n]"
  if [[ "${NETWATCH_ASSUME_YES:-0}" == "1" ]]; then
    [[ "$default" == "y" ]] && return 0 || return 1
  fi
  read -r -p "$prompt $hint " reply || reply=""
  reply="${reply:-$default}"
  [[ "$reply" =~ ^[Yy]([Ee][Ss])?$ ]]
}

need_root_for() {
  if [[ $EUID -ne 0 ]]; then
    die "$1 requires root. Re-run with: sudo $0 ${*:2}"
  fi
}

timestamp() { date -u +%Y%m%dT%H%M%SZ; }

# backup_if_exists PATH -> copies to PATH.bak-<timestamp> before any change
backup_if_exists() {
  if [[ -e "$1" ]]; then
    local dst="$1.bak-$(timestamp)"
    cp -a "$1" "$dst"
    say "kept existing $(basename "$1") as $(basename "$dst")"
  fi
}

sudo_run() {
  if [[ $EUID -eq 0 ]]; then "$@"; else sudo "$@"; fi
}
