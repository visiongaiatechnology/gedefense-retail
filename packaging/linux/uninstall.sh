#!/usr/bin/env bash
# GeDefense Retail - Linux uninstaller.
# Removes services and binaries; configuration and data are kept unless --purge.
# Refuses unsafe prefixes (FIND-006): absolute path, marker file, no symlink.
# Usage: sudo ./uninstall.sh [--purge] [--prefix /opt/gedefense-retail] [--dry-run]
set -euo pipefail

PREFIX="/opt/gedefense-retail"
PURGE=0
DRY_RUN=0
MARKER=".gedefense-retail-install"
while [ $# -gt 0 ]; do
  case "$1" in
    --prefix) PREFIX="$2"; shift ;;
    --purge) PURGE=1 ;;
    --dry-run) DRY_RUN=1 ;;
    -h|--help) sed -n '2,7p' "$0"; exit 0 ;;
    *) echo "uninstall: unknown argument $1" >&2; exit 2 ;;
  esac
  shift
done

# Validate before any filesystem mutation (FIND-006).
validate_prefix() {
  local raw="$1"
  case "$raw" in
    ""|/|/bin|/boot|/dev|/etc|/home|/lib|/lib64|/opt|/proc|/root|/run|/sbin|/srv|/sys|/tmp|/usr|/var)
      echo "uninstall: refusing unsafe prefix '$raw'" >&2; return 1 ;;
  esac
  case "$raw" in
    /*) ;;
    *) echo "uninstall: prefix must be an absolute path: '$raw'" >&2; return 1 ;;
  esac
  case "$raw" in
    *"/../"*|*"/..") echo "uninstall: prefix must not contain '..': '$raw'" >&2; return 1 ;;
  esac
  if [ -L "$raw" ]; then
    echo "uninstall: refusing symlink prefix '$raw'" >&2; return 1
  fi
  if [ ! -d "$raw" ]; then
    echo "uninstall: prefix '$raw' is not a directory" >&2; return 1
  fi
  if [ ! -f "$raw/$MARKER" ]; then
    echo "uninstall: '$raw' is not a GeDefense Retail installation (marker missing)" >&2; return 1
  fi
  return 0
}
validate_prefix "$PREFIX" || exit 2

if [ "$(id -u)" != "0" ]; then
  echo "uninstall: must run as root" >&2; exit 1
fi

run() {
  if [ "$DRY_RUN" = "1" ]; then echo "DRY-RUN: $*"; else "$@"; fi
}

if command -v systemctl >/dev/null 2>&1; then
  run systemctl stop gedefense-retail.service 2>/dev/null || true
  run systemctl stop gedefense-retailgate.service 2>/dev/null || true
  run systemctl disable gedefense-retail.service 2>/dev/null || true
  run systemctl disable gedefense-retailgate.service 2>/dev/null || true
  run rm -f /etc/systemd/system/gedefense-retail.service /etc/systemd/system/gedefense-retailgate.service
  run systemctl daemon-reload 2>/dev/null || true
fi
run rm -rf "$PREFIX"
if [ "$PURGE" = "1" ]; then
  for path in /etc/gedefense-retail /var/lib/gedefense-retail /var/lib/gedefense-gate /var/log/gedefense-retail; do
    case "$path" in /etc/gedefense-retail|/var/lib/gedefense-retail|/var/lib/gedefense-gate|/var/log/gedefense-retail) ;; *) exit 2 ;; esac
    run rm -rf "$path"
  done
  echo "uninstall: configuration, data and logs removed (--purge)"
else
  echo "uninstall: binaries removed; /etc/gedefense-retail and /var/lib/gedefense-* kept"
fi
