#!/usr/bin/env bash
# GeDefense Retail - Linux uninstaller.
# Removes services and binaries; configuration and data are kept unless --purge.
# Usage: sudo ./uninstall.sh [--purge] [--prefix /opt/gedefense-retail]
set -euo pipefail

PREFIX="/opt/gedefense-retail"
PURGE=0
while [ $# -gt 0 ]; do
  case "$1" in
    --prefix) PREFIX="$2"; shift ;;
    --purge) PURGE=1 ;;
    -h|--help) sed -n '2,6p' "$0"; exit 0 ;;
    *) echo "uninstall: unknown argument $1" >&2; exit 2 ;;
  esac
  shift
done
if [ "$(id -u)" != "0" ]; then
  echo "uninstall: must run as root" >&2; exit 1
fi

if command -v systemctl >/dev/null 2>&1; then
  systemctl stop gedefense-retail.service 2>/dev/null || true
  systemctl stop gedefense-retailgate.service 2>/dev/null || true
  systemctl disable gedefense-retail.service 2>/dev/null || true
  systemctl disable gedefense-retailgate.service 2>/dev/null || true
  rm -f /etc/systemd/system/gedefense-retail.service /etc/systemd/system/gedefense-retailgate.service
  systemctl daemon-reload
fi
rm -rf "$PREFIX"
if [ "$PURGE" = "1" ]; then
  rm -rf /etc/gedefense-retail /var/lib/gedefense-retail /var/lib/gedefense-gate /var/log/gedefense-retail
  echo "uninstall: configuration, data and logs removed (--purge)"
else
  echo "uninstall: binaries removed; /etc/gedefense-retail and /var/lib/gedefense-* kept"
fi
