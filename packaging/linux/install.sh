#!/usr/bin/env bash
# GeDefense Retail - Linux installer (inside the release bundle).
#
# Installs the binaries, example configuration and systemd units. The
# refrigeration plant is never touched: this only installs the passive
# monitoring gateway and the optional access gate.
#
# Usage: sudo ./install.sh [--prefix /opt/gedefense-retail] [--no-systemd] [--start]
set -euo pipefail

BUNDLE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PREFIX="/opt/gedefense-retail"
ETC_DIR="/etc/gedefense-retail"
DATA_RETAIL="/var/lib/gedefense-retail"
DATA_GATE="/var/lib/gedefense-gate"
LOG_DIR="/var/log/gedefense-retail"
USE_SYSTEMD=1
START_SERVICES=0

while [ $# -gt 0 ]; do
  case "$1" in
    --prefix) PREFIX="$2"; shift ;;
    --no-systemd) USE_SYSTEMD=0 ;;
    --start) START_SERVICES=1 ;;
    -h|--help) sed -n '2,12p' "$0"; exit 0 ;;
    *) echo "install: unknown argument $1" >&2; exit 2 ;;
  esac
  shift
done

if [ "$(id -u)" != "0" ]; then
  echo "install: must run as root (sudo ./install.sh)" >&2
  exit 1
fi

ensure_user() {
  local user="$1"
  if ! id -u "$user" >/dev/null 2>&1; then
    useradd --system --home-dir "$PREFIX" --shell /usr/sbin/nologin "$user"
  fi
}

# Users must exist before the data directories are created with their ownership.
ensure_user gedefense
ensure_user gedefense-gate

install -d -m 0755 "$PREFIX" "$PREFIX/bin" "$PREFIX/config" "$PREFIX/docs"
install -m 0755 "$BUNDLE"/bin/retaild "$BUNDLE"/bin/retailgate "$BUNDLE"/bin/retail-sim "$PREFIX/bin/"
install -m 0644 "$BUNDLE"/LICENSE "$BUNDLE"/README.md "$BUNDLE"/THIRD-PARTY-NOTICES.md "$BUNDLE"/VERSION "$PREFIX/"
cp -r "$BUNDLE"/docs/. "$PREFIX/docs/"
install -d -m 0750 "$ETC_DIR"
for cfg in retail.example.json gate.example.json gate-policy.example.json; do
  if [ ! -f "$ETC_DIR/$cfg" ]; then
    install -m 0640 "$BUNDLE/config/$cfg" "$ETC_DIR/$cfg"
  fi
done
install -d -m 0750 -o gedefense -g gedefense "$DATA_RETAIL" "$LOG_DIR"
install -d -m 0750 -o gedefense-gate -g gedefense-gate "$DATA_GATE"

if [ "$USE_SYSTEMD" = "1" ] && command -v systemctl >/dev/null 2>&1; then
  install -m 0644 "$BUNDLE/config/gedefense-retail.service" /etc/systemd/system/
  install -m 0644 "$BUNDLE/config/gedefense-retailgate.service" /etc/systemd/system/
  systemctl daemon-reload
  systemctl enable gedefense-retail.service >/dev/null 2>&1 || true
  systemctl enable gedefense-retailgate.service >/dev/null 2>&1 || true
  if [ "$START_SERVICES" = "1" ]; then
    systemctl restart gedefense-retail.service
    systemctl restart gedefense-retailgate.service
  fi
fi

echo "GeDefense Retail installed under $PREFIX"
echo "Next steps:"
echo "  1) Edit $ETC_DIR/retail.example.json -> $ETC_DIR/retail.json (dashboard_whitelist_cidrs, site)"
echo "  2) Create an admin token: $PREFIX/bin/retaild gen-token --user admin --role admin"
echo "     Insert token_sha256 into users[] (never the plaintext token)."
echo "  3) Gate: configure $ETC_DIR/gate.json + gate-policy.json (hash-password/gen-totp)."
echo "  4) First start opens the dashboard setup wizard (security.setup_token_ttl_s, default 3600s)."
echo "  5) systemctl start gedefense-retail.service gedefense-retailgate.service"
echo "Uninstall: sudo ./uninstall.sh [--purge]  (keeps configuration/data by default)"
