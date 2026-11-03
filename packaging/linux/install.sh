#!/usr/bin/env bash
# GeDefense Retail - Linux installer (inside the release bundle).
#
# Installs binaries, example configuration, systemd units, the service users/
# groups and hardened ownership/permissions (FIND-002). The refrigeration plant
# is never touched: this only installs the passive monitoring gateway and the
# optional access gate.
#
# Usage: sudo ./install.sh [--prefix /opt/gedefense-retail] [--no-systemd] [--start]
set -euo pipefail

BUNDLE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PREFIX="/opt/gedefense-retail"
ETC_DIR="/etc/gedefense-retail"
DATA_RETAIL="/var/lib/gedefense-retail"
DATA_GATE="/var/lib/gedefense-gate"
LOG_DIR="/var/log/gedefense-retail"
UNIT_DIR="/etc/systemd/system"
USE_SYSTEMD=1
START_SERVICES=0
MARKER=".gedefense-retail-install"

while [ $# -gt 0 ]; do
  case "$1" in
    --prefix) PREFIX="$2"; shift ;;
    --no-systemd) USE_SYSTEMD=0 ;;
    --start) START_SERVICES=1 ;;
    -h|--help) sed -n '2,14p' "$0"; exit 0 ;;
    *) echo "install: unknown argument $1" >&2; exit 2 ;;
  esac
  shift
done

if [ "$(id -u)" != "0" ]; then
  echo "install: must run as root (sudo ./install.sh)" >&2
  exit 1
fi
case "$PREFIX" in
  /|/bin|/boot|/dev|/etc|/home|/lib|/lib64|/opt|/proc|/root|/run|/sbin|/srv|/sys|/tmp|/usr|/var)
    echo "install: refusing unsafe --prefix '$PREFIX'" >&2; exit 2 ;;
esac
if [ -L "$PREFIX" ]; then
  echo "install: refusing symlink --prefix '$PREFIX'" >&2; exit 2
fi

ensure_group() {
  getent group "$1" >/dev/null 2>&1 || groupadd --system "$1"
}
ensure_user() {
  local user="$1"
  if ! id -u "$user" >/dev/null 2>&1; then
    useradd --system --user-group --home-dir "$PREFIX" --shell /usr/sbin/nologin "$user"
  fi
  # The service user must be member of its own group; units use User= and Group=.
  usermod -a -G "$user" "$user" >/dev/null 2>&1 || true
}

# Users/groups must exist before directories are created with their ownership.
ensure_user gedefense
ensure_user gedefense-gate
ensure_group gedefense
ensure_group gedefense-gate

# --- install files -----------------------------------------------------------
install -d -m 0755 "$PREFIX" "$PREFIX/bin" "$PREFIX/config" "$PREFIX/docs"
install -m 0755 "$BUNDLE"/bin/retaild "$BUNDLE"/bin/retailgate "$BUNDLE"/bin/retail-sim "$PREFIX/bin/"
install -m 0644 "$BUNDLE"/LICENSE "$BUNDLE"/README.md "$BUNDLE"/THIRD-PARTY-NOTICES.md "$BUNDLE"/VERSION "$PREFIX/"
cp -r "$BUNDLE"/docs/. "$PREFIX/docs/"
printf 'version=%s\ninstalled_at=%s\n' "$(tr -d ' \r\n' < "$BUNDLE/VERSION")" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" > "$PREFIX/$MARKER"
chmod 0644 "$PREFIX/$MARKER"

# --- configuration: root:gedefense 0750, files root:gedefense 0640 -----------
install -d -m 0750 -o root -g gedefense "$ETC_DIR"
for cfg in retail.example.json gate.example.json gate-policy.example.json; do
  if [ ! -f "$ETC_DIR/$cfg" ]; then
    install -m 0640 -o root -g gedefense "$BUNDLE/config/$cfg" "$ETC_DIR/$cfg"
  fi
done
chown root:gedefense "$ETC_DIR" 2>/dev/null || true
chmod 0750 "$ETC_DIR"
find "$ETC_DIR" -maxdepth 1 -type f -name '*.json' -exec chown root:gedefense {} + -exec chmod 0640 {} +
# Fail closed: the service users must be able to read their configuration.
for cfg in retail.example.json gate.example.json gate-policy.example.json; do
  [ -f "$ETC_DIR/$cfg" ] || continue
  runuser -u gedefense -- test -r "$ETC_DIR/$cfg" 2>/dev/null || \
    runuser -u gedefense-gate -- test -r "$ETC_DIR/$cfg" 2>/dev/null || {
      echo "install: configuration $ETC_DIR/$cfg is not readable by the service user" >&2; exit 1; }
done
if [ -f "$ETC_DIR/retail.json" ]; then
  runuser -u gedefense -- "$PREFIX/bin/retaild" check --config "$ETC_DIR/retail.json" >/dev/null || {
    echo "install: retaild check failed for $ETC_DIR/retail.json" >&2; exit 1; }
fi

# --- data: owned by the service user, mode 0700 (FIND-002) -------------------
install -d -m 0700 -o gedefense -g gedefense "$DATA_RETAIL"
install -d -m 0700 -o gedefense-gate -g gedefense-gate "$DATA_GATE"
install -d -m 0750 -o gedefense -g gedefense "$LOG_DIR"
chown -R gedefense:gedefense "$DATA_RETAIL" "$LOG_DIR"
chown -R gedefense-gate:gedefense-gate "$DATA_GATE"
chmod 0700 "$DATA_RETAIL" "$DATA_GATE"
chmod 0750 "$LOG_DIR"

# --- systemd units -----------------------------------------------------------
if [ "$USE_SYSTEMD" = "1" ] && command -v systemctl >/dev/null 2>&1; then
  install -d -m 0755 "$UNIT_DIR"
  install -m 0644 "$BUNDLE/config/gedefense-retail.service" "$UNIT_DIR/"
  install -m 0644 "$BUNDLE/config/gedefense-retailgate.service" "$UNIT_DIR/"
  systemctl daemon-reload
  systemctl enable gedefense-retail.service >/dev/null 2>&1 || true
  systemctl enable gedefense-retailgate.service >/dev/null 2>&1 || true
  if [ "$START_SERVICES" = "1" ]; then
    systemctl restart gedefense-retail.service
    systemctl restart gedefense-retailgate.service
  fi
fi

echo "GeDefense Retail installed under $PREFIX (hardened ownership/permissions)"
echo "Next steps:"
echo "  1) Edit $ETC_DIR/retail.example.json -> $ETC_DIR/retail.json (keep root:gedefense 0640)"
echo "  2) Create an admin token: $PREFIX/bin/retaild token rotate --user admin --role admin"
echo "     Insert token_sha256 into users[] (never the plaintext token), then restart retaild."
echo "  3) Gate: configure $ETC_DIR/gate.json + gate-policy.json (hash-password/gen-totp)."
echo "  4) First start opens the dashboard setup wizard (security.setup_token_ttl_s, default 3600s)."
echo "  5) systemctl start gedefense-retail.service gedefense-retailgate.service"
echo "Uninstall: sudo ./uninstall.sh [--purge]  (keeps configuration/data by default)"
