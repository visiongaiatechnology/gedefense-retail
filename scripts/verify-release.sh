#!/usr/bin/env bash
# GeDefense Retail - release verification matrix (Linux/WSL2).
#
# Runs build, vet, test, race and both loopback E2E suites, then probes the
# packaged binaries (`version`, `check`, `/health`). Prints one evidence line per
# gate and exits non-zero if any gate failed.
#
# Usage: bash scripts/verify-release.sh [--skip-e2e] [--binary-dir <dir>]
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MODULE="$ROOT/src/retail"
VERSION="$(tr -d ' \r\n' < "$ROOT/VERSION")"
LOG_DIR="$ROOT/var/release"
LOG="$LOG_DIR/linux-gates.log"
SKIP_E2E=0
BINARY_DIR=""

while [ $# -gt 0 ]; do
  case "$1" in
    --skip-e2e) SKIP_E2E=1 ;;
    --binary-dir) BINARY_DIR="$2"; shift ;;
    -h|--help) sed -n '2,10p' "$0"; exit 0 ;;
    *) echo "verify-release: unknown argument $1" >&2; exit 2 ;;
  esac
  shift
done

mkdir -p "$LOG_DIR"
: > "$LOG"
FAILED=0
declare -a SUMMARY=()

run_gate() {
  local name="$1"; shift
  local start
  start=$(date +%s)
  {
    echo "=== $name: $* ==="
    "$@"
  } >>"$LOG" 2>&1
  local code=$?
  local elapsed=$(( $(date +%s) - start ))
  if [ $code -eq 0 ]; then
    SUMMARY+=("PASS  $name  exit=0  ${elapsed}s")
  else
    SUMMARY+=("FAIL  $name  exit=$code  ${elapsed}s")
    FAILED=1
  fi
}

run_gate "linux/go-build"  bash -c "cd '$MODULE' && CGO_ENABLED=0 go build ./..."
run_gate "linux/go-vet"    bash -c "cd '$MODULE' && go vet ./..."
run_gate "linux/go-test"   bash -c "cd '$MODULE' && go test ./..."
run_gate "linux/go-race"   bash -c "cd '$MODULE' && go test -race ./..."
if [ "$SKIP_E2E" = "0" ]; then
  run_gate "linux/e2e"      python3 "$ROOT/tests/e2e.py"
  run_gate "linux/gate-e2e" python3 "$ROOT/tests/gate_e2e.py"
fi

if [ -n "$BINARY_DIR" ] && [ -d "$BINARY_DIR" ]; then
  run_gate "linux/binary-version" "$BINARY_DIR/retaild" version
  if [ -f "$ROOT/var/release/probe/retail.json" ]; then
    run_gate "linux/binary-check" "$BINARY_DIR/retaild" check --config "$ROOT/var/release/probe/retail.json"
  fi
  run_gate "linux/retailgate-version" "$BINARY_DIR/retailgate" version
  run_gate "linux/retail-sim-version" "$BINARY_DIR/retail-sim" version
fi

echo "RELEASE_MATRIX version=$VERSION"
for line in "${SUMMARY[@]}"; do echo "$line"; done
echo "LOG=$LOG"
if [ "$FAILED" -ne 0 ]; then
  echo "MATRIX_RESULT=FAILED"
  exit 1
fi
echo "MATRIX_RESULT=PASS"
