#!/usr/bin/env bash
# GeDefense Retail - cross-platform release builder (Linux/macOS/WSL).
#
# Builds the three binaries for linux/amd64, linux/arm64, windows/amd64 and
# windows/arm64 with reproducible flags (trimpath, buildvcs=false, CGO off),
# then optionally packages tar.gz/zip release bundles with checksums.
#
# Usage:
#   scripts/build-release.sh [--package] [--targets "linux/amd64 ..."]
# Environment:
#   GEDEFENSE_COMMIT      override the commit id (default: git short hash or "local")
#   GEDEFENSE_BUILD_DATE  override the build timestamp (RFC3339 UTC)
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MODULE="$ROOT/src/retail"
VERSION="$(tr -d ' \r\n' < "$ROOT/VERSION")"
COMMIT="${GEDEFENSE_COMMIT:-$(git -C "$ROOT" rev-parse --short HEAD 2>/dev/null || echo local)}"
BUILD_DATE="${GEDEFENSE_BUILD_DATE:-$(date -u +%Y-%m-%dT%H:%M:%SZ)}"
DIST="$ROOT/dist/$VERSION"
BINARIES=(retaild retailgate retail-sim)
TARGETS_DEFAULT="linux/amd64 linux/arm64 windows/amd64 windows/arm64"

PACKAGE=0
TARGETS="$TARGETS_DEFAULT"
while [ $# -gt 0 ]; do
  case "$1" in
    --package) PACKAGE=1 ;;
    --targets) TARGETS="$2"; shift ;;
    --version) VERSION="$2"; shift ;;
    -h|--help) sed -n '2,20p' "$0"; exit 0 ;;
    *) echo "build-release: unknown argument $1" >&2; exit 2 ;;
  esac
  shift
done

if ! command -v go >/dev/null 2>&1; then
  echo "build-release: go toolchain not found" >&2; exit 1
fi
if [ ! -f "$MODULE/go.mod" ]; then
  echo "build-release: module not found at $MODULE" >&2; exit 1
fi

MODULE_PATH="$(cd "$MODULE" && go list -m)"
LDFLAGS="-s -w -X ${MODULE_PATH}/internal/version.Version=${VERSION} -X ${MODULE_PATH}/internal/version.Commit=${COMMIT} -X ${MODULE_PATH}/internal/version.BuildDate=${BUILD_DATE}"

echo "BUILD version=$VERSION commit=$COMMIT build_date=$BUILD_DATE dist=$DIST"
rm -rf "$DIST"
mkdir -p "$DIST"

for target in $TARGETS; do
  GOOS="${target%%/*}"
  GOARCH="${target##*/}"
  outdir="$DIST/${GOOS}-${GOARCH}"
  mkdir -p "$outdir"
  for bin in "${BINARIES[@]}"; do
    name="$bin"
    if [ "$GOOS" = "windows" ]; then name="${bin}.exe"; fi
    echo "BUILD ${GOOS}/${GOARCH} ${name}"
    ( cd "$MODULE" && CGO_ENABLED=0 GOOS="$GOOS" GOARCH="$GOARCH" \
      go build -trimpath -buildvcs=false -ldflags "$LDFLAGS" -o "$outdir/$name" "./cmd/$bin" )
  done
  ( cd "$outdir" && sha256sum ./* > SHA256SUMS )
done

# Overall checksum file over every built binary (relative paths). The release
# asset SHA256SUMS (archive hashes) is written by package-release.{sh,ps1}.
(
  cd "$DIST"
  find . -type f \( -name 'retaild*' -o -name 'retailgate*' -o -name 'retail-sim*' \) \
    | sort | sed 's|^\./||' | while IFS= read -r file; do sha256sum "$file"; done > SHA256SUMS.binaries
)
echo "BUILD_OK $(wc -l < "$DIST/SHA256SUMS.binaries") binaries"

if [ "$PACKAGE" = "1" ]; then
  exec "$ROOT/scripts/package-release.sh" --version "$VERSION"
fi
