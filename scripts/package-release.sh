#!/usr/bin/env bash
# GeDefense Retail - package the built distribution into installable archives.
#
# Expects dist/<version>/<os>-<arch>/ binaries produced by build-release.sh.
# Creates:
#   dist/<version>/gedefense-retail-<version>-linux-<arch>.tar.gz
#   dist/<version>/gedefense-retail-<version>-windows-<arch>.zip
#   dist/<version>/SHA256SUMS.archives
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VERSION="$(tr -d ' \r\n' < "$ROOT/VERSION")"
DIST="$ROOT/dist/$VERSION"
PACKAGING="$ROOT/packaging"
STAGE="$DIST/staging"

while [ $# -gt 0 ]; do
  case "$1" in
    --version) VERSION="$2"; DIST="$ROOT/dist/$VERSION"; STAGE="$DIST/staging"; shift ;;
    -h|--help) sed -n '2,12p' "$0"; exit 0 ;;
    *) echo "package-release: unknown argument $1" >&2; exit 2 ;;
  esac
  shift
done

if [ ! -d "$DIST" ]; then
  echo "package-release: $DIST does not exist; run scripts/build-release.sh first" >&2
  exit 1
fi
rm -rf "$STAGE"
mkdir -p "$STAGE"

python3 - "$ROOT" "$DIST" "$STAGE" "$VERSION" "$PACKAGING" <<'PY'
import os, sys, tarfile, zipfile, hashlib, shutil
from pathlib import Path

root, dist, stage, version, packaging = map(Path, sys.argv[1:6])
common = ["README.md", "LICENSE", "VERSION", "THIRD-PARTY-NOTICES.md"]
configs = ["retail.example.json", "gate.example.json", "gate-policy.example.json",
           "gedefense-retail.service", "gedefense-retailgate.service"]
binaries = ["retaild", "retailgate", "retail-sim"]

def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()

def copy_common(bundle):
    for name in common:
        shutil.copy2(root / name, bundle / name)
    (bundle / "config").mkdir(parents=True, exist_ok=True)
    for name in configs:
        shutil.copy2(root / "config" / name, bundle / "config" / name)
    shutil.copytree(root / "docs", bundle / "docs", dirs_exist_ok=True)

archives = []
for target_dir in sorted(dist.iterdir()):
    if not target_dir.is_dir() or target_dir.name in ("staging",):
        continue
    os_name, _, arch = target_dir.name.partition("-")
    if os_name == "linux":
        bundle = stage / f"gedefense-retail-{version}-linux-{arch}"
        (bundle / "bin").mkdir(parents=True, exist_ok=True)
        for name in binaries:
            src = target_dir / name
            if src.exists():
                shutil.copy2(src, bundle / "bin" / name)
                os.chmod(bundle / "bin" / name, 0o755)
        copy_common(bundle)
        for script in ("install.sh", "uninstall.sh"):
            shutil.copy2(packaging / "linux" / script, bundle / script)
            os.chmod(bundle / script, 0o755)
        manifest = []
        for path in sorted(bundle.rglob("*")):
            if path.is_file():
                manifest.append(f"{sha256(path)}  {path.relative_to(bundle)}")
        (bundle / "SHA256SUMS").write_text("\n".join(manifest) + "\n", encoding="utf-8")
        archive = dist / f"{bundle.name}.tar.gz"
        with tarfile.open(archive, "w:gz") as tar:
            tar.add(bundle, arcname=bundle.name)
        archives.append(archive)
    elif os_name == "windows":
        bundle = stage / f"gedefense-retail-{version}-windows-{arch}"
        (bundle / "bin").mkdir(parents=True, exist_ok=True)
        for name in binaries:
            src = target_dir / f"{name}.exe"
            if src.exists():
                shutil.copy2(src, bundle / "bin" / f"{name}.exe")
        copy_common(bundle)
        for script in ("install-windows.ps1", "uninstall-windows.ps1"):
            shutil.copy2(packaging / "windows" / script, bundle / script)
        manifest = []
        for path in sorted(bundle.rglob("*")):
            if path.is_file():
                manifest.append(f"{sha256(path)}  {path.relative_to(bundle)}")
        (bundle / "SHA256SUMS").write_text("\r\n".join(manifest) + "\r\n", encoding="utf-8")
        archive = dist / f"{bundle.name}.zip"
        with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as zf:
            for path in sorted(bundle.rglob("*")):
                if path.is_file():
                    zf.write(path, path.relative_to(stage))
        archives.append(archive)
    else:
        continue

lines = []
for archive in archives:
    lines.append(f"{sha256(archive)}  {archive.name}")
(dist / "SHA256SUMS").write_text("\n".join(lines) + "\n", encoding="utf-8")
(dist / "SHA256SUMS.archives").write_text("\n".join(lines) + "\n", encoding="utf-8")
print("PACKAGE_OK")
for archive in archives:
    print(f"  {archive.name}  {archive.stat().st_size} B")
PY

# SBOM (FIND-004): SPDX-2.3 JSON next to the archives, created from SOURCE_DATE_EPOCH.
if command -v python3 >/dev/null 2>&1; then
  python3 "$ROOT/scripts/generate-sbom.py" --dist "$DIST" --version "$VERSION"
fi
