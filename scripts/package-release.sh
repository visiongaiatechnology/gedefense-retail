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
import os, sys, tarfile, zipfile, hashlib, shutil, gzip, time, re
from pathlib import Path

root, dist, stage, version, packaging = map(Path, sys.argv[1:6])
# archive timestamps/ownership are normalized to SOURCE_DATE_EPOCH so
# repeated builds (local and CI) produce byte-identical archives.
EPOCH = int(os.environ.get("SOURCE_DATE_EPOCH", "0") or "0")
if EPOCH <= 0:
    EPOCH = int(time.time())
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

# public-docs allowlist: only explicitly public docs may enter a release bundle.
DENY_DOC_PATTERN = re.compile(
    r"(security-(audit|review|assumptions|scan)|audit_matrix|"
    r"public-release-hygiene|release-report|architecture-gap|reuse-matrix|"
    r"access-gate-review|access-gate-threat-model|review-findings|alpha-report)",
    re.IGNORECASE,
)
manifest_path = root / "docs" / "PUBLIC-DOCS.manifest"
if not manifest_path.is_file():
    print("package-release: docs/PUBLIC-DOCS.manifest is missing (fail-closed)", file=sys.stderr)
    sys.exit(1)
public_docs = []
for raw_line in manifest_path.read_text(encoding="utf-8").splitlines():
    entry = raw_line.split("#", 1)[0].strip()
    if not entry:
        continue
    rel = Path(entry)
    if rel.is_absolute() or ".." in rel.parts:
        print(f"package-release: manifest entry {entry!r} is unsafe", file=sys.stderr)
        sys.exit(1)
    if DENY_DOC_PATTERN.search(rel.as_posix()):
        print(f"package-release: manifest entry {entry!r} matches a denied internal pattern", file=sys.stderr)
        sys.exit(1)
    if not (root / rel).is_file():
        print(f"package-release: manifest entry {entry!r} does not exist", file=sys.stderr)
        sys.exit(1)
    public_docs.append(rel)
if not public_docs:
    print("package-release: public docs manifest is empty (fail-closed)", file=sys.stderr)
    sys.exit(1)

def copy_public_docs(bundle):
    for rel in public_docs:
        dest = bundle / "docs" / rel.relative_to("docs")
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(root / rel, dest)

def scan_archive(archive):
    if archive.name.endswith(".tar.gz"):
        with tarfile.open(archive) as tf:
            names = tf.getnames()
    else:
        with zipfile.ZipFile(archive) as zf:
            names = zf.namelist()
    for name in names:
        if DENY_DOC_PATTERN.search(name):
            print(f"package-release: {archive.name} contains denied internal document {name}", file=sys.stderr)
            sys.exit(1)
    joined = "\n".join(names)
    for required in ("data/ot-catalog/vendors.json", "data/ot-catalog/write-surface.json",
                     "data/ot-catalog/regulatory-context.json", "docs/retail/"):
        if required not in joined:
            print(f"package-release: {archive.name} is missing {required}", file=sys.stderr)
            sys.exit(1)

def copy_common(bundle):
    for name in common:
        shutil.copy2(root / name, bundle / name)
    (bundle / "config").mkdir(parents=True, exist_ok=True)
    for name in configs:
        shutil.copy2(root / "config" / name, bundle / "config" / name)
    copy_public_docs(bundle)
    # OT catalog ships with every bundle (write-surface/current-value evidence).
    catalog = root / "data" / "ot-catalog"
    if catalog.is_dir():
        shutil.copytree(catalog, bundle / "data" / "ot-catalog", dirs_exist_ok=True)

def write_tar_gz(archive, bundle):
    with open(archive, "wb") as raw:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=EPOCH, compresslevel=9) as gz:
            with tarfile.open(fileobj=gz, mode="w", format=tarfile.GNU_FORMAT) as tar:
                for path in sorted(bundle.rglob("*")):
                    if not path.is_file():
                        continue
                    arcname = f"{bundle.name}/{path.relative_to(bundle).as_posix()}"
                    info = tar.gettarinfo(str(path), arcname)
                    info.mtime = EPOCH
                    info.uid = info.gid = 0
                    info.uname = info.gname = ""
                    info.mode = 0o755 if os.access(path, os.X_OK) else 0o644
                    with open(path, "rb") as fh:
                        tar.addfile(info, fh)

def write_zip(archive, bundle):
    with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as zf:
        for path in sorted(bundle.rglob("*")):
            if not path.is_file():
                continue
            arcname = f"{bundle.name}/{path.relative_to(bundle).as_posix()}"
            info = zipfile.ZipInfo(arcname, date_time=time.gmtime(EPOCH)[:6])
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = (0o755 if os.access(path, os.X_OK) else 0o644) << 16
            with open(path, "rb") as fh:
                zf.writestr(info, fh.read())

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
        write_tar_gz(archive, bundle)
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
        write_zip(archive, bundle)
        archives.append(archive)
    else:
        continue

for archive in archives:
    scan_archive(archive)

lines = []
# Fail the packaging run if a required bundle asset is missing.
required_files = ["data/ot-catalog/vendors.json", "data/ot-catalog/write-surface.json",
                  "data/ot-catalog/regulatory-context.json"]
for bundle in [p for p in stage.iterdir() if p.is_dir()]:
    for rel in required_files:
        if not (bundle / rel).is_file():
            print(f"package-release: bundle {bundle.name} is missing {rel}", file=sys.stderr)
            sys.exit(1)
    if not (bundle / "docs" / "retail").is_dir():
        print(f"package-release: bundle {bundle.name} is missing docs/retail", file=sys.stderr)
        sys.exit(1)

for archive in archives:
    lines.append(f"{sha256(archive)}  {archive.name}")
(dist / "SHA256SUMS").write_text("\n".join(lines) + "\n", encoding="utf-8")
(dist / "SHA256SUMS.archives").write_text("\n".join(lines) + "\n", encoding="utf-8")
print("PACKAGE_OK")
for archive in archives:
    print(f"  {archive.name}  {archive.stat().st_size} B")
PY

# SBOM: SPDX-2.3 JSON next to the archives, created from SOURCE_DATE_EPOCH.
if command -v python3 >/dev/null 2>&1; then
  python3 "$ROOT/scripts/generate-sbom.py" --dist "$DIST" --version "$VERSION"
fi
