#!/usr/bin/env python3
"""Generate a minimal SPDX-2.3 JSON SBOM for a GeDefense Retail release.

Covers the release archives and all built binaries with their SHA-256 digests,
the Go toolchain version and the product license metadata. `created` honours
SOURCE_DATE_EPOCH for reproducible releases (FIND-004/FIND-009).

Usage:
  python3 scripts/generate-sbom.py --dist dist/0.2.0-alpha.3 \
      --version 0.2.0-alpha.3 --out dist/0.2.0-alpha.3/SBOM.spdx.json
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

PRODUCT = "GeDefense Retail"
SUPPLIER = "VisionGaiaTechnology"
LICENSE_DECLARED = "LicenseRef-VGT-Proprietary"
GO_LICENSE = "BSD-3-Clause"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def spdx_id(prefix: str, name: str) -> str:
    safe = re.sub(r"[^A-Za-z0-9.-]", "-", name)
    return f"SPDXRef-{prefix}-{safe}"


def created_timestamp() -> str:
    raw = os.environ.get("SOURCE_DATE_EPOCH")
    if raw and raw.isdigit():
        return datetime.fromtimestamp(int(raw), tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def go_version() -> str:
    try:
        out = subprocess.run(["go", "version"], capture_output=True, text=True, check=True).stdout.strip()
    except Exception:
        out = "go toolchain (version unknown)"
    match = re.search(r"go\d+\.\d+(?:\.\d+)?", out)
    return match.group(0) if match else out


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate an SPDX-2.3 JSON SBOM")
    parser.add_argument("--dist", required=True, help="release dist directory")
    parser.add_argument("--version", required=True, help="release version, e.g. 0.2.0-alpha.3")
    parser.add_argument("--repo", default="https://github.com/visiongaiatechnology/gedefense-retail")
    parser.add_argument("--out", default="", help="output path (default: <dist>/SBOM.spdx.json)")
    args = parser.parse_args()

    dist = Path(args.dist)
    if not dist.is_dir():
        print(f"generate-sbom: dist directory not found: {dist}", file=sys.stderr)
        return 1
    out = Path(args.out) if args.out else dist / "SBOM.spdx.json"

    files = []
    seen = set()
    for path in sorted(dist.rglob("*")):
        if not path.is_file():
            continue
        rel = path.relative_to(dist).as_posix()
        if rel == out.name or path == out:
            continue
        if path.suffix in (".sig", ".pem") or rel.startswith("staging/"):
            continue
        if path.name in ("SBOM.spdx.json",):
            continue
        if rel in seen:
            continue
        seen.add(rel)
        files.append({
            "SPDXID": spdx_id("File", rel),
            "fileName": rel,
            "checksums": [{"algorithm": "SHA256", "checksumValue": sha256_file(path)}],
            "fileTypes": ["BINARY"] if path.suffix in (".tar", ".gz", ".zip") or "retail" in path.name else ["TEXT"],
            "licenseConcluded": LICENSE_DECLARED,
            "copyrightText": "Copyright (c) VisionGaiaTechnology",
        })

    created = created_timestamp()
    namespace = f"{args.repo}/spdx/{args.version}/{uuid.uuid4()}"
    doc = {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": f"{PRODUCT}-{args.version}",
        "documentNamespace": namespace,
        "creationInfo": {
            "created": created,
            "creators": ["Tool: generate-sbom.py-1.0", f"Organization: {SUPPLIER}"],
            "licenseListVersion": "3.24",
        },
        "packages": [
            {
                "SPDXID": "SPDXRef-Package-GeDefenseRetail",
                "name": PRODUCT,
                "versionInfo": args.version,
                "downloadLocation": "NOASSERTION",
                "filesAnalyzed": True,
                "licenseConcluded": LICENSE_DECLARED,
                "licenseDeclared": LICENSE_DECLARED,
                "copyrightText": "Copyright (c) VisionGaiaTechnology",
                "supplier": f"Organization: {SUPPLIER}",
                "hasFiles": [f["SPDXID"] for f in files],
            },
            {
                "SPDXID": "SPDXRef-Package-GoStdlib",
                "name": "Go standard library (statically linked)",
                "versionInfo": go_version(),
                "downloadLocation": "https://go.dev/dl/",
                "filesAnalyzed": False,
                "licenseConcluded": GO_LICENSE,
                "licenseDeclared": GO_LICENSE,
                "copyrightText": "Copyright (c) The Go Authors",
                "supplier": "Organization: The Go Authors",
            },
        ],
        "files": files,
        "relationships": [
            {"spdxElementId": "SPDXRef-DOCUMENT", "relationshipType": "DESCRIBES",
             "relatedSpdxElement": "SPDXRef-Package-GeDefenseRetail"},
            {"spdxElementId": "SPDXRef-Package-GeDefenseRetail", "relationshipType": "DEPENDS_ON",
             "relatedSpdxElement": "SPDXRef-Package-GoStdlib"},
        ],
    }
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(doc, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"SBOM_OK {out} ({len(files)} files, go={doc['packages'][1]['versionInfo']}, created={created})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
