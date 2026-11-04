#!/usr/bin/env python3
"""Visual QA for the GeDefense Retail dashboard (mock mode, headless Chrome).

Serves internal/webui/web over a local static server, renders the eight views in
desktop/tablet/mobile width plus the empty/error/offline states, and stores PNGs
under var/visual-qa/.

The mock pages are clearly labelled as design QA and contain no real security
data. This script proves the visual implementation; the live data path is
covered by tests/e2e.py.
"""

from __future__ import annotations

import http.server
import os
import shutil
import socket
import subprocess
import sys
import threading
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
WEB = ROOT / "src" / "retail" / "internal" / "webui" / "web"
OUT = ROOT / "var" / "visual-qa"
PORT = int(os.environ.get("GEDEFENSE_VISUAL_PORT", "18090"))

CHROME_CANDIDATES = [
    os.path.join(os.environ.get("ProgramFiles", ""), "Google", "Chrome", "Application", "chrome.exe"),
    os.path.join(os.environ.get("ProgramFiles(x86)", ""), "Google", "Chrome", "Application", "chrome.exe"),
    os.path.join(os.environ.get("LOCALAPPDATA", ""), "Google", "Chrome", "Application", "chrome.exe"),
    os.path.join(os.environ.get("ProgramFiles", ""), "Microsoft", "Edge", "Application", "msedge.exe"),
]


def find_chrome() -> str | None:
    for candidate in CHROME_CANDIDATES:
        if candidate and Path(candidate).exists():
            return candidate
    return None


class QuietHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(WEB), **kwargs)

    def log_message(self, fmt: str, *args) -> None:  # noqa: D401 - silence server log
        return


def port_free(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        try:
            sock.bind(("127.0.0.1", port))
            return True
        except OSError:
            return False


def shot(chrome: str, name: str, url: str, width: int, height: int) -> tuple[str, Path | None]:
    path = OUT / f"{name}.png"
    profile = OUT / f"profile-{name}"
    args = [
        chrome, "--headless=new", "--disable-gpu", "--hide-scrollbars",
        "--no-first-run", "--disable-extensions", "--disable-background-networking",
        f"--user-data-dir={profile}", f"--window-size={width},{height}",
        "--force-device-scale-factor=1", "--virtual-time-budget=20000",
        f"--screenshot={path}", url,
    ]
    try:
        subprocess.run(args, capture_output=True, timeout=90)
    except subprocess.TimeoutExpired:
        return name, None
    return name, path if path.exists() else None


def main() -> int:
    chrome = find_chrome()
    if chrome is None:
        print("FAIL: Chrome/Edge nicht gefunden - visuelle QA nicht möglich.")
        return 1
    if not (WEB / "index.html").exists():
        print(f"FAIL: {WEB / 'index.html'} fehlt")
        return 1
    if not port_free(PORT):
        print(f"FAIL: Port {PORT} belegt")
        return 1

    if OUT.exists():
        shutil.rmtree(OUT)
    OUT.mkdir(parents=True, exist_ok=True)

    server = http.server.ThreadingHTTPServer(("127.0.0.1", PORT), QuietHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{PORT}/mock/?state=normal&lang=de"
    views = ["overview", "site", "assets", "coldchain", "access", "threat", "integrity", "incidents"]

    jobs: list[tuple[str, str, int, int]] = []
    for view in views:
        jobs.append((f"desktop-{view}", f"{base}#/{view}", 1440, 900))
    # NOTE: Windows Chrome enforces a minimum viewport width of ~500 CSS px for
    # --window-size. The mobile shots below therefore use 500x844; the true
    # 390x844 emulation (scrollWidth == innerWidth) was measured via CDP by the
    # UI owner and is documented in docs/retail/ui-design-spec.md.
    jobs += [
        ("tablet-overview", f"{base}#/overview", 1024, 768),
        ("tablet-assets", f"{base}#/assets", 1024, 768),
        ("mobile-overview", f"{base}#/overview", 500, 844),
        ("mobile-coldchain", f"{base}#/coldchain", 500, 844),
        ("mobile-threat", f"{base}#/threat", 500, 844),
        ("state-empty-assets", f"http://127.0.0.1:{PORT}/mock/?state=empty&lang=de#/assets", 1440, 900),
        ("state-error-coldchain", f"http://127.0.0.1:{PORT}/mock/?state=error&lang=de#/coldchain", 1440, 900),
        ("state-offline-overview", f"http://127.0.0.1:{PORT}/mock/?state=offline&lang=de#/overview", 1440, 900),
        # Access Gate (0.2): approval inbox, plan detail, sessions, denies, status
        ("desktop-gate-inbox", f"{base}#/gate", 1440, 900),
        ("desktop-gate-plan", f"{base}#/gate?plan=pln-2026-11-04-01", 1440, 1200),
        ("desktop-gate-sessions", f"{base}#/gate?tab=sessions", 1440, 900),
        ("desktop-gate-denies", f"{base}#/gate?tab=denies", 1440, 900),
        ("desktop-gate-status", f"{base}#/gate?tab=status", 1440, 900),
        ("mobile-gate", f"{base}#/gate", 500, 844),
        ("desktop-gate-login", f"http://127.0.0.1:{PORT}/mock/?state=normal&gateLogin=1&lang=de#/gate", 1440, 900),
        ("state-empty-gate", f"http://127.0.0.1:{PORT}/mock/?state=empty&lang=de#/gate", 1440, 900),
        ("state-error-gate", f"http://127.0.0.1:{PORT}/mock/?state=error&lang=de#/gate", 1440, 900),
        ("state-offline-gate", f"http://127.0.0.1:{PORT}/mock/?state=offline&lang=de#/gate", 1440, 900),
        # First-run setup: 8 languages, 6 steps, completion and mobile
    *[
        (f"setup-lang-{code}", f"http://127.0.0.1:{PORT}/mock/?state=normal&lang={code}#/setup", 1440, 950)
        for code in ["en", "de", "fr", "it", "es", "ja", "zh", "ru"]
    ],
    ("setup-step-site", f"http://127.0.0.1:{PORT}/mock/?state=normal&lang=de#/setup?step=1", 1440, 950),
    ("setup-step-whitelist", f"http://127.0.0.1:{PORT}/mock/?state=normal&lang=de#/setup?step=2", 1440, 950),
    ("setup-step-admin", f"http://127.0.0.1:{PORT}/mock/?state=normal&lang=de#/setup?step=3", 1440, 950),
    ("setup-step-collectors", f"http://127.0.0.1:{PORT}/mock/?state=normal&lang=de#/setup?step=4", 1440, 950),
    ("setup-step-summary", f"http://127.0.0.1:{PORT}/mock/?state=normal&lang=de#/setup?step=5", 1440, 950),
    ("setup-complete", f"http://127.0.0.1:{PORT}/mock/?state=normal&setupCompleted=1&lang=de#/setup", 1440, 1100),
    ("mobile-setup-language", f"http://127.0.0.1:{PORT}/mock/?state=normal&lang=de#/setup", 500, 900),
    ("mobile-setup-whitelist", f"http://127.0.0.1:{PORT}/mock/?state=normal&lang=de#/setup?step=2", 500, 1000),
    ("notfound-sirdu", f"http://127.0.0.1:{PORT}/mock/?state=normal&lang=de#/does-not-exist", 1440, 900),
    # Manufacturer knowledge panel in the asset inspector
    # Empty CTAs for the two split views
    ("state-empty-access", f"http://127.0.0.1:{PORT}/mock/?state=normal&empty=access&lang=de#/access", 1440, 900),
    ("state-empty-coldchain", f"http://127.0.0.1:{PORT}/mock/?state=normal&empty=coldchain&lang=de#/coldchain", 1440, 900),
    ("desktop-vendor-panel", f"{base}#/assets?asset=asset-danfoss-aksm800", 1440, 1200),
    ("desktop-vendor-panel-disabled", f"http://127.0.0.1:{PORT}/mock/?state=normal&vendors=disabled&lang=de#/assets?asset=asset-danfoss-aksm800", 1440, 1000),
    ("mobile-vendor-panel", f"{base}#/assets?asset=asset-danfoss-aksm800", 500, 1000),
    ]

    ok = 0
    try:
        # wait for the local server
        deadline = time.time() + 15
        while time.time() < deadline:
            try:
                with urllib.request.urlopen(f"http://127.0.0.1:{PORT}/mock/", timeout=2):
                    break
            except Exception:  # noqa: BLE001 - retry loop
                time.sleep(0.2)

        for name, url, w, h in jobs:
            shot_name, path = shot(chrome, name, url, w, h)
            if path is None:
                print(f"[FAIL] {shot_name} (kein Screenshot)")
                continue
            ok += 1
            print(f"[OK]   {shot_name:<24} {w}x{h}  {path.stat().st_size} bytes  ({path})")
    finally:
        server.shutdown()
        server.server_close()

    print(f"\nScreenshots: {ok}/{len(jobs)} unter {OUT}")
    return 0 if ok == len(jobs) else 1


if __name__ == "__main__":
    sys.exit(main())