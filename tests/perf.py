#!/usr/bin/env python3
"""Performance evidence for GeDefense Retail 0.1 (loopback, synthetic events).

Measures ingest throughput through the simulator ingest path and read latency of
the core API endpoints on a local gateway. These are engineering baselines, not
product guarantees; the numbers are recorded in the release report together with
the hardware/OS they were measured on.
"""

from __future__ import annotations

import json
import os
import shutil
import statistics
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MODULE = ROOT / "src" / "retail"
BIN = ROOT / "bin"
LISTEN = "127.0.0.1:18081"
BASE = f"http://{LISTEN}"
EVENTS = int(os.environ.get("GEDEFENSE_PERF_EVENTS", "5000"))


def run(cmd: list[str], cwd: Path | None = None, timeout: int = 300) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, cwd=str(cwd) if cwd else None, capture_output=True, text=True, timeout=timeout)


def http(method: str, path: str, token: str = "", body: object = None) -> tuple[int, bytes]:
    h = {"X-Request-Id": "perf-" + os.urandom(4).hex()}
    if token:
        h["Authorization"] = f"Bearer {token}"
    data = None
    if body is not None:
        data = json.dumps(body).encode()
        h["Content-Type"] = "application/json"
    req = urllib.request.Request(BASE + path, data=data, headers=h, method=method)
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return resp.status, resp.read(1 << 20)
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read(1 << 20)
    except urllib.error.URLError:
        return 0, b""


def rss_kb(pid: int) -> int:
    if os.name == "nt":
        out = run(["tasklist", "/FI", f"PID eq {pid}", "/FO", "CSV", "/NH"]).stdout
        parts = [p.strip('"') for p in out.strip().split(",")]
        if len(parts) >= 5:
            try:
                return int(parts[-1].replace(".", "").replace(",", "").strip('" K'))
            except ValueError:
                return 0
        return 0
    try:
        with open(f"/proc/{pid}/status", encoding="utf-8") as fh:
            for line in fh:
                if line.startswith("VmRSS:"):
                    return int(line.split()[1])
    except OSError:
        return 0
    return 0


def main() -> int:
    work = ROOT / "var" / "perf"
    if work.exists():
        shutil.rmtree(work)
    work.mkdir(parents=True, exist_ok=True)
    BIN.mkdir(parents=True, exist_ok=True)
    retaild = BIN / ("retaild.exe" if os.name == "nt" else "retaild")
    sim = BIN / ("retail-sim.exe" if os.name == "nt" else "retail-sim")

    for target, out in (("./cmd/retaild", retaild), ("./cmd/retail-sim", sim)):
        proc = run(["go", "build", "-trimpath", "-o", str(out), target], cwd=MODULE)
        if proc.returncode != 0:
            print(f"BUILD FAILED: {target}\n{proc.stderr}")
            return 1

    tokens = {}
    for user, role in (("admin", "admin"), ("technik-01", "operator"), ("viewer-01", "viewer")):
        tokens[user] = json.loads(run([str(retaild), "gen-token", "--user", user, "--role", role]).stdout)
    token = tokens["admin"]
    cfg = json.loads((ROOT / "config" / "retail.example.json").read_text(encoding="utf-8"))
    cfg["listen"] = LISTEN
    cfg["data_dir"] = str(work / "data")
    cfg["log_level"] = "warn"
    cfg["simulation"] = {"enabled": True, "listen": LISTEN}
    cfg["collectors"] = []
    for user in cfg["users"]:
        user["token_sha256"] = tokens[user["user_id"]]["token_sha256"]
    cfg_path = work / "retail.json"
    cfg_path.write_text(json.dumps(cfg, indent=2), encoding="utf-8")

    stdout, stderr = work / "stdout.log", work / "stderr.log"
    with open(stdout, "w", encoding="utf-8") as out, open(stderr, "w", encoding="utf-8") as err:
        server = subprocess.Popen([str(retaild), "serve", "--config", str(cfg_path)],
                                  stdout=out, stderr=err, cwd=str(ROOT))
    try:
        deadline = time.time() + 30
        while time.time() < deadline:
            st, _ = http("GET", "/api/v1/health")
            if st == 200:
                break
            time.sleep(0.3)
        else:
            print("SERVER DID NOT START")
            print(stderr.read_text(encoding="utf-8", errors="replace")[-2000:])
            return 1

        rss_before = rss_kb(server.pid)
        print(f"--- Ingest: {EVENTS} synthetische Events ---")
        t0 = time.time()
        feed = run([str(sim), "feed", "--url", BASE, "--token", token["token"],
                    "--scenario", "normal", "--count", str(EVENTS), "--batch", "200",
                    "--rate", "5000"], timeout=600)
        elapsed = time.time() - t0
        print((feed.stdout or feed.stderr).strip()[-500:])
        if feed.returncode != 0:
            print("FEED FAILED")
            return 1
        accepted = 0
        st, raw = http("GET", "/api/v1/health", token["token"])
        try:
            accepted = json.loads(raw).get("storage", {}).get("events", 0)
        except json.JSONDecodeError:
            pass
        rate = accepted / elapsed if elapsed > 0 else 0
        rss_after = rss_kb(server.pid)
        print(f"ingest: {accepted} events in {elapsed:.2f}s -> {rate:.0f} events/s "
              f"(rss {rss_before/1024:.1f}->{rss_after/1024:.1f} MiB)")

        print("--- Rate-Limit-Erholung: 35 s warten (120 req/min, Burst 40) ---")
        time.sleep(35)
        print("--- API-Latenz (5 Messungen je Endpoint, Rate-Limit-bewusst) ---")
        endpoints = ["/api/v1/overview", "/api/v1/alerts?limit=50", "/api/v1/assets?limit=50",
                     "/api/v1/coldchain", "/api/v1/timeline?limit=50"]
        lat: dict[str, list[float]] = {}
        for _ in range(1):
            for ep in endpoints:
                http("GET", ep, token["token"])
        for ep in endpoints:
            samples = []
            for _ in range(5):
                t = time.perf_counter()
                st, _ = http("GET", ep, token["token"])
                samples.append((time.perf_counter() - t) * 1000.0)
                if st != 200:
                    print(f"FAIL {ep}: status={st}")
            lat[ep] = samples
        for ep, samples in lat.items():
            p50 = statistics.median(samples)
            p95 = sorted(samples)[int(len(samples) * 0.95) - 1]
            print(f"{ep:<32} p50={p50:7.1f} ms  p95={p95:7.1f} ms")

        data_dir = work / "data"
        size = sum(p.stat().st_size for p in data_dir.rglob("*") if p.is_file())
        print(f"data_dir size: {size/1024/1024:.2f} MiB")
        print(f"rss after API phase: {rss_kb(server.pid)/1024:.1f} MiB")
        return 0
    finally:
        if server.poll() is None:
            server.terminate()
            try:
                server.wait(timeout=10)
            except subprocess.TimeoutExpired:
                server.kill()


if __name__ == "__main__":
    sys.exit(main())
