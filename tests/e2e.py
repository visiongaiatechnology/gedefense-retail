#!/usr/bin/env python3
"""End-to-End acceptance run for GeDefense Retail MVP 0.1 (loopback only).

Builds the binaries, generates throw-away bearer tokens, starts the gateway with
a temporary configuration, exercises auth/RBAC/safety/detection/cold-chain and
the simulator ingest, and shuts everything down again.

This proves the *software* behaviour on loopback with synthetic observations. It
does NOT prove behaviour against real OT hardware - that is the pilot acceptance
(docs/retail/pilot-acceptance.md).

Exit code 0 = all checks passed, 1 = at least one check failed.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MODULE = ROOT / "src" / "retail"
BIN = ROOT / "bin"
LISTEN = os.environ.get("GEDEFENSE_E2E_LISTEN", "127.0.0.1:18080")
BASE = f"http://{LISTEN}"
TIMEOUT_UP = 60
SCENARIO = os.environ.get("GEDEFENSE_E2E_SCENARIO", "angriff")

results: list["Check"] = []


@dataclass
class Check:
    cid: str
    name: str
    ok: bool
    detail: str = ""


def check(cid: str, name: str, ok: bool, detail: str = "") -> None:
    results.append(Check(cid, name, bool(ok), detail))
    print(f"[{'PASS' if ok else 'FAIL'}] {cid}  {name}")
    if detail:
        print(f"        {detail}")


def run(cmd: list[str], cwd: Path | None = None, timeout: int = 300) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, cwd=str(cwd) if cwd else None, capture_output=True, text=True, timeout=timeout)


def http(method: str, path: str, token: str = "", body: object = None, headers: dict | None = None,
         timeout: int = 10) -> tuple[int, bytes, dict]:
    h: dict[str, str] = {"X-Request-Id": "e2e-" + os.urandom(4).hex()}
    if token:
        h["Authorization"] = f"Bearer {token}"
    data = None
    if body is not None:
        data = json.dumps(body).encode()
        h["Content-Type"] = "application/json"
    if headers:
        h.update(headers)
    req = urllib.request.Request(BASE + path, data=data, headers=h, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read(1 << 20), dict(resp.headers)
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read(1 << 20), dict(exc.headers)
    except urllib.error.URLError as exc:
        return 0, str(exc).encode(), {}


def get_json(path: str, token: str) -> tuple[int, object]:
    status, raw, _ = http("GET", path, token)
    try:
        return status, json.loads(raw) if raw else None
    except json.JSONDecodeError:
        return status, None


def wait_health(deadline_s: int = TIMEOUT_UP) -> bool:
    deadline = time.time() + deadline_s
    while time.time() < deadline:
        status, _, _ = http("GET", "/api/v1/health", timeout=2)
        if status == 200:
            return True
        time.sleep(0.4)
    return False


def main() -> int:
    work = ROOT / "var" / "e2e"
    if work.exists():
        shutil.rmtree(work, ignore_errors=True)
    work.mkdir(parents=True, exist_ok=True)
    BIN.mkdir(parents=True, exist_ok=True)

    retaild = BIN / ("retaild.exe" if os.name == "nt" else "retaild")
    sim = BIN / ("retail-sim.exe" if os.name == "nt" else "retail-sim")

    # --- Build -----------------------------------------------------------------
    print("=== GeDefense Retail E2E ===")
    for target, out in (("./cmd/retaild", retaild), ("./cmd/retail-sim", sim)):
        proc = run(["go", "build", "-trimpath", "-o", str(out), target], cwd=MODULE)
        ok = proc.returncode == 0
        check("BUILD-" + target.split("/")[-1], f"go build {target}", ok, (proc.stderr or "").strip()[:400])
        if not ok:
            return finish()

    # --- Tokens ----------------------------------------------------------------
    tokens: dict[str, dict] = {}
    for user, role in (("admin", "admin"), ("technik-01", "operator"), ("viewer-01", "viewer")):
        proc = run([str(retaild), "gen-token", "--user", user, "--role", role])
        try:
            tokens[user] = json.loads(proc.stdout)
        except json.JSONDecodeError:
            check("CFG-01", "gen-token output is JSON", False, proc.stdout[:300] + proc.stderr[:300])
            return finish()
    check("CFG-01", "gen-token erzeugt drei getrennte Zufalls-Tokens", len(tokens) == 3,
          ", ".join(tokens))

    # --- Configuration ---------------------------------------------------------
    cfg = json.loads((ROOT / "config" / "retail.example.json").read_text(encoding="utf-8"))
    cfg["listen"] = LISTEN
    cfg["data_dir"] = str(work / "data")
    cfg["log_level"] = "debug"
    cfg["simulation"] = {"enabled": True, "listen": LISTEN}
    cfg["security"] = {
        "require_whitelist": True,
        "dashboard_whitelist_cidrs": ["127.0.0.1/32", "::1/128"],
        "trust_proxy_headers": False,
        "setup_token_ttl_s": 3600,
    }
    cfg["setup"] = {"completed": True, "completed_at": "2026-11-03T12:00:00Z", "language": "de"}
    cfg["collectors"] = []
    for user in cfg["users"]:
        user["token_sha256"] = tokens[user["user_id"]]["token_sha256"]
    cfg_path = work / "retail.json"
    cfg_path.write_text(json.dumps(cfg, indent=2), encoding="utf-8")

    proc = run([str(retaild), "check", "--config", str(cfg_path)])
    check("CFG-02", "retaild check validiert Konfiguration (Exit 0)", proc.returncode == 0,
          (proc.stdout or proc.stderr).strip()[:500])
    if proc.returncode != 0:
        return finish()

    # --- Start gateway ---------------------------------------------------------
    stdout_path, stderr_path = work / "retaild.stdout.log", work / "retaild.stderr.log"
    with open(stdout_path, "w", encoding="utf-8") as out, open(stderr_path, "w", encoding="utf-8") as err:
        server = subprocess.Popen([str(retaild), "serve", "--config", str(cfg_path)],
                                  stdout=out, stderr=err, cwd=str(ROOT))
    admin = tokens["admin"]["token"]
    operator = tokens["technik-01"]["token"]
    viewer = tokens["viewer-01"]["token"]

    try:
        up = wait_health()
        check("HLT-01", "Dienst startet und /health antwortet", up)
        if not up:
            print(stderr_path.read_text(encoding="utf-8", errors="replace")[-3000:])
            return finish(server)

        status, health = get_json("/api/v1/health", admin)
        health = health or {}
        storage = health.get("storage", {}) if isinstance(health, dict) else {}
        check("HLT-02", "/health: status=ok, read_only=true",
              status == 200 and health.get("status") == "ok" and health.get("read_only") is True,
              f"status={health.get('status')} read_only={health.get('read_only')}")
        check("HLT-03", "/health: Audit-Kette beim Start ok", storage.get("audit_chain_ok") is True,
              f"audit_chain_ok={storage.get('audit_chain_ok')}")

        # --- Auth / RBAC ------------------------------------------------------
        st, _, _ = http("GET", "/api/v1/overview")
        check("AUTH-01", "GET /overview ohne Token -> 401", st == 401, f"status={st}")
        st, _, _ = http("GET", "/api/v1/overview", "invalid-token")
        check("AUTH-02", "GET /overview mit ungültigem Token -> 401", st == 401, f"status={st}")
        st, _, _ = http("GET", "/api/v1/overview", viewer)
        check("AUTH-03", "GET /overview als viewer -> 200", st == 200, f"status={st}")
        st, _, _ = http("POST", "/api/v1/alerts/alr_doesnotexist/ack", viewer, {"note": "x"})
        check("AUTH-04", "POST Alert-Ack als viewer -> 403", st == 403, f"status={st}")
        st, _, _ = http("POST", "/api/v1/policies/reload", operator)
        check("AUTH-05", "POST /policies/reload als operator -> 403", st == 403, f"status={st}")

        # --- Security headers -------------------------------------------------
        st, _, headers = http("GET", "/api/v1/meta", admin)
        csp = headers.get("Content-Security-Policy", "")
        nosniff = headers.get("X-Content-Type-Options", "")
        frame = headers.get("X-Frame-Options", "")
        check("SEC-01", "CSP gesetzt, kein unsafe-inline", bool(csp) and "unsafe-inline" not in csp, f"csp={csp[:120]}")
        check("SEC-02", "nosniff + X-Frame-Options DENY", nosniff.lower() == "nosniff" and frame.upper() == "DENY",
              f"nosniff={nosniff} frame={frame}")

        # --- Validation -------------------------------------------------------
        st, _, _ = http("POST", "/api/v1/windows", admin, {"unknown_field": 1})
        check("VAL-01", "unbekanntes JSON-Feld -> 400", st == 400, f"status={st}")

        # --- Dev ingest guards ------------------------------------------------
        st, _, _ = http("POST", "/api/v1/dev/events", admin, {"events": []})
        check("DEV-01", "dev-ingest ohne X-GeDefense-Sim -> 404", st == 404, f"status={st}")

        # --- Simulator feed ---------------------------------------------------
        print(f"--- Simulator-Feed (Szenario {SCENARIO}) ---")
        feed = run([str(sim), "feed", "--url", BASE, "--token", admin, "--scenario", SCENARIO,
                    "--duration", "20", "--rate", "20", "--batch", "50"])
        feed_out = (feed.stdout + feed.stderr).strip()
        print(feed_out[-1500:])
        check("SIM-01", f"retail-sim feed ({SCENARIO}) erfolgreich", feed.returncode == 0, feed_out[-300:])

        # --- Detection --------------------------------------------------------
        deadline = time.time() + 60
        alerts = {}
        while time.time() < deadline:
            st, alerts = get_json("/api/v1/alerts?limit=50", admin)
            alerts = alerts or {}
            if alerts.get("total", 0) > 0:
                break
            time.sleep(2)
        total = alerts.get("total", 0) if isinstance(alerts, dict) else 0
        check("DET-01", "Detection erzeugt Alerts aus synthetischen Beobachtungen", total > 0, f"total={total}")

        if total > 0:
            first = alerts["items"][0]
            check("DET-02", "Alerts enthalten Evidenz, Rule-ID, Rule-Version",
                  bool(first.get("evidence")) and bool(first.get("rule_id")) and bool(first.get("rule_version")),
                  f"rule={first.get('rule_id')} evidence={len(first.get('evidence', []))}")
            check("DET-03", "Alerts tragen Zusammenfassung/Correlation (Fakten vs. Hypothese)",
                  bool(first.get("summary")), f"summary_len={len(first.get('summary', ''))}")
            aid = first["alert_id"]
            st, _, _ = http("POST", f"/api/v1/alerts/{aid}/ack", operator, {"note": "E2E: Betreiber informiert"})
            check("DET-04", "Operator kann Alert bestätigen (acknowledged)",
                  st == 200, f"status={st}")
            st, _, _ = http("POST", f"/api/v1/alerts/{aid}/close", operator,
                            {"status": "false_positive", "note": "E2E: Abtauzyklus"})
            st2, closed = get_json(f"/api/v1/alerts/{aid}", admin)
            closed = closed or {}
            alert = closed.get("alert", {}) if isinstance(closed, dict) else {}
            check("DET-05", "Operator kann Alert schließen (false_positive)",
                  st == 200 and alert.get("status") == "false_positive",
                  f"status={st} alert_status={alert.get('status')}")

        # --- Cold chain -------------------------------------------------------
        st, cc = get_json("/api/v1/coldchain", admin)
        cc = cc or {}
        points = sum(len(item.get("series", {}).get("points", [])) for item in cc.get("items", []))
        check("CC-01", "Coldchain liefert Telemetrie-Serien", st == 200 and points > 0, f"points={points}")

        # --- Audit ------------------------------------------------------------
        st, audit = get_json("/api/v1/audit?limit=200", admin)
        audit = audit or {}
        check("AUD-01", "Audit-Kette bleibt gültig", st == 200 and audit.get("chain_ok") is True,
              f"chain_ok={audit.get('chain_ok')} entries={len(audit.get('items', []))}")

        # --- Endpoint smoke ---------------------------------------------------
        for cid, path in (("API-01", "/api/v1/overview"), ("API-02", "/api/v1/assets"),
                          ("API-03", "/api/v1/timeline"), ("API-04", "/api/v1/incidents"),
                          ("API-05", "/api/v1/policies"), ("API-06", "/api/v1/access"),
                          ("API-07", "/api/v1/integrity"), ("API-08", "/api/v1/collectors")):
            st, _ = get_json(path, admin)
            check(cid, f"GET {path} -> 200", st == 200, f"status={st}")

        # --- UI ---------------------------------------------------------------
        st, raw, _ = http("GET", "/", timeout=10)
        html = raw.decode("utf-8", errors="replace")
        check("UI-01", "Dashboard-HTML wird ausgeliefert", st == 200 and "GeDefense" in html, f"status={st} bytes={len(raw)}")
        low = html.lower()
        check("UI-02", "UI ohne externe CDN-Referenzen",
              not any(x in low for x in ("cdn.", "fonts.googleapis", "unpkg.com", "jsdelivr")),
              "keine externen Hosts im HTML")

        # --- Safety: no write/scan/control endpoints --------------------------
        for path in ("/api/v1/ot/write", "/api/v1/scan", "/api/v1/control", "/api/v1/policy/write"):
            st, _, _ = http("POST", path, admin, {})
            check("SAFE-" + path.strip("/").replace("/", "-").upper(), f"kein Endpunkt POST {path} (404/405)",
                  st in (404, 405), f"status={st}")

        # --- SSE auth ---------------------------------------------------------
        st, _, _ = http("GET", "/api/v1/stream", timeout=5)
        check("SSE-01", "SSE-Stream ohne Token -> 401", st == 401, f"status={st}")
    finally:
        pass

    return finish(server)


def finish(server: subprocess.Popen | None = None) -> int:
    if server is not None and server.poll() is None:
        server.terminate()
        try:
            server.wait(timeout=10)
        except subprocess.TimeoutExpired:
            server.kill()
    print()
    print("=== Ergebnis ===")
    passed = sum(1 for r in results if r.ok)
    failed = [r for r in results if not r.ok]
    for r in results:
        if not r.ok:
            print(f" - FAIL {r.cid}: {r.name} ({r.detail})")
    print(f"E2E: {passed}/{len(results)} PASS, {len(failed)} FAIL")
    if failed:
        log = ROOT / "var" / "e2e" / "retaild.stderr.log"
        if log.exists():
            print("--- retaild stderr (tail) ---")
            print("\n".join(log.read_text(encoding="utf-8", errors="replace").splitlines()[-15:]))
        return 1
    print("ALLE E2E-PRUEFUNGEN BESTANDEN (Loopback/Simulation; keine echte OT-Hardware).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
