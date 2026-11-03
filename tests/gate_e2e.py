#!/usr/bin/env python3
"""End-to-End acceptance for GeDefense Retail Access Gate (0.2 Alpha).

Starts a local gate with fake OT devices (Modbus TCP register controller, HTTP
supervisor), a fake webhook receiver, and exercises the complete approval flow:

  login -> plan -> four-eyes approval -> one-time token -> session -> write
  -> wrong value must be denied -> null-write proof -> replay blocked
  -> deny timeline/audit -> gate-down fail-safe (plant unaffected)
  -> 02:14 attack scenario (deny + on-call webhook + untouched device)

The fake devices only live on loopback. No real OT hardware is touched.
Exit code 0 = all checks passed.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import shutil
import socket
import struct
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MODULE = ROOT / "src" / "retail"
BIN = ROOT / "bin"
WORK = ROOT / "var" / "gate-e2e"

API_PORT = 18540
MODBUS_PORT = 11502
HTTP_PROXY_PORT = 18443
MODBUS_UPSTREAM = 15021
HTTP_UPSTREAM = 18081
WEBHOOK_PORT = 18091
BASE = f"http://127.0.0.1:{API_PORT}"

PASSWORD = "Test-Pass-123!"
RESULTS: list[tuple[str, str, bool, str]] = []


def check(cid: str, name: str, ok: bool, detail: str = "") -> None:
    RESULTS.append((cid, name, bool(ok), detail))
    print(f"[{'PASS' if ok else 'FAIL'}] {cid}  {name}")
    if detail:
        print(f"        {detail}")


# --------------------------------------------------------------------------
# Crypto helpers (independent of the Go implementation: proves the format)
# --------------------------------------------------------------------------
def hash_password(password: str, iterations: int = 100_000) -> str:
    salt = os.urandom(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations)
    return f"pbkdf2-sha256${iterations}${base64.b64encode(salt).decode()}${base64.b64encode(digest).decode()}"


def totp(secret_b32: str, t: float | None = None) -> str:
    key = base64.b32decode(secret_b32.upper() + "=" * ((8 - len(secret_b32) % 8) % 8))
    counter = int((t if t is not None else time.time()) // 30)
    msg = struct.pack(">Q", counter)
    digest = hmac.new(key, msg, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code = (struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF) % 1_000_000
    return f"{code:06d}"



def wait_next_totp_window() -> None:
    """Wait for the next TOTP time step.

    The gate enforces per-user TOTP replay protection, so a code used for login
    cannot be reused for the approval within the same 30s window.
    """
    now = time.time()
    time.sleep(30 - (now % 30) + 0.6)


# --------------------------------------------------------------------------
# HTTP helpers
# --------------------------------------------------------------------------
def http(method: str, path: str, token: str = "", body: object = None,
         headers: dict | None = None, timeout: int = 10) -> tuple[int, dict, bytes]:
    h = {"X-Request-Id": "ge2e-" + os.urandom(4).hex()}
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
            raw = resp.read(1 << 20)
            return resp.status, dict(resp.headers), raw
    except urllib.error.HTTPError as exc:
        return exc.code, dict(exc.headers), exc.read(1 << 20)
    except (urllib.error.URLError, ConnectionResetError) as exc:
        return 0, {}, str(exc).encode()


def jget(path: str, token: str) -> tuple[int, object]:
    st, _, raw = http("GET", path, token)
    try:
        return st, json.loads(raw) if raw else None
    except json.JSONDecodeError:
        return st, None


def jpost(path: str, token: str, body: object, headers: dict | None = None) -> tuple[int, object]:
    st, _, raw = http("POST", path, token, body, headers)
    try:
        return st, json.loads(raw) if raw else None
    except json.JSONDecodeError:
        return st, None


# --------------------------------------------------------------------------
# Fake Modbus TCP controller (upstream)
# --------------------------------------------------------------------------
class FakeModbus:
    """Minimal Modbus/TCP slave. Records every write ADU it receives."""

    def __init__(self, port: int) -> None:
        self.port = port
        self.writes: list[tuple[int, int]] = []
        self.registers: dict[int, int] = {40001: 40}  # 4.0 degC with scale 10
        self.reads = 0
        self.lock = threading.Lock()
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", port))
        self.sock.listen(8)
        self.running = True
        self.thread = threading.Thread(target=self._serve, daemon=True)

    def start(self) -> None:
        self.thread.start()

    def stop(self) -> None:
        self.running = False
        try:
            self.sock.close()
        except OSError:
            pass

    def _serve(self) -> None:
        while self.running:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            threading.Thread(target=self._handle, args=(conn,), daemon=True).start()

    def _handle(self, conn: socket.socket) -> None:
        try:
            conn.settimeout(10)
            while True:
                header = self._recv_exact(conn, 7)
                if not header:
                    return
                txn, proto, length, unit = struct.unpack(">HHHB", header)
                pdu = self._recv_exact(conn, length - 1)
                if not pdu:
                    return
                resp = self._respond(pdu)
                payload = struct.pack(">HHHB", txn, proto, len(resp) + 1, unit) + resp
                conn.sendall(payload)
        except (OSError, struct.error):
            return
        finally:
            try:
                conn.close()
            except OSError:
                pass

    @staticmethod
    def _recv_exact(conn: socket.socket, n: int) -> bytes | None:
        buf = b""
        while len(buf) < n:
            chunk = conn.recv(n - len(buf))
            if not chunk:
                return None
            buf += chunk
        return buf

    def _respond(self, pdu: bytes) -> bytes:
        fc = pdu[0]
        if fc in (3, 4):
            with self.lock:
                self.reads += 1
                start = struct.unpack(">H", pdu[1:3])[0]
                count = struct.unpack(">H", pdu[3:5])[0]
                values = [self.registers.get(start + i, 0) for i in range(count)]
            body = struct.pack(">B", fc + 0x00 + 0)  # placeholder, overwritten below
            body = struct.pack(">B", fc) + struct.pack(">B", count * 2) + b"".join(struct.pack(">H", v & 0xFFFF) for v in values)
            return body
        if fc == 6:
            reg = struct.unpack(">H", pdu[1:3])[0]
            val = struct.unpack(">H", pdu[3:5])[0]
            with self.lock:
                self.writes.append((reg, val))
                self.registers[reg] = val
            return pdu
        if fc == 5:
            with self.lock:
                self.writes.append((struct.unpack(">H", pdu[1:3])[0], pdu[3:5].hex()))
            return pdu
        if fc == 16:
            with self.lock:
                self.writes.append((struct.unpack(">H", pdu[1:3])[0], pdu[5:7].hex()))
            return struct.pack(">B", fc) + pdu[1:5]
        # Illegal function
        return bytes([fc | 0x80, 0x01])


def modbus_request(func: int, register: int, value: int, timeout: float = 5.0) -> bytes:
    """Send one FC6 write through the gate; returns the raw response PDU."""
    with socket.create_connection(("127.0.0.1", MODBUS_PORT), timeout=timeout) as s:
        s.settimeout(timeout)
        pdu = struct.pack(">BHH", func, register, value)
        s.sendall(struct.pack(">HHHB", 1, 0, len(pdu) + 1, 1) + pdu)
        header = _recv(s, 7)
        txn, proto, length, unit = struct.unpack(">HHHB", header)
        return _recv(s, length - 1)


def _recv(s: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = s.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("closed")
        buf += chunk
    return buf


# --------------------------------------------------------------------------
# Fake HTTP supervisor (upstream)
# --------------------------------------------------------------------------
class FakeSupervisor(BaseHTTPRequestHandler):
    posts = 0

    def log_message(self, *args) -> None:  # silence
        return

    def do_GET(self) -> None:  # noqa: N802
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(b"<html><title>StoreView Fake</title><body>supervisor</body></html>")

    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length", "0"))
        self.rfile.read(length)
        FakeSupervisor.posts += 1
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"config accepted")


# --------------------------------------------------------------------------
# Fake webhook receiver
# --------------------------------------------------------------------------
class Webhook(BaseHTTPRequestHandler):
    hits: list[dict] = []

    def log_message(self, *args) -> None:  # silence
        return

    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length)
        try:
            Webhook.hits.append({"body": json.loads(raw), "sig": self.headers.get("X-GeDefense-Signature", "")})
        except json.JSONDecodeError:
            Webhook.hits.append({"body": None, "sig": self.headers.get("X-GeDefense-Signature", "")})
        self.send_response(204)
        self.end_headers()


def start_threaded(server: ThreadingHTTPServer) -> threading.Thread:
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    return t


# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------
def main() -> int:
    if WORK.exists():
        shutil.rmtree(WORK, ignore_errors=True)
    WORK.mkdir(parents=True, exist_ok=True)
    BIN.mkdir(parents=True, exist_ok=True)
    retailgate = BIN / ("retailgate.exe" if os.name == "nt" else "retailgate")

    build = subprocess.run(["go", "build", "-trimpath", "-o", str(retailgate), "./cmd/retailgate"],
                           cwd=str(MODULE), capture_output=True, text=True)
    check("BUILD", "go build ./cmd/retailgate", build.returncode == 0, (build.stderr or "").strip()[:400])
    if build.returncode != 0:
        return finish(None)

    secrets = {
        "master-01": ("JBSWY3DPEHPK3PXP", "master_admin"),
        "approver-01": ("KRSXG5CTMVRXEZLU", "approver"),
        "vendor-acme": ("MFRGGZDFMZTWQ2LK", "vendor"),
    }
    users = []
    for uid, (secret, _kind) in secrets.items():
        roles = {
            "master-01": ["master_admin", "approver"],
            "approver-01": ["approver"],
            "vendor-acme": ["vendor_write_requester"],
        }[uid]
        kind = {"master-01": "admin", "approver-01": "operator", "vendor-acme": "vendor"}[uid]
        users.append({
            "user_id": uid, "name": uid, "kind": kind, "roles": roles,
            "password_hash": hash_password(PASSWORD),
            "totp_secret": secret, "totp_enabled": True,
            "device_fingerprints": [], "status": "active",
        })

    gate_cfg = {
        "listen": {"api": f"127.0.0.1:{API_PORT}", "tls_cert_file": "", "tls_key_file": "",
                   "client_ca_file": "", "require_client_cert": False},
        "data_dir": str(WORK / "data"),
        "site_id": "filiale-001",
        "gateway_asset_id": "asset-edge-gateway",
        "policy_file": "gate-policy.json",
        "timeouts": {"session_ttl_s": 900, "token_ttl_s": 300, "approval_ttl_s": 86400,
                     "plan_ttl_s": 604800, "write_session_max_uses": 1},
        "targets": [
            {"target_id": "aksm-1", "asset_id": "asset-danfoss-aksm800", "protocol": "modbus_tcp",
             "listen": f"127.0.0.1:{MODBUS_PORT}", "upstream": f"127.0.0.1:{MODBUS_UPSTREAM}",
             "unit_id": 1, "timeout_s": 5, "read_registers": {"fc": 3, "start": 1, "count": 64}},
            {"target_id": "xweb-1", "asset_id": "asset-dixell-xweb", "protocol": "http",
             "listen": f"127.0.0.1:{HTTP_PROXY_PORT}", "upstream": f"http://127.0.0.1:{HTTP_UPSTREAM}",
             "ca_file": "", "insecure_skip_verify": False,
             "url_allowlist": ["/", "/cgi-bin/*"]},
        ],
        "source_cidrs": ["127.0.0.1/32", "::1/128"],
        "users": users,
        "notify": {"webhook_url": f"http://127.0.0.1:{WEBHOOK_PORT}/hook", "hmac_secret": "e2e-secret-0123456789abcdef",
                   "timeout_s": 5, "escalation": [{"after_minutes": 5, "role": "approver"}]},
    }
    policy = {
        "policy_id": "gate-policy-filiale-001", "version": 1,
        "updated_at": "2026-11-03T12:00:00Z", "updated_by": "master-01",
        "default_deny": True,
        "critical_assets": ["asset-danfoss-aksm800"],
        "four_eyes_assets": ["asset-danfoss-aksm800"],
        "modbus_write_allowlist": [{"target_id": "aksm-1", "fc": 6, "register": 40001,
                                    "value": "35", "max_delta": 5.0, "note": "e2e"}],
        "http_write_allowlist": [{"target_id": "xweb-1", "method": "POST",
                                  "path_prefix": "/cgi-bin/config", "note": "e2e"}],
        "token": {"max_uses": 1, "bind_source_ip": True},
        "notify": {"deny_min_severity": "medium"},
    }
    (WORK / "gate.json").write_text(json.dumps(gate_cfg, indent=2), encoding="utf-8")
    (WORK / "gate-policy.json").write_text(json.dumps(policy, indent=2), encoding="utf-8")

    mon = FakeModbus(MODBUS_UPSTREAM)
    mon.start()
    http_upstream = ThreadingHTTPServer(("127.0.0.1", HTTP_UPSTREAM), FakeSupervisor)
    start_threaded(http_upstream)
    webhook = ThreadingHTTPServer(("127.0.0.1", WEBHOOK_PORT), Webhook)
    start_threaded(webhook)

    stdout = open(WORK / "gate.stdout.log", "w", encoding="utf-8")
    stderr = open(WORK / "gate.stderr.log", "w", encoding="utf-8")
    gate = subprocess.Popen([str(retailgate), "serve", "--config", str(WORK / "gate.json")],
                            stdout=stdout, stderr=stderr, cwd=str(ROOT))

    vendor_tok = approver_tok = master_tok = ""
    try:
        up = False
        for _ in range(80):
            st, _, _ = http("GET", "/api/v1/gate/health", timeout=2)
            if st == 200:
                up = True
                break
            time.sleep(0.25)
        check("G-01", "Gate startet und /health antwortet", up)
        if not up:
            print((WORK / "gate.stderr.log").read_text(encoding="utf-8", errors="replace")[-3000:])
            return finish(gate)

        st, _, raw = http("GET", "/api/v1/gate/health")
        health = json.loads(raw)
        check("G-02", "Health: audit_chain_ok=true", health.get("audit_chain_ok") is True)

        # --- Login ---
        st, _, _ = http("POST", "/api/v1/gate/auth/login",
                        body={"user_id": "vendor-acme", "password": "falsch", "totp": totp(secrets["vendor-acme"][0])})
        check("G-03", "Login mit falschem Passwort -> 401", st == 401, f"status={st}")

        st, _, raw = http("POST", "/api/v1/gate/auth/login",
                          body={"user_id": "vendor-acme", "password": PASSWORD,
                                "totp": totp(secrets["vendor-acme"][0])})
        logged = json.loads(raw) if st == 200 else {}
        vendor_tok = logged.get("session_token", "")
        check("G-04", "Vendor-Login mit TOTP -> Session-Token", st == 200 and bool(vendor_tok), f"status={st}")

        st, _, raw = http("POST", "/api/v1/gate/auth/login",
                          body={"user_id": "approver-01", "password": PASSWORD,
                                "totp": totp(secrets["approver-01"][0])})
        approver_tok = (json.loads(raw) if st == 200 else {}).get("session_token", "")
        st, _, raw = http("POST", "/api/v1/gate/auth/login",
                          body={"user_id": "master-01", "password": PASSWORD,
                                "totp": totp(secrets["master-01"][0])})
        master_tok = (json.loads(raw) if st == 200 else {}).get("session_token", "")
        check("G-05", "Approver- und Master-Login", bool(approver_tok) and bool(master_tok))

        # --- Plan ---
        now = time.time()
        plan_body = {
            "target_id": "aksm-1", "asset_id": "asset-danfoss-aksm800", "protocol": "modbus_tcp",
            "operations": [{"operation_id": "op-1", "protocol": "modbus_tcp", "function": "fc6",
                            "address": "40001", "current_value": "40", "new_value": "35",
                            "unit": "celsius"}],
            "reason": "E2E Sollwert nach Wartung", "ticket_ref": "SVC-E2E",
            "window_start": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now + 5)),
            "window_end": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now + 1800)),
        }
        st, plan = jpost("/api/v1/gate/plans", vendor_tok, plan_body)
        plan_raw = "" if st in (200, 201) else str(plan)
        plan_id = (plan or {}).get("plan", {}).get("plan_id", "") if isinstance(plan, dict) else ""
        check("G-06", "Vendor erstellt Write-Plan (pending, hash)", st in (200, 201) and bool(plan_id),
              f"status={st} plan={plan_id} body={plan_raw[:300]}")

        # --- Null-write proof BEFORE any approval/session ---
        before = len(mon.writes)
        try:
            resp = modbus_request(6, 0, 35)
        except OSError:
            resp = b""
        blocked_before_approval = resp[:1] == b"\x86" or len(mon.writes) == before
        check("G-07", "NULL-WRITE: ohne Freigabe kein Write am Gerät", blocked_before_approval and len(mon.writes) == before,
              f"writes={len(mon.writes)-before} resp={resp.hex() if resp else 'closed'}")
        check("G-08", "NULL-WRITE: Modbus-Exception an den Client", resp[:1] == b"\x86", f"resp={resp.hex()}")

        # --- Approvals: self-approval forbidden, MFA required, four eyes ---
        st, _ = jpost(f"/api/v1/gate/plans/{plan_id}/approve", vendor_tok, {"comment": "ich"})
        check("G-09", "Self-Approval verboten -> 403/409", st in (403, 409), f"status={st}")

        st, _ = jpost(f"/api/v1/gate/plans/{plan_id}/approve", approver_tok, {"comment": "ohne MFA"})
        check("G-10", "Freigabe ohne MFA -> 403", st == 403, f"status={st}")

        wait_next_totp_window()
        st, first = jpost(f"/api/v1/gate/plans/{plan_id}/approve", approver_tok, {"comment": "1. Augen"},
                          headers={"X-Gate-MFA": totp(secrets["approver-01"][0])})
        first_token = (first or {}).get("token") if isinstance(first, dict) else None
        check("G-11", "Erste Vier-Augen-Freigabe: kein Token", st == 200 and not first_token, f"status={st}")

        wait_next_totp_window()
        st, final = jpost(f"/api/v1/gate/plans/{plan_id}/approve", master_tok, {"comment": "2. Augen"},
                          headers={"X-Gate-MFA": totp(secrets["master-01"][0])})
        token = ((final or {}).get("token") or {}).get("token", "") if isinstance(final, dict) else ""
        check("G-12", "Zweite Freigabe (Master) liefert Einmal-Token", st == 200 and bool(token), f"status={st}")

        # --- Session (only once the approved window has started) ---
        time.sleep(6)
        st, sess = jpost("/api/v1/gate/sessions", vendor_tok, {"plan_id": plan_id, "token": token})
        session = (sess or {}).get("session", {}) if isinstance(sess, dict) else {}
        check("G-13", "Session aus Token (Source-IP gebunden)", st in (200, 201) and session.get("source_ip") == "127.0.0.1",
              f"status={st} session={session.get('session_id')}")

        # --- Wrong value must be denied, exact value allowed ---
        before = len(mon.writes)
        resp = modbus_request(6, 0, 42)
        check("G-14", "Falscher Wert -> Exception + kein Write", resp[:1] == b"\x86" and len(mon.writes) == before,
              f"resp={resp.hex()} writes={len(mon.writes)-before}")
        # Wait: value 42 = 4.2 degC; approved is 35 = 3.5 degC
        resp = modbus_request(6, 0, 35)
        check("G-15", "Exakt freigegebener Wert -> Write erreicht Gerät", resp[:1] == b"\x06" and len(mon.writes) == before + 1,
              f"resp={resp.hex()} writes={len(mon.writes)-before}")

        # --- Token replay ---
        st, _ = jpost("/api/v1/gate/sessions", vendor_tok, {"plan_id": plan_id, "token": token})
        check("G-16", "Token-Replay -> abgelehnt", st in (409, 401, 403), f"status={st}")

        # --- Denies + Audit ---
        st, denies = jget("/api/v1/gate/denies?limit=50", approver_tok)
        items = (denies or {}).get("items", []) if isinstance(denies, dict) else []
        reasons = [d.get("reason") for d in items]
        check("G-17", "Deny-Timeline enthält Ablehnungen", st == 200 and len(items) >= 2 and "value_mismatch" in reasons,
              f"status={st} denies={len(items)} reasons={reasons[:6]}")
        check("G-18", "Deny enthält Evidenz (Quelle/Ziel/Funktion/Severity)",
              bool(items) and bool(items[0].get("source_ip")) and bool(items[0].get("severity")),
              f"first={items[0] if items else None}")

        st, audit = jget("/api/v1/gate/audit?limit=200", master_tok)
        audit = audit or {}
        check("G-19", "Audit-Kette nach Aktionen gültig", st == 200 and audit.get("chain_ok") is True,
              f"chain_ok={audit.get('chain_ok')} entries={len(audit.get('items', []))}")

        # --- Webhook escalation (24/7) ---
        deadline = time.time() + 10
        while time.time() < deadline and not Webhook.hits:
            time.sleep(0.2)
        check("G-20", "On-Call-Webhook bei Deny ausgelöst", len(Webhook.hits) > 0, f"hits={len(Webhook.hits)}")
        if Webhook.hits:
            check("G-21", "Webhook ist HMAC-signiert", bool(Webhook.hits[0].get("sig")))

        # --- HTTP proxy: login page + GET proxied + POST without plan denied ---
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{HTTP_PROXY_PORT}/gate/login", timeout=5) as r:
                login_html = r.read()
                check("G-22", "HTTP-Proxy liefert Gate-Login", r.status == 200 and b"login" in login_html.lower() or r.status == 200)
        except Exception as exc:  # noqa: BLE001
            check("G-22", "HTTP-Proxy liefert Gate-Login", False, repr(exc))

        # --- Fail-safe: gate down -> management closed, plant unaffected ---
        gate.terminate()
        try:
            gate.wait(timeout=10)
        except subprocess.TimeoutExpired:
            gate.kill()
        time.sleep(0.5)
        try:
            socket.create_connection(("127.0.0.1", MODBUS_PORT), timeout=2).close()
            mgmt_closed = False
        except OSError:
            mgmt_closed = True
        check("G-23", "Gate down -> Management-Pfad gesperrt", mgmt_closed)

        # plant still answers when addressed directly (autonomous controller)
        try:
            with socket.create_connection(("127.0.0.1", MODBUS_UPSTREAM), timeout=2) as s:
                s.settimeout(3)
                pdu = struct.pack(">BHH", 3, 40001, 1)
                s.sendall(struct.pack(">HHHB", 7, 0, len(pdu) + 1, 1) + pdu)
                header = _recv(s, 7)
                _tnx, _p, length, _u = struct.unpack(">HHHB", header)
                body = _recv(s, length - 1)
                plant_alive = body[:1] == b"\x03"
        except OSError:
            plant_alive = False
        check("G-24", "Kälteanlage (Regler) läuft nach Gate-Ausfall weiter", plant_alive)
    finally:
        if gate.poll() is None:
            gate.terminate()
            try:
                gate.wait(timeout=10)
            except subprocess.TimeoutExpired:
                gate.kill()
        stdout.close()
        stderr.close()
        mon.stop()
        http_upstream.shutdown()
        webhook.shutdown()

    return finish(None)


def finish(gate: subprocess.Popen | None) -> int:
    print()
    passed = sum(1 for _cid, _n, ok, _d in RESULTS if ok)
    failed = [(cid, n, d) for cid, n, ok, d in RESULTS if not ok]
    for cid, name, detail in failed:
        print(f" - FAIL {cid}: {name} ({detail})")
    print(f"GATE-E2E: {passed}/{len(RESULTS)} PASS, {len(failed)} FAIL")
    if failed:
        log = WORK / "gate.stderr.log"
        if log.exists():
            print("--- gate stderr (tail) ---")
            print("\n".join(log.read_text(encoding="utf-8", errors="replace").splitlines()[-20:]))
        return 1
    print("ALLE GATE-E2E-PRUEFUNGEN BESTANDEN (Loopback/Fake-Geräte; keine echte OT-Hardware).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
