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
# Unique work dir per run: prevents collisions with stale/concurrent gate-e2e
# processes (which previously deleted the data dir of a running gate).
WORK = ROOT / "var" / f"gate-e2e-{os.getpid()}"

API_PORT = 18540
MODBUS_PORT = 11502
HTTP_PROXY_PORT = 18443
MODBUS_UPSTREAM = 15021
MODBUS2_PORT = 11503
MODBUS2_UPSTREAM = 15022
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
    time.sleep(30 - (now % 30) + 1.5)


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
        self.coils: dict[int, bool] = {0: True}
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
        if fc in (1, 2):
            start = struct.unpack(">H", pdu[1:3])[0]
            count = struct.unpack(">H", pdu[3:5])[0]
            byte_count = (count + 7) // 8
            payload = bytearray(byte_count)
            if fc == 1:
                with self.lock:
                    self.reads += 1
                    for i in range(count):
                        if self.coils.get(start + i, False):
                            payload[i // 8] |= 1 << (i % 8)
            return bytes([fc, byte_count]) + bytes(payload)
        if fc in (3, 4):
            with self.lock:
                self.reads += 1
                start = struct.unpack(">H", pdu[1:3])[0]
                count = struct.unpack(">H", pdu[3:5])[0]
                # Operator convention: holding 40001+n corresponds to wire n.
                values = [self.registers.get(40001 + start + i, 0) for i in range(count)]
            body = struct.pack(">B", fc) + struct.pack(">B", count * 2) + b"".join(struct.pack(">H", v & 0xFFFF) for v in values)
            return body
        if fc == 6:
            reg = struct.unpack(">H", pdu[1:3])[0]
            val = struct.unpack(">H", pdu[3:5])[0]
            with self.lock:
                self.writes.append((reg, val))
                self.registers[40001 + reg] = val
            return pdu
        if fc == 5:
            raw = struct.unpack(">H", pdu[1:3])[0]
            val = struct.unpack(">H", pdu[3:5])[0]
            with self.lock:
                self.writes.append((raw, pdu[3:5].hex()))
                self.coils[raw] = val == 0xFF00
            return pdu
        if fc == 16:
            start = struct.unpack(">H", pdu[1:3])[0]
            qty = struct.unpack(">H", pdu[3:5])[0]
            with self.lock:
                self.writes.append((start, pdu[6:8].hex()))
                for i in range(qty):
                    self.registers[40001 + start + i] = struct.unpack(">H", pdu[6 + i * 2:8 + i * 2])[0]
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


def modbus_pdu(pdu: bytes, timeout: float = 5.0) -> bytes:
    """Send one raw PDU through the gate; returns the raw response PDU."""
    with socket.create_connection(("127.0.0.1", MODBUS_PORT), timeout=timeout) as s:
        s.settimeout(timeout)
        s.sendall(struct.pack(">HHHB", 1, 0, len(pdu) + 1, 1) + pdu)
        header = _recv(s, 7)
        _txn, _proto, length, _unit = struct.unpack(">HHHB", header)
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


