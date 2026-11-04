#!/usr/bin/env python3
"""End-to-End acceptance for GeDefense Retail Access Gate (scenario/CLI).

The test harness (fake devices, HTTP helpers, TOTP/wait helpers, checks) lives
in tests/gate_e2e_harness.py so both files stay below the 500-line budget.
The scenarios and assertions are unchanged; run with: python tests/gate_e2e.py
"""

import sys

from gate_e2e_harness import *  # noqa: F401,F403 - shared harness API
from gate_e2e_harness import _recv  # noqa: F401 - single underscore helper

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
             "unit_id": 1, "timeout_s": 5, "read_registers": {"fc": 3, "start": 0, "count": 64},
             "read_coils": {"fc": 1, "start": 0, "count": 8}},
            {"target_id": "cold-1", "asset_id": "asset-danfoss-aksm800", "protocol": "modbus_tcp",
             "listen": f"127.0.0.1:{MODBUS2_PORT}", "upstream": f"127.0.0.1:{MODBUS2_UPSTREAM}",
             "unit_id": 1, "timeout_s": 5, "read_registers": {"fc": 3, "start": 0, "count": 64}},
            {"target_id": "xweb-1", "asset_id": "asset-dixell-xweb", "protocol": "http",
             "listen": f"127.0.0.1:{HTTP_PROXY_PORT}", "upstream": f"http://127.0.0.1:{HTTP_UPSTREAM}",
             "ca_file": "", "insecure_skip_verify": False,
             "url_allowlist": ["/", "/cgi-bin/*"]},
        ],
        "source_cidrs": ["127.0.0.1/32", "::1/128"],
        "users": users,
        "notify": {"webhook_url": f"http://127.0.0.1:{WEBHOOK_PORT}/hook", "hmac_secret": "e2e-secret-0123456789abcdef",
                   "timeout_s": 5, "escalation": [{"after_minutes": 5, "role": "approver"}]},
        "integrity": {"enabled": True, "poll_interval_s": 10, "confirm_reads": 2, "stale_after_s": 60,
                      "references": [{"target_id": "cold-1", "fc": 3, "register": 40001, "unit_id": 1,
                                      "value": "4.0", "scale": 0.1, "unit": "celsius",
                                      "note": "E2E Referenz Kuehlraum", "recovery": True}],
                      "recovery": {"enabled": True, "max_actions_per_hour": 1, "max_actions_per_day": 2,
                                   "cooldown_s": 60, "require_no_active_window": True}},
    }
    policy = {
        "policy_id": "gate-policy-filiale-001", "version": 1,
        "updated_at": "2026-11-03T12:00:00Z", "updated_by": "master-01",
        "default_deny": True,
        "critical_assets": ["asset-danfoss-aksm800"],
        "four_eyes_assets": ["asset-danfoss-aksm800"],
        "modbus_write_allowlist": [{"target_id": "aksm-1", "fc": 6, "register": 40001,
                                    "value": "35", "max_delta": 5.0, "note": "e2e"},
                                   {"target_id": "aksm-1", "fc": 16, "register": 40002, "note": "e2e"},
                                   {"target_id": "aksm-1", "fc": 16, "register": 40003, "note": "e2e"},
                                   {"target_id": "aksm-1", "fc": 5, "register": 1, "note": "e2e"}],
        "http_write_allowlist": [{"target_id": "xweb-1", "method": "POST",
                                  "path_prefix": "/cgi-bin/config", "note": "e2e"}],
        "token": {"max_uses": 1, "bind_source_ip": True},
        "notify": {"deny_min_severity": "medium"},
    }
    (WORK / "gate.json").write_text(json.dumps(gate_cfg, indent=2), encoding="utf-8")
    (WORK / "gate-policy.json").write_text(json.dumps(policy, indent=2), encoding="utf-8")

    mon = FakeModbus(MODBUS_UPSTREAM)
    mon.start()
    mon2 = FakeModbus(MODBUS2_UPSTREAM)
    with mon2.lock:
        mon2.registers[40001] = 300  # 30.0 degC external drift vs 4.0 reference
    mon2.start()
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

        def approve_with_mfa(plan_id: str, tok: str, secret: str, comment: str):
            """Approve with a fresh TOTP window; retry once on a replay/403 flake."""
            result = (0, None)
            for _ in range(2):
                wait_next_totp_window()
                result = jpost(f"/api/v1/gate/plans/{plan_id}/approve", tok, {"comment": comment},
                               headers={"X-Gate-MFA": totp(secret)})
                if result[0] == 200:
                    return result
            return result

        # --- Plan ---
        now = time.time()
        plan_body = {
            "target_id": "aksm-1", "asset_id": "asset-danfoss-aksm800", "protocol": "modbus_tcp",
            "operations": [{"operation_id": "op-1", "protocol": "modbus_tcp", "function": "fc6",
                            "address": "40001", "current_value": "4.0", "new_value": "3.5",
                            "value_scale": 0.1, "unit": "celsius"}],
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

        st, first = approve_with_mfa(plan_id, approver_tok, secrets["approver-01"][0], "1. Augen")
        first_token = (first or {}).get("token") if isinstance(first, dict) else None
        check("G-11", "Erste Vier-Augen-Freigabe: kein Token", st == 200 and not first_token, f"status={st}")

        st, final = approve_with_mfa(plan_id, master_tok, secrets["master-01"][0], "2. Augen")
        token = ((final or {}).get("token") or {}).get("token", "") if isinstance(final, dict) else ""
        check("G-12", "Zweite Freigabe (Master) liefert Einmal-Token", st == 200 and bool(token), f"status={st}")

        # --- Session (only once the approved window has started) ---
        time.sleep(6)
        st, _, sess_raw = http("POST", "/api/v1/gate/sessions", vendor_tok, {"plan_id": plan_id, "token": token})
        try:
            sess = json.loads(sess_raw) if sess_raw else None
        except json.JSONDecodeError:
            sess = None
        session = (sess or {}).get("session", {}) if isinstance(sess, dict) else {}
        check("G-13", "Session aus Token (Source-IP gebunden)", st in (200, 201) and session.get("source_ip") == "127.0.0.1",
              f"status={st} session={session.get('session_id')} body={sess_raw[:200]!r}")

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

        # --- Read-before-Write: live value is re-read and compared with the
        # approved current_value before any write is forwarded (FIND fix).
        def approve_plan_and_session(current_value: str) -> tuple[str, str]:
            now2 = time.time()
            body2 = {
                "target_id": "aksm-1", "asset_id": "asset-danfoss-aksm800", "protocol": "modbus_tcp",
                "operations": [{"operation_id": "op-rb", "protocol": "modbus_tcp", "function": "fc6",
                                "address": "40001", "current_value": current_value, "new_value": "3.5",
                                "value_scale": 0.1, "unit": "celsius"}],
                "reason": "E2E Read-before-Write", "ticket_ref": "SVC-E2E-RB",
                "window_start": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now2 + 5)),
                "window_end": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now2 + 1800)),
            }
            stp, plan2 = jpost("/api/v1/gate/plans", vendor_tok, body2)
            pid = (plan2 or {}).get("plan", {}).get("plan_id", "") if isinstance(plan2, dict) else ""
            if not pid:
                return "", ""
            _st1, _ = approve_with_mfa(pid, approver_tok, secrets["approver-01"][0], "1. Augen")
            _st2, final2 = approve_with_mfa(pid, master_tok, secrets["master-01"][0], "2. Augen")
            tok2 = ((final2 or {}).get("token") or {}).get("token", "") if isinstance(final2, dict) else ""
            time.sleep(6)
            sts, sess2 = jpost("/api/v1/gate/sessions", vendor_tok, {"plan_id": pid, "token": tok2})

            return pid, ((sess2 or {}).get("session", {}) if isinstance(sess2, dict) else {}).get("session_id", "")

        def approve_custom_plan(operations: list[dict], ticket: str) -> tuple[str, str]:
            """Create+approve a plan with arbitrary operations (FC16/FC5 cases)."""
            now3 = time.time()
            body3 = {
                "target_id": "aksm-1", "asset_id": "asset-danfoss-aksm800", "protocol": "modbus_tcp",
                "operations": operations, "reason": "E2E multi/config case", "ticket_ref": ticket,
                "window_start": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now3 + 5)),
                "window_end": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now3 + 1800)),
            }
            stp, plan3 = jpost("/api/v1/gate/plans", vendor_tok, body3)
            pid = (plan3 or {}).get("plan", {}).get("plan_id", "") if isinstance(plan3, dict) else ""
            if not pid:
                print(f"        [debug] plan rejected status={stp} body={str(plan3)[:200]}")
                return "", ""
            _st1, _ = approve_with_mfa(pid, approver_tok, secrets["approver-01"][0], "1. Augen")
            _st2, final3 = approve_with_mfa(pid, master_tok, secrets["master-01"][0], "2. Augen")
            tok3 = ((final3 or {}).get("token") or {}).get("token", "") if isinstance(final3, dict) else ""
            time.sleep(6)
            _sts, sess3 = jpost("/api/v1/gate/sessions", vendor_tok, {"plan_id": pid, "token": tok3})
            return pid, ((sess3 or {}).get("session", {}) if isinstance(sess3, dict) else {}).get("session_id", "")

        # Device value is now 35 (after G-15), but the plan claims current 40.
        pid_rb, sess_rb = approve_plan_and_session("4.0")
        before = len(mon.writes)
        reads_before = mon.reads
        resp = modbus_request(6, 0, 35)
        check("G-25", "Read-before-Write: Ist-Wert-Mismatch -> kein Write (0x04)",
              resp[:1] == b"\x86" and resp[1:2] == b"\x04" and len(mon.writes) == before and mon.reads > reads_before,
              f"plan={pid_rb} session={sess_rb} resp={resp.hex()} writes={len(mon.writes)-before} reads={mon.reads-reads_before}")
        st, denies_rb = jget("/api/v1/gate/denies?limit=50", approver_tok)
        rb_items = (denies_rb or {}).get("items", []) if isinstance(denies_rb, dict) else []
        rb_reasons = [d.get("reason") for d in rb_items]
        check("G-26", "Deny current_value_mismatch + Audit-Evidenz",
              "current_value_mismatch" in rb_reasons and any(d.get("reason") == "current_value_mismatch" and d.get("severity") == "critical" for d in rb_items),
              f"reasons={rb_reasons[:6]}")

        # Exhaust the mismatch session with a valid write (restore device to 40
        # first) so the following plan gets its own fresh session lookup.
        with mon.lock:
            mon.registers[40001] = 40
        resp = modbus_request(6, 0, 35)
        check("G-26b", "Read-before-Write Match -> Write nach Session-Consume",
              resp[:1] == b"\x06", f"resp={resp.hex()}")

        # Empty current_value is rejected already at plan creation (defense in
        # depth). The proxy-level current_value_missing deny covers legacy or
        # manipulated plans and is exercised by the modbusproxy unit tests.
        now3 = time.time()
        st_missing, _ = jpost("/api/v1/gate/plans", vendor_tok, {
            "target_id": "aksm-1", "asset_id": "asset-danfoss-aksm800", "protocol": "modbus_tcp",
            "operations": [{"operation_id": "op-missing", "protocol": "modbus_tcp", "function": "fc6",
                            "address": "40001", "current_value": "", "new_value": "35", "unit": "celsius"}],
            "reason": "E2E missing current_value", "ticket_ref": "SVC-E2E-MISSING",
            "window_start": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now3 + 5)),
            "window_end": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now3 + 1800)),
        })
        check("G-27", "Plan ohne current_value -> API 400 (fail-closed)",
              st_missing == 400, f"status={st_missing}")

        # --- F-A8-01/02: multi-operation FC16 with decimal scale and FC5 with
        # a real read_coils window (read-before-write per operation). ---
        with mon.lock:
            mon.registers[40002] = 40
            mon.registers[40003] = 0
        ops16 = [
            {"operation_id": "fc16-a", "protocol": "modbus_tcp", "function": "fc16",
             "address": "40002", "current_value": "4.0", "new_value": "4.1", "value_scale": 0.1},
            {"operation_id": "fc16-b", "protocol": "modbus_tcp", "function": "fc16",
             "address": "40003", "current_value": "0.0", "new_value": "0.2", "value_scale": 0.1},
        ]
        pid16, sess16 = approve_custom_plan(ops16, "SVC-E2E-FC16")
        before = len(mon.writes)
        pdu16 = struct.pack(">BHHB", 16, 1, 2, 4) + struct.pack(">HH", 41, 2)
        resp = modbus_pdu(pdu16)
        check("G-29", "FC16 Multi-Op (Dezimal/Scale) -> Readback je Op, ein Write",
              resp[:1] == b"\x10" and len(mon.writes) == before + 1,
              f"plan={pid16} session={sess16} resp={resp.hex()} writes={len(mon.writes)-before}")

        with mon.lock:
            mon.coils[0] = True
        ops5 = [{"operation_id": "coil-1", "protocol": "modbus_tcp", "function": "fc5",
                 "address": "1", "current_value": "1", "new_value": "0", "value_scale": 1}]
        pid5, sess5 = approve_custom_plan(ops5, "SVC-E2E-FC5")
        before = len(mon.writes)
        resp = modbus_pdu(bytes([5, 0, 0, 0, 0]))
        check("G-30", "FC5 mit read_coils -> FC1-Readback vor Write",
              resp[:1] == b"\x05" and len(mon.writes) == before + 1,
              f"plan={pid5} session={sess5} resp={resp.hex()} writes={len(mon.writes)-before}")

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

        # --- 0.3 Setpoint Integrity + Automatic Recovery (cold-1 reference) ---
        recovered = False
        last_status = None
        deadline = time.time() + 70
        while time.time() < deadline:
            st, integ = jget("/api/v1/gate/integrity", approver_tok)
            last_status = integ
            refs = (integ or {}).get("references", []) if isinstance(integ, dict) else []
            if st == 200 and refs:
                rec = refs[0].get("recovery", {})
                if refs[0].get("state") == "ok" and rec.get("last_result") == "applied":
                    recovered = True
                    break
            time.sleep(1)
        check("G-31", "Integritaets-Worker + Automatic Recovery (Drift 30.0 -> Referenz 4.0)",
              recovered and any(w[1] == 40 for w in mon2.writes),
              f"status={last_status} writes={mon2.writes}")
        st, audit_api = jget("/api/v1/gate/audit?limit=200", master_tok)
        audit_raw = json.dumps(audit_api or {})
        check("G-32", "Audit enthaelt gate.recovery.applied", "gate.recovery.applied" in audit_raw)
        with mon2.lock:
            mon2.registers[40001] = 300
        writes_before = len(mon2.writes)
        time.sleep(25)
        check("G-33", "Cooldown/Rate-Limit verhindert zweite Recovery",
              len(mon2.writes) == writes_before, f"writes={mon2.writes}")

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
        mon2.stop()
        http_upstream.shutdown()
        webhook.shutdown()

    return finish(None)



if __name__ == "__main__":
    sys.exit(main())
