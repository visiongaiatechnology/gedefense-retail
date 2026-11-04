# HTTP API v1 — overview

All endpoints are JSON over HTTP/1.1 on the configured listen address. Timestamps are RFC 3339 in
UTC. The API is restricted by the dashboard IP whitelist; unauthenticated clients outside the
whitelist receive `403 ip_not_allowed`.

## Authentication and roles

`Authorization: Bearer <token>` — tokens are generated at setup (`admin`) and stored only as
SHA-256 digests. Roles: `viewer` (read), `operator` (alert/incident workflow), `admin` (everything).
Rate limit: 120 requests/minute per token (burst 40); login attempts have a stricter limit.

Error format:

```json
{"error":{"code":"ip_not_allowed","message":"access denied","request_id":"…"}}
```

Stable codes: `unauthorized`, `forbidden`, `not_found`, `invalid_request`, `conflict`,
`rate_limited`, `unavailable`, `internal`, `ip_not_allowed`, `setup_required`, `setup_conflict`.
Messages are localised via `Accept-Language`; codes never change with the language.

## Monitoring endpoints (`retaild`)

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/v1/health` | liveness, storage, collectors, read-only flag |
| GET | `/api/v1/meta` | product, version, capabilities, supported protocols |
| GET | `/api/v1/overview` | fleet/site KPI snapshot |
| GET | `/api/v1/sites` · `/sites/{id}` | stores and zone configuration |
| GET | `/api/v1/assets` · `/assets/{id}` | passive inventory, sensors, evidence |
| GET | `/api/v1/alerts` · `/alerts/{id}` | detections, evidence, correlation |
| POST | `/alerts/{id}/ack` · `/assign` · `/close` | operator workflow (audited) |
| GET | `/api/v1/coldchain` | temperature series, limits, violations, data quality |
| GET | `/api/v1/access` | maintenance windows, sessions, anomalies |
| GET | `/api/v1/timeline` · `/incidents` · `/incidents/{id}` | correlated threat timeline and cases |
| POST | `/incidents/{id}/note` | operator note (audited) |
| GET | `/incidents/{id}/export` | evidence bundle (JSON) |
| GET | `/api/v1/policies` · `/policies/{site}/versions/{v}` | versioned operator policy |
| POST | `/api/v1/policies/reload` | reload policy file (admin, audited) |
| GET | `/api/v1/audit` | hash-chained audit entries + chain status |
| GET | `/api/v1/collectors` | adapter health and counters |
| GET | `/api/v1/vendors` · `/vendors/{id}` | vendor catalog entries (runtime knowledge, read-only) |
| GET | `/api/v1/regulatory-context` | market/regulatory hints (informational only, no compliance claim) |
| GET | `/api/v1/stream` | SSE stream (alerts, events, incidents, health) |

### Vendor catalog and regulatory context endpoints

All three endpoints are read-only, require the `viewer` role (anonymous requests: `401`), use the
usual API rate limit and set `Cache-Control: no-store`.

| Endpoint | Response (summary) |
|---|---|
| `GET /api/v1/vendors` | `{enabled, items[], total, warnings?}`; one item per device family: `vendor_id`, `vendor_name`, `family{id,name,category,lifecycle,protocols[],management_interface}`, `write_surfaces_count`, `highest_evidence` (`high\|medium\|low`); deterministic order |
| `GET /api/v1/vendors/{family_id}` | `{enabled, vendor_id, vendor_name, family{…}, write_surfaces[], warnings?}`; each write surface has `protocol`, `scope`, `operations[]` (`kind`, optional `function_code`/`function`/`service`/`target`, `name`, `decision`, `change_class?`), `change_classes[]`, `evidence{source_url?,confidence,verification}`, `notes` |
| `GET /api/v1/regulatory-context` | `{enabled, note, product_boundary_summary[], frameworks[], warnings?}`; `note` explicitly states there is no compliance/legal/certification statement and that HACCP/NIS2 obligations remain with the operator |

Failure and path behaviour:

- Missing/invalid catalog ⇒ HTTP `200` with `enabled:false`, empty `items`/`frameworks` and
  `warnings[]`; never `500` (also for `/vendors/{family_id}`).
- Unknown `family_id` while the catalog is active ⇒ `404 not_found`.
- Partial failure (`vendors.json` OK but `write-surface.json`/`regulatory-context.json` missing or
  broken) ⇒ `enabled:true`, affected lists empty and warnings included.
- `GEDEFENSE_OT_CATALOG` may point to `vendors.json` or the catalog directory; sibling
  `write-surface.json`/`regulatory-context.json` are loaded from the same directory. Missing files
  produce warnings, not a startup abort.

The catalog is runtime knowledge for classification/advisory only; it grants no write permission,
whitelist admission or auto-allow.

## Setup endpoints (`retaild`, loopback only until setup is complete)

| Method | Path |
|---|---|
| GET | `/api/v1/setup/state` |
| POST | `/api/v1/setup/language` · `/site` · `/whitelist` · `/admin` · `/collectors` · `/complete` |

`/setup` serves the guided wizard UI. Setup endpoints are loopback-only and disabled (404) after a
successful completion.

## Access Gate endpoints (`retailgate`)

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/v1/gate/health` | public liveness of the gate |
| POST | `/api/v1/gate/auth/login` | password + TOTP (+ client certificate if configured) |
| GET | `/api/v1/gate/plans` · `/plans/{id}` | write plans |
| POST | `/api/v1/gate/plans` | request a write plan |
| POST | `/api/v1/gate/plans/{id}/approve` | four-eyes approval, `X-Gate-MFA` required |
| POST | `/api/v1/gate/plans/{id}/reject` · `/cancel` | invalidate a plan |
| POST | `/api/v1/gate/sessions` | redeem the one-time token (source-IP bound) |
| GET/DELETE | `/api/v1/gate/sessions` · `/sessions/{id}` | list/revoke sessions |
| GET | `/api/v1/gate/denies` | denied write attempts with evidence |
| GET | `/api/v1/gate/audit` | gate audit chain |
| GET | `/api/v1/gate/status` | plans/sessions/denies/fail-safe state |
| GET | `/api/v1/gate/integrity` | setpoint-integrity references, last values, recovery state |
| GET | `/api/v1/gate/policy` · POST `/policy/reload` | write policy |
| GET | `/api/v1/gate/escalations` · POST `/{id}/ack` | 24/7 escalation incl. human acknowledgement |
| GET | `/api/v1/gate/stream` | SSE: plan/session/deny/fail-safe/integrity (`gate_integrity`) events |

Write plans bind target, protocol, function, address and value exactly. The proxy rejects any
deviation, expired or reused token, wrong source IP, or closed maintenance window — with a Modbus
exception (FC-level) or HTTP 403, a `write_unknown` record for unclear device answers, and an
audit entry.

**Modbus read-before-write:** immediately before forwarding a write, the gate re-reads the current
value (FC3 for holding registers, FC1 `read_coils` for coil writes) and compares it with the value
bound in the plan. A missing/empty value, a read error or a mismatch denies the write and is audited
with `current_value_missing`, `current_value_mismatch` or `current_value_unreadable`. The write is not
forwarded. Order is **verify → consume/audit → forward**: token/session consumption and the audit
entry happen only after successful verification.

**Values and `value_scale`:** `current_value` and `new_value` are display values. `value_scale`
defaults to `1.0`; with a scale the raw device value is `round(display_value / value_scale)` (for
example `current_value 4.0` / `new_value 3.5` at `value_scale 0.1` ⇒ raw `40 → 35`). Decimal values
(containing `.`) **require** `value_scale`; otherwise the plan is rejected with `400`.
`retailgate check` also warns, and the plan hash binds both values and the scale.

**`read_coils` (FC1) is a separate read window.** Modbus targets may configure
`read_coils: {"fc":1,"start":0,"count":N}`. FC5/FC15 coil writes require it for read-before-write;
without it the gate denies the write and `retailgate check` produces a failing check `RBC-<target>`
(and warns for Modbus/HTTP allowlists when verification is incomplete).

**TOCTOU residual window:** a short time window remains between the re-read and the actual write, in
which another actor could change the device value. The gate reduces it (immediate re-read, short
sessions/timeouts) but does **not** close it completely; device interlocks, monitoring/alarms on
unexpected changes and short approval windows are the operator-side mitigations. No “TOCTOU-free”
guarantee is made.

**HTTP boundary:** for HTTP(S) supervisor UIs there is no generic current-value re-check (form/JSON
values cannot be universally parsed). URL/method allowlisting and the plan's value binding remain;
the gate check output warns when no verification is possible. This is not an equivalent
read-before-write guarantee.

The vendor catalog (`data/ot-catalog/`) feeds `/api/v1/vendors*` and the UI for classification and
advisory only; it never grants write access, whitelist admission or an auto-allow.

### Setpoint integrity and automatic recovery

`GET /api/v1/gate/integrity` (viewer/approver/master/auditor) reports the configured `integrity`
references with target/fc/register/unit, expected value/scale, last read value/state, last check time,
and recovery statistics (actions in the current hour/day, cooldown remaining, last
`gate.recovery.applied|failed|unknown`). SSE clients receive `gate_integrity` events for confirmed
mismatches, recovery attempts and errors.

Configuration (in `gate.json`):

```json
"integrity": {
  "enabled": true, "poll_interval_s": 60, "confirm_reads": 3, "stale_after_s": 180,
  "references": [
    {"target_id":"aksm-1","fc":3,"register":40002,"unit_id":1,
     "value":"4.0","scale":0.1,"unit":"celsius","note":"meat room setpoint","recovery":true}
  ],
  "recovery": {"enabled": false, "max_actions_per_hour": 3, "max_actions_per_day": 10,
               "cooldown_s": 300, "require_no_active_window": true}
}
```

- The worker polls references cyclically via **FC3** and only reports a mismatch after
  `confirm_reads` consecutive deviations; `stale_after` marks missing/stale data.
- **Recovery is disabled by default (`recovery.enabled:false`).** When enabled, only references with
  `"recovery": true` are written (FC6 to the reference value) — no active plan/session is used;
  rate-limit, cooldown and `require_no_active_window` apply; a read-back verifies the result.
- Audit events: `gate.integrity.mismatch`, `gate.recovery.applied|failed|unknown`.
  `failed`/`unknown` require operator action; no automatic retry loop.
- Limits: recovery proves neither who wrote outside the gate nor that no other writer exists; the
  read→write TOCTOU window remains; HTTP writes have no generic value re-check. Integrity monitoring
  only covers configured Modbus references.


**Operator/fail-safe semantics:** while the gate fail-safe has `AllowWrite=false`, no integrity reads
or recovery run. Recovery needs a successful audit intent before the write; if the audit append fails
after the write, the action is `gate.recovery.unknown` and is **not** retried automatically. Each
confirmed mismatch allows one attempt (no flapping loop). The FC6 recovery write is preceded by an
FC3 re-read, but read→write is not atomic (TOCTOU residual). References are operator-approved, only
Modbus (`modbus_tcp`, FC3/FC6) is supported in this version; HTTP has no integrity/recovery.
`require_no_active_window` must be true when recovery is enabled; rate limits/cooldown and
`integrity.recovery.enabled=false` (kill switch) apply.

## Data protection

No packet payloads, no credentials, no personal data. Only metadata, measurements, approvals and
audit records are stored. See [`SECURITY-MODEL.md`](SECURITY-MODEL.md).
