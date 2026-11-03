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
| GET | `/api/v1/stream` | SSE stream (alerts, events, incidents, health) |

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
| GET | `/api/v1/gate/policy` · POST `/policy/reload` | write policy |
| GET | `/api/v1/gate/escalations` · POST `/{id}/ack` | 24/7 escalation incl. human acknowledgement |
| GET | `/api/v1/gate/stream` | SSE: plan/session/deny/fail-safe events |

Write plans bind target, protocol, function, address and value exactly. The proxy rejects any
deviation, expired or reused token, wrong source IP, or closed maintenance window — with a Modbus
exception (FC-level) or HTTP 403, a `write_unknown` record for unclear device answers, and an
audit entry.

## Data protection

No packet payloads, no credentials, no personal data. Only metadata, measurements, approvals and
audit records are stored. See [`SECURITY-MODEL.md`](SECURITY-MODEL.md).
