# Architecture

GeDefense Retail consists of two cooperating services and a browser dashboard:

| Component | Purpose | Safety property |
|---|---|---|
| `retaild` | Passive monitoring gateway: collectors, detection, alerting, local storage, dashboard/API | Read-only. Never writes to OT devices. |
| `retailgate` | Enforcement point for the store management/configuration path | Default-deny writes. Only an approved, exact write plan is forwarded. |
| Dashboard (`/`) | Operations cockpit for sightings, alerts, cold-chain integrity, gate approvals | Static assets, no external CDN. |

## Data flow (monitoring)

```text
OT devices (Modbus, BACnet, MQTT, SNMP, HTTP-UI)
        │  passive tap / read-only poll
        ▼
collectors ─► normalized events ─► local event log (JSONL)
                                   │
                                   ├─► state registry (assets, sensors, samples, peers)
                                   ├─► discovery (asset hypotheses, confidence)
                                   ├─► detection rules (15) ─► alerts ─► correlation (3 chains)
                                   └─► dashboard/API (REST + SSE, Bearer token, IP whitelist)
```

## Data flow (management path)

```text
Vendor ── login (password + TOTP [+ client certificate]) ──► retailgate
   │
   ├─ write plan (target, protocol, address, current → new value, reason, ticket, window)
   ├─ approval (four eyes for critical assets, MFA required)
   ├─ one-time token (bound to plan hash + source IP + TTL, exactly one use)
   ├─ session (bound to source IP + target)
   └─ proxy check: plan approved AND operation matches address+value AND window open
          │ yes → byte-preserving forwarded to the controller, audit before effect
          └ no  → Modbus exception / HTTP 403 + denied-write evidence + alert
```

If `retailgate` stops, only remote management is closed; the refrigeration plant keeps
running autonomously. The gate never touches OT process communication and never replaces a
firewall or a controller's own safety functions.

## Network zones

- **Management client zone** — operator browsers and vendor access, restricted by the dashboard
  IP whitelist.
- **Gate/monitoring host** — dedicated Linux host or VM; two NICs recommended when the gate is
  deployed (management side and OT-management side).
- **OT management zone** — controllers, supervisors, BMS. Only the gate/monitoring host may
  reach it, and only for the approved paths.
- **OT process zone** — controller-to-actuator communication; not monitored for content and never
  modified.

## Storage

Local, edge-native, no database server: append-only event log (JSONL, rotated), atomic alert and
policy state files, hash-chained audit log, bounded store-and-forward spool for an optional central
instance. File permissions are 0600/0700 on Linux.

## Extension points

- Protocol adapters under `internal/adapters` (read-only contract).
- Detection rules under `internal/detect/rules` (versioned rule metadata).
- Gate policy (`gate-policy.json`) for write allowlists and critical assets.
- See `docs/README.md` for the documentation index.
