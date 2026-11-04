# Security model and honest alpha limits

> **Alpha.** GeDefense Retail is experimental. It is not a certified product, not a replacement for
> a refrigeration controller safety function, and not a HACCP/NIS2 conformity claim.

## Non-negotiable invariants

1. `retaild` is passive and read-only; it never writes to OT devices or actuators.
2. `retailgate` is the only path that can forward a configuration change, and only after an exact,
   approved write plan (four eyes where configured, MFA, one-time token, source-IP binding).
3. There is no autonomous control: no rule, schedule or model ever writes by itself.
4. OT process communication is never filtered, blocked or modified by GeDefense.
5. A failure of GeDefense must not affect the plant: gate down means remote management closed,
   cooling continues.
6. Dashboard, API and SSE are restricted by a hard IP whitelist; other clients are rejected.
7. Every state-changing action is audited before it takes effect; the audit chain is tamper-evident.
8. No packet payloads, credentials or personal data are stored; only metadata and measurements.
9. Writes that time out or disconnect are recorded as `write_unknown`; no automatic retry.

## Authentication and access

- Dashboard/API: bearer tokens (hashed at rest), roles `viewer`, `operator`, `admin`, rate limit.
- Gate: local identities, PBKDF2-HMAC-SHA256 passwords, TOTP MFA, optional client-certificate
  binding, lockout, short-lived sessions.
- Setup wizard: available only from loopback and only until setup is completed.

## Write enforcement: read-before-write (0.2.0-alpha.8)

- **Modbus TCP only:** immediately before forwarding a write, the gate re-reads the current value
  (FC3 for holding registers, FC1 `read_coils` for coil writes) and compares it with the value bound
  in the plan. Empty/missing values, read errors and mismatches deny the write and are audited with
  `current_value_missing`, `current_value_unreadable` or `current_value_mismatch`; no write leaves the
  gate. Order: verify → consume/audit → forward.
- **Values:** `current_value`/`new_value` are display values; `value_scale` defaults to `1.0` and
  the raw value is `round(display/value_scale)`. Decimal values require a scale (otherwise `400`);
  `retailgate check` warns as well.
- **`read_coils` (FC1)** is a separate read window; Modbus targets may configure
  `read_coils: {"fc":1,"start":0,"count":N}`. FC5/FC15 writes require it — otherwise the gate denies
  and `retailgate check` reports a failing check `RBC-<target>`.
- **TOCTOU residual risk:** a short window between re-read and write remains and cannot be fully
  closed by the gate. Mitigations: immediate re-read, short sessions/approval windows and
  device-side interlocks/monitoring for unexpected changes. No “TOCTOU-free” claim.
- Read-before-write is defense in depth on top of plan approval, four eyes, one-time token and
  source-IP binding; it never replaces approval.
- **HTTP(S) boundary:** there is no generic current-value re-check for supervisor web UIs. The gate
  keeps URL/method allowlisting and value binding; check output warns when verification is not
  possible. HTTP writes are therefore not equivalent to Modbus read-before-write.
- Real controller/firmware semantics of the re-read are **not tested** in this alpha (fake devices,
  loopback).

## Vendor catalog and packaged data (0.2.0-alpha.8)

- The release bundle ships `data/ot-catalog/` (`vendors.json`, `write-surface.json`,
  `regulatory-context.json`).
- Discovery, API (`/api/v1/vendors*`, `/api/v1/regulatory-context`), UI and gate advisory use it as
  runtime knowledge; unknown devices stay unknown.
- The catalog is **not** an auto-allow: it grants no write permission, no whitelist admission and no
  bypass of plan/approval. Regulatory context is informational and makes no compliance claim.
- **Failure behaviour:** a missing, invalid or oversized `vendors.json` disables the catalog
  (`enabled:false`, empty lists, warnings, HTTP 200 — no 500). Partial failures keep the catalog
  enabled with empty affected lists and warnings. Missing files never abort startup.
- Catalog/regulatory endpoints are read-only, `viewer`-RBAC, rate-limited and `no-store`; anonymous
  requests receive `401`. `retaild check` reports catalog problems only as warnings in `warnings[]`
  and does not change `ok` or check results.

## Release integrity and signatures (0.2.0-alpha.8)

- Archives, `SHA256SUMS`, `SHA256SUMS.archives` and `SBOM.spdx.json` are published with cosign
  **keyless** signatures (`*.sig`/`*.pem`), together with `SHA256SUMS` / `SHA256SUMS.archives`;
  `SBOM.spdx.json` (SPDX-2.3 JSON) lists the release archives and binaries with hashes; all bundle files are covered by the bundle `SHA256SUMS`.
- **Windows binaries are NOT_SIGNED** (no Authenticode certificate); SmartScreen may warn. Do not
  treat Windows code signing as a security control in this alpha.
- Verification steps are in [DEPLOYMENT.md](DEPLOYMENT.md) and
  [BUILD-AND-RELEASE.md](BUILD-AND-RELEASE.md). **If a signature asset is missing, treat the
  download as unsigned.**
- cosign keyless relies on the CI OIDC identity; no long-lived signing key is stored in the
  repository. Key custody and rotation rehearsal are **NOT_TESTED** in this alpha.
- Signatures prove provenance/integrity only; they are **not** a compliance or certification claim.

## Token rotation and central mTLS

- Bearer tokens are stored only as hashes. Rotate with
  `retaild token rotate --user <id> [--role viewer|operator|admin]` (or hash an existing token with
  `retaild token hash --token <token>`), replace `token_sha256` in `retail.json` and **restart**;
  there is no hot reload and the old token stays valid until the restart. `retaild check` rejects
  empty, duplicate and placeholder hashes.
- The optional central connection is outbound-only. When `central` is configured, `require_mtls`
  defaults to true: an `https://` URL requires client certificate, client key and CA file. An
  explicit `require_mtls:false` is a documented opt-out for loopback/test endpoints only; plain
  `http://` is accepted only for loopback.
- Client certificates/keys are rotated manually (replace files, restart); automatic rotation and
  KMS/HSM integration are not implemented in the alpha.

## Audit buffer and residual risk

- Audit records are hash-chained and written before a write decision takes effect.
- Graceful shutdown flushes buffered setup/gate audit entries (`store.AuditLog.Flush` after HTTP
  shutdown); a `kill -9`/hard kill can lose the buffered tail (up to 128 entries on the affected
  build). This is loss-of-last-evidence, not a tampering vector.
- Operator duty: graceful service stops, maintenance windows, verify the audit chain on start. A
  complete incident-response/forensics runbook is **not** part of this alpha.

## Known alpha limitations

- Verified against fake controllers and supervisors on loopback, **not** against real store hardware.
- No independent penetration test of the Access Gate yet.
- TOTP is not phishing-resistant (WebAuthn/FIDO2 planned).
- Network segmentation and the removal of bypass paths (service laptops, legacy VPNs, vendor
  cloud portals) remain operator responsibilities; GeDefense can only make bypasses visible.
- The management path must actually be routed through `retailgate`; without that, enforcement is
  not effective.
- Certificate pinning and CGI parameter allowlists are implemented in the proxy but not yet
  exposed in the configuration schema.
- API sessions are in memory (restart logs out), audit retention is non-destructive.
- BACnet/MQTT data-plane enforcement, central fleet management and signed self-update are planned
  for later releases.
- No compliance or certification claim of any kind.

## Reporting vulnerabilities

Please use the private GitHub security advisory for this repository. Do not open a public issue for
security problems. Include affected version, component, reproduction and impact. Never send real
store credentials or production data.
