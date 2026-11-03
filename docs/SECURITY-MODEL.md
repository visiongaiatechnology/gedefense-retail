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
