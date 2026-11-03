# Changelog

All notable changes to GeDefense Retail are documented here. The project follows semantic
versioning; alpha releases may change behavior without notice and are **not production-ready**.

## [0.2.0-alpha.2] — 2026-11-03

### Added

- **Setup wizard** (`/setup`, first-run, loopback-only): language, site, access whitelist, admin
  account with one-time token, collectors, summary and completion with restart hint. Setup writes
  the configuration atomically and disables itself once completed.
- **IP whitelist enforcement** for dashboard, API, SSE, static assets and setup (after completion).
  `require_whitelist` defaults to on; non-whitelisted sources receive `403 ip_not_allowed` without
  UI or asset leakage. Optional proxy-header trust is explicit and documented.
- **Eight UI languages**: English, German, French, Italian, Spanish, Japanese, Chinese, Russian,
  including setup, login and dashboard views.
- **Original GeDefense logo and mascot** integrated as local assets; no external CDN or third-party
  fonts.
- **Cross-platform release packaging** for Linux and Windows (amd64/arm64) with installer scripts
  and SHA-256 checksums.
- Public documentation: README (EN master plus DE/FR/IT/ES/JA/ZH/RU language switcher), SECURITY,
  CONTRIBUTING, CHANGELOG, NOTICE, THIRD-PARTY-NOTICES, CODE_OF_CONDUCT.

### Changed

- First-run behavior binds to loopback until setup is completed; remote access requires an explicit
  whitelist entry.
- Navigation and wording prepared for localization; the language switcher is available in every
  README.

### Security

- Whitelist checks are fail-closed and apply to the setup API during the setup window.
- No secrets or plaintext tokens are returned after the one-time setup/admin display.

## [0.2.0-alpha.1] — 2026-11-03

### Added

- **GeDefense Retail Access Gate (`retailgate`)**: enforcement of the management/configuration
  path for controllers and supervisor web UIs.
- Write plans with exact target/protocol/function/address/value binding, plan hash and optional
  ticket reference.
- Identity: local users, PBKDF2 password hashes, TOTP MFA, device binding via client certificate
  fingerprints, lockout.
- Approval workflow: self-approval denial, four-eyes for critical assets with `master_admin`
  participation, one-time token, source-IP-bound write session, revocation.
- Data planes: Modbus TCP enforcement proxy and HTTP(S) reverse proxy, default-deny allowlists.
- Hash-chained gate audit, denial timeline and evidence, fail-safe matrix, HMAC-signed webhook
  notifications with escalation and acknowledgement.
- Gate UI: approval inbox, plan detail with current→new values, one-time token dialog, sessions,
  deny timeline, status and fail-safe view.
- Verification evidence (loopback, fake controllers): gate end-to-end 25/25 checks passed; build,
  vet, unit/integration tests and race detector green; previous monitoring acceptance remained
  39/39.

### Security

- S-01 boundary clarified by architecture decision D-13: `retaild` stays read-only; only the
  authorization proxy can forward an approved operation.
- Gate starts only with a valid policy and an intact audit chain; failures close the management
  path instead of opening it.

### Known limitations

- No real OT hardware tested; no independent gate penetration test yet; TOTP is not phishing-resistant.

## [0.1.0] — 2026-11-03

### Added

- First monitoring release (`retaild`): passive asset discovery, OT flow observation, cold-chain
  integrity checks, data-quality rules, maintenance-access visibility, detection rules and
  correlation, alert/incident workflow, hash-chained audit, glass-style dashboard.
- Passive/read-only adapters for Modbus TCP, MQTT, BACnet/IP, SNMP v1/v2c GET, PCAP and HTTP
  management-UI metadata; simulator (`retail-sim`).
- Operator-owned, versioned policy for temperature limits, data quality, retention, maintenance and
  alerting; local-first operation with bounded offline spool.
- Acceptance and security documentation, including an independent security audit with the
  conditional release gate and an end-to-end acceptance harness (39/39 checks on
  loopback/simulation).

### Security

- Product invariants: no OT write path, no active scanning, no plant control, fail-safe behavior.
- Conditional release gate; Windows ACL and live-OT pilot items documented as open conditions.

[0.2.0-alpha.2]: https://github.com/visiongaiatechnology/gedefense-retail/releases
