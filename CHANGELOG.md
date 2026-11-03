# Changelog

All notable changes to GeDefense Retail are documented here. The project follows semantic
versioning; alpha releases may change behavior without notice and are **not production-ready**.

## [0.2.0-alpha.6] — 2026-11-03

### Release engineering / audit follow-up

- FIND-014 (LOW): release pipeline adds a post-publish `cosign verify-blob` smoke test for
  `SHA256SUMS`, `SHA256SUMS.archives` and `SBOM.spdx.json`; certificates are normalised to PEM.
- FIND-015 (INFO): `SOURCE_DATE_EPOCH` corrected to `1793664000` (`2026-11-03T00:00:00Z`), so SBOM and
  archive timestamps match the actual release date.
- Third-party GitHub Actions are pinned by commit SHA (checkout, setup-go, upload/download-artifact,
  cosign-installer); the CI workflow now fails fast if a release script loses its executable bit.
- Added `docs/INCIDENT-RESPONSE.md` (incident response runbook) and linked it from the documentation index.

## [0.2.0-alpha.5] — 2026-11-03

### Release engineering

- Release workflow now flattens the downloaded build artefacts and publishes an explicit asset list.
  This fixes the missing `SHA256SUMS`/`SBOM.spdx.json` validation failure in the publish job.
- Cosign keyless signatures (`*.sig` + `*.pem`) for all archives, checksums and the SBOM are now
  produced and published by the tag pipeline.

### Notes

- Windows binaries remain not Authenticode-signed (NOT_SIGNED).

## [0.2.0-alpha.4] — 2026-11-03

### Security / release engineering

- FIND-012 fixed: all release/install scripts are tracked as executable (100755); the
  release pipeline now fails early if an executable bit is missing (`test -x`).
- FIND-013 fixed: the release workflow pins `SOURCE_DATE_EPOCH=1762290000`, builds one
  canonical artefact set on Linux (Go 1.27.1) and verifies on Windows; `SHA256SUMS.archives`
  and `SBOM.spdx.json` are generated from that set.
- Tag releases are signed with cosign keyless (OIDC) and publish `*.sig`/`*.pem` assets next to
  the archives, checksums and SBOM.

### Notes

- This is the first release produced and signed by the CI tag pipeline; verify signatures with
  `cosign verify-blob` (see README "Integrity and signatures").
- Windows binaries remain **not Authenticode-signed** (NOT_SIGNED).

## [0.2.0-alpha.3] — 2026-11-03

Security remediation release after the VGT-100 deep audit (report: 2026-11-03, findings FIND-001…011).
The release is published only after the fixes below pass the re-test; it remains an **experimental
alpha**, not production-ready, without certification or compliance claims.

### Security (VGT-100 audit remediation)

- **FIND-001 / FIND-002 — installer hardening:** Windows services run as `NT AUTHORITY\LocalService`
  with explicit `icacls` DACLs (inheritance disabled; config read, data modify, Administrators full,
  Users none); Linux `/etc/gedefense-retail` is `root:gedefense` (`0750`) with config files `0640`,
  data directories owned by the service users. Installers fail closed when ownership/permission
  changes fail; uninstallers validate paths before deleting and do not restore previous ACLs.
- **FIND-003 — release integrity:** each archive is published with `SHA256SUMS` and
  `SHA256SUMS.archives`; archives, `SHA256SUMS`, `SHA256SUMS.archives` and `SBOM.spdx.json` are
  signed with cosign keyless (`*.sig`/`*.pem`). Windows binaries are **NOT_SIGNED** (no Authenticode
  certificate) and remain alpha.
- **FIND-004 — SBOM:** `SBOM.spdx.json` (SPDX) is published as a release asset and lists bundled
  components and hashes.
- **FIND-005 — CI hardening:** least-privilege permissions per workflow job (`contents: write` and
  `id-token: write` only where required), strict tag trigger and pinned actions (see
  `docs/BUILD-AND-RELEASE.md`).
- **FIND-006 — uninstaller path validation:** Linux and Windows uninstallers validate absolute
  paths, expected prefixes and symlinks before removing anything.
- **FIND-007 — token rotation:** rotate bearer tokens with
  `retaild token rotate --user <id> [--role viewer|operator|admin]` or hash an existing token with
  `retaild token hash --token <token>`; replace `token_sha256` in `users[]` and restart (no hot
  reload; the old token stays valid until then). `retaild check` rejects empty, duplicate and
  placeholder hashes.
- **FIND-008 — central mTLS:** when `central` is configured, `require_mtls` defaults to true; an
  `https://` URL requires client certificate, key and CA files. An explicit `require_mtls:false` is
  a documented loopback/test opt-out; plain `http://` is loopback-only.
- **FIND-009 — reproducible builds:** `SOURCE_DATE_EPOCH` (or `GEDEFENSE_BUILD_DATE`) pins the build
  date; `-trimpath` and `-buildvcs=false` remain mandatory.
- **FIND-010 — shutdown/audit flushing:** graceful shutdown flushes buffered setup/gate audit
  entries; a hard kill can still lose the buffered tail (documented residual risk).
- **FIND-011 — accepted:** TOTP uses RFC-6238 HMAC-SHA1; accepted for the alpha and documented.

### Added

- Release verification material: `SHA256SUMS.archives`, SPDX `SBOM.spdx.json`, cosign signatures,
  `docs/DEPLOYMENT.md` hardening and rotation guidance, `docs/SECURITY-MODEL.md` signature status.

### Known limitations

- No real OT hardware, no independent Access Gate penetration test, no compliance or certification
  claim; see `README.md` (honest alpha limits) and `docs/SECURITY-MODEL.md`.

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

[0.2.0-alpha.3]: https://github.com/visiongaiatechnology/gedefense-retail/releases
[0.2.0-alpha.2]: https://github.com/visiongaiatechnology/gedefense-retail/releases
