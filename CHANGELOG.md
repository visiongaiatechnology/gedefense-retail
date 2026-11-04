# Changelog

All notable changes to GeDefense Retail are documented here. The project follows semantic
versioning; alpha releases may change behavior without notice and are **not production-ready**.

## [0.3.0-alpha.1] — 2026-11-04

### Added

- **Setpoint integrity + automatic recovery (opt-in):** new `gate.json` `integrity` block with
  references (`target_id`, `fc`, `register`, `unit_id`, `value`, `scale`, `unit`, `note`,
  `recovery`), polling (`poll_interval`, `confirm_reads`, `stale_after`) and recovery controls
  (`max_actions_per_hour`, `max_actions_per_day`, `cooldown_s`, `require_no_active_window`;
  recovery disabled by default). The worker checks references cyclically per FC3 and confirms a
  mismatch; recovery writes the reference value per FC6 only for explicitly approved references,
  without an active plan/session, with rate limit/cooldown, read-back and audit events
  `gate.integrity.mismatch` and `gate.recovery.applied|failed|unknown`. New API
  `GET /api/v1/gate/integrity` and SSE `gate_integrity`.
- **Network enforcement (`retailgate netpolicy`):** generates/applies nftables/iptables rules so new
  connections to controllers are accepted only from `--gate-source` CIDRs (otherwise drop + log),
  using its own table/chain; options `--out`, `--apply`, `--rollback`, `--check`; requires routing/
  NAT/bridge at the gate host and is not a router itself.
- **Bypass integration:** `retaild` config `bypass: {enabled, gate_source_cidrs}` (CIDR/single IP,
  IPv4/IPv6, max. 64, normalized-duplicate/zoning validation; entries validated even when disabled;
  `enabled:true` without a valid list refuses to start — fail-closed). Passive `write_attempt` events
  from non-gate sources raise `retail.bypass-suspected` (critical, category `access`, rule version 1)
  with evidence/facts/hypothesis/recommendations and dedup
  `retail.bypass-suspected|<site>|<source>|<target>|<register>`; gate sources and reads are excluded.
  The rule is an adapter/gate-signal rule (passive rule pack stays at 15) and feeds the normal alert
  engine/correlation/incidents.
- Documentation: 8-language READMEs, API, SECURITY-MODEL, DEPLOYMENT, operations runbook, policy
  reference, deployment guide, Access Gate API contract, protocol matrix and docs index updated;
  explicit operator section for setpoint integrity/automatic recovery (defaults, fail-safe/
  `AllowWrite`, audit fail-closed/no-retry, one attempt per mismatch, TOCTOU, Modbus-only, kill
  switch) added; `config/gate.example.json` (public and product) now contains a safe `integrity`
  block (`enabled:false`, empty references, `recovery.enabled:false`); release notes added.

### Security

- Automatic recovery is **opt-in**, only for explicitly marked references, rate-limited/cooldown,
  read-back and audited; it does not replace plan approval for normal writes, and `failed`/`unknown`
  recovery stays a manual operator decision.
- `netpolicy` is host-level defense in depth: it only enforces on the gate host, requires correct
  routing/segmentation, and makes no claim to close bypass paths elsewhere.
- The bypass alert is a detection signal based on passive events; it does not prove attribution.

### Known limitations

- Recovery is opt-in and does **not** prove that nobody wrote outside the gate; the read→write
  (TOCTOU) window remains; HTTP writes have no generic value re-check.
- `netpolicy` only enforces on the gate host; operators must still remove bypass paths (service
  laptops, legacy VPNs, vendor portals).
- Bypass detection is passive and cannot attribute writes definitively; it proves only the write
  attempt and a source outside the gate CIDRs, not an actor, approval or a segmentation gap. Verify
  with device logs and operator evidence.
- Alpha quality; no compliance/certification claim.

## [0.2.0-alpha.8] — 2026-11-04

### Fixed (operator-confirmed release packaging defect)

- Release bundles now contain the curated public `docs/retail/` documentation: vendor landscape,
  protocol support matrix, market context, pilot acceptance, operations runbook, deployment guide,
  policy reference, vendor workflows/onboarding, safety boundaries and threat model. Previously
  `docs/BUILD-AND-RELEASE.md` referenced `docs/retail/deployment-guide.md` and
  `docs/retail/pilot-acceptance.md` while the archives omitted the directory.
- `data/ot-catalog/` (`vendors.json`, `write-surface.json`, `regulatory-context.json`) is part of
  the bundle and documented as runtime knowledge (no auto-allow).
- Documentation index adds a "Vendor & pilot documentation" section; internal audit/release/handoff
  reports remain unpublished.

### Added

- **Modbus read-before-write:** immediately before forwarding an approved write, the gate re-reads
  the current value (FC3/FC4) and compares it with the plan's bound value. Missing/empty values,
  read errors and mismatches deny the write and are audited with `current_value_missing`,
  `current_value_mismatch` or `current_value_unreadable`.
- **HTTP boundary documented honestly:** no generic current-value re-check for HTTP(S) supervisor
  UIs; URL/method allowlisting and value binding remain, and the gate check warns when verification
  is not possible.
- **Vendor catalog as runtime knowledge:** discovery, API, UI and gate advisory use
  `data/ot-catalog/`; it is not an auto-allow. New endpoints: `GET /api/v1/vendors`,
  `/api/v1/vendors/{id}` and `GET /api/v1/regulatory-context`.
- Updated public docs: `docs/README.md` (vendor & pilot section), `docs/API.md`,
  `docs/DEPLOYMENT.md`, `docs/SECURITY-MODEL.md`, `docs/BUILD-AND-RELEASE.md`.

### Security

- Read-before-write hardens the Modbus management path against stale planning values, but remains
  defense in depth on top of plan approval, four-eyes, one-time token and source-IP binding.
- The vendor catalog cannot grant write access, whitelist admission or a bypass; regulatory context
  is informational only.

### Known limitations

- Real controller/current-value semantics are not tested (fake devices, loopback); HTTP has no
  generic current-value re-check; Windows binaries remain NOT_SIGNED; no independent Access Gate
  penetration test; no compliance or certification claim.

## [0.2.0-alpha.7] — 2026-11-03

### Fixed (operator review)

- Gate view now probes the public gate health endpoint before showing a login form. If the separate
  `retailgate` service or the reverse-proxy route `/api/v1/gate` is missing, the view explains the
  cause, keeps monitoring running and offers a retry instead of a login mask that cannot work.
- Empty-state actions in the cold-chain and access views no longer feel dead: "first three sensors"
  widens the period automatically, the period control updates, and a localised toast explains when
  the range is still empty. The same feedback is shown when "set to 7 days" finds no access records.
- Added eight multilingual feedback strings (`gate.unavailable.*`,
  `view.access.widened_empty_*`, `view.coldchain.widened_empty_*`) in all eight UI languages.

### Notes

- No authentication or authorization behaviour was weakened; the gate health endpoint is public by
  design, tokens stay in the browser session storage, and no new external dependencies were added.
- Alpha quality: the local demo gate credentials used during the review are not part of the release.

## [0.2.0-alpha.6] — 2026-11-03

### Release engineering / audit follow-up

- Release hardening (low): release pipeline adds a post-publish `cosign verify-blob` smoke test for
  `SHA256SUMS`, `SHA256SUMS.archives` and `SBOM.spdx.json`; certificates are normalised to PEM.
- Release hardening (info): `SOURCE_DATE_EPOCH` corrected to `1793664000` (`2026-11-03T00:00:00Z`), so SBOM and
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

- Release hardening: all release/install scripts are tracked as executable (100755); the
  release pipeline now fails early if an executable bit is missing (`test -x`).
- Release hardening: the release workflow pins `SOURCE_DATE_EPOCH=1762290000`, builds one
  canonical artefact set on Linux (Go 1.27.1) and verifies on Windows; `SHA256SUMS.archives`
  and `SBOM.spdx.json` are generated from that set.
- Tag releases are signed with cosign keyless (OIDC) and publish `*.sig`/`*.pem` assets next to
  the archives, checksums and SBOM.

### Notes

- This is the first release produced and signed by the CI tag pipeline; verify signatures with
  `cosign verify-blob` (see README "Integrity and signatures").
- Windows binaries remain **not Authenticode-signed** (NOT_SIGNED).

## [0.2.0-alpha.3] — 2026-11-03

Security remediation release after an independent release-pipeline audit.
The release is published only after the fixes below pass the re-test; it remains an **experimental
alpha**, not production-ready, without certification or compliance claims.

### Security remediation

- **Installer hardening:** Windows services run as `NT AUTHORITY\LocalService`
  with explicit `icacls` DACLs (inheritance disabled; config read, data modify, Administrators full,
  Users none); Linux `/etc/gedefense-retail` is `root:gedefense` (`0750`) with config files `0640`,
  data directories owned by the service users. Installers fail closed when ownership/permission
  changes fail; uninstallers validate paths before deleting and do not restore previous ACLs.
- **Release integrity:** each archive is published with `SHA256SUMS` and
  `SHA256SUMS.archives`; archives, `SHA256SUMS`, `SHA256SUMS.archives` and `SBOM.spdx.json` are
  signed with cosign keyless (`*.sig`/`*.pem`). Windows binaries are **NOT_SIGNED** (no Authenticode
  certificate) and remain alpha.
- **SBOM:** `SBOM.spdx.json` (SPDX) is published as a release asset and lists bundled
  components and hashes.
- **CI hardening:** least-privilege permissions per workflow job (`contents: write` and
  `id-token: write` only where required), strict tag trigger and pinned actions (see
  `docs/BUILD-AND-RELEASE.md`).
- **Uninstaller path validation:** Linux and Windows uninstallers validate absolute
  paths, expected prefixes and symlinks before removing anything.
- **Token rotation:** rotate bearer tokens with
  `retaild token rotate --user <id> [--role viewer|operator|admin]` or hash an existing token with
  `retaild token hash --token <token>`; replace `token_sha256` in `users[]` and restart (no hot
  reload; the old token stays valid until then). `retaild check` rejects empty, duplicate and
  placeholder hashes.
- **Central mTLS:** when `central` is configured, `require_mtls` defaults to true; an
  `https://` URL requires client certificate, key and CA files. An explicit `require_mtls:false` is
  a documented loopback/test opt-out; plain `http://` is loopback-only.
- **Reproducible builds:** `SOURCE_DATE_EPOCH` (or `GEDEFENSE_BUILD_DATE`) pins the build
  date; `-trimpath` and `-buildvcs=false` remain mandatory.
- **Shutdown/audit flushing:** graceful shutdown flushes buffered setup/gate audit
  entries; a hard kill can still lose the buffered tail (documented residual risk).
- **TOTP (accepted):** TOTP uses RFC-6238 HMAC-SHA1; accepted for the alpha and documented.

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
