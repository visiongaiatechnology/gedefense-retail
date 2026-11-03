<p align="center">
  <a href="docs/assets/gedefense-logo.png">
    <img src="docs/assets/gedefense-logo.png" alt="GeDefense Retail" width="360">
  </a>
</p>

<h1 align="center">GeDefense Retail</h1>

<p align="center"><strong>ColdChain &amp; Store Infrastructure Security</strong><br>
Passive OT monitoring and a default-deny enforcement gate for the store management path.</p>

<p align="center">
  <a href="https://github.com/visiongaiatechnology/gedefense-retail/releases"><img alt="Release" src="https://img.shields.io/github/v/release/visiongaiatechnology/gedefense-retail?style=flat-square&label=release"></a>
  <img alt="License: AGPL-3.0" src="https://img.shields.io/badge/license-AGPL--3.0-blue?style=flat-square">
  <img alt="Go 1.23+" src="https://img.shields.io/badge/go-1.23%2B-00ADD8?style=flat-square&logo=go&logoColor=white">
  <img alt="Platforms: Linux and Windows" src="https://img.shields.io/badge/platforms-Linux%20%7C%20Windows-444?style=flat-square">
  <img alt="Status: Alpha" src="https://img.shields.io/badge/status-alpha-orange?style=flat-square">
</p>

[English](README.md) · [Deutsch](README.de.md) · [Français](README.fr.md) · [Italiano](README.it.md) · [Español](README.es.md) · [日本語](README.ja.md) · [中文](README.zh.md) · [Русский](README.ru.md)

---

<a id="alpha-status"></a>
## Alpha status

> **0.2.0-alpha.3 — experimental, not production-ready.**
> GeDefense Retail is an early alpha. It has been verified on loopback with fake controllers and
> supervisors, not against real refrigeration hardware in a store. There is no independent
> penetration test of the Access Gate yet, and no compliance or certification claim is made.
> Do not use it as the only safety, food-safety or monitoring control of a refrigeration plant.

<a id="overview"></a>
## What this is

GeDefense Retail protects and documents the infrastructure behind a supermarket: refrigeration
controllers, cold rooms, display cases, sensor gateways, building automation, and the remote
maintenance path used by refrigeration service companies.

It ships as two separate services:

| Service | Binary | Role |
|---|---|---|
| **Monitoring** | `retaild` | Passive, read-only OT observability: assets, flows, cold-chain integrity, data quality, alerts, audit, dashboard |
| **Access Gate** | `retailgate` | The only permitted path for management/configuration writes to controllers: default-deny, plan-bound, human-approved, fully audited |
| **Simulator** | `retail-sim` | Local test data for development and acceptance runs (loopback only) |

**Product promise:**

- **No OT process write path from GeDefense.** `retaild` and all passive adapters never write to a
  controller. The Access Gate does not control the process; it authorizes and forwards a single,
  explicitly approved configuration operation.
- **Writes are default-deny.** A write is forwarded only if it matches an approved *write plan*
  (target, protocol, function, address **and** value) inside an approved time window.
- **Human control.** Critical assets require two distinct approvals, one of them from a
  `master_admin`. There is no autonomous write, no schedule-based write and no AI decision.
- **Fail-closed for the management path.** If the gate stops, remote management is closed. The
  refrigeration plant keeps running autonomously because the gate is not part of the process loop.
- **Evidence before the effect.** Every action and every denied write is written to a hash-chained
  audit log; the gate refuses to start on a broken chain.

<a id="features"></a>
## Features

### ColdChain monitoring (`retaild`, passive/read-only)

- Passive asset discovery from flow metadata, OUI hints and protocol evidence — unknown devices
  stay unknown, with confidence values.
- OT network observation: new peers, unexpected paths, protocol metadata, flow baselines.
- Cold-chain integrity: operator-defined temperature limits, rate-of-change, setpoint deviation,
  independent-sensor divergence.
- Data-quality checks: frozen values, telemetry gaps, clock skew, implausible values — a bad reading
  is never displayed as a good temperature.
- Maintenance access: approved windows, vendor access anomalies, session metadata.
- Detection rules and correlated incidents: facts, hypothesis and recommended checks are kept
  separate in every alert.
- Local-first operation: detection and alerting keep working without WAN; bounded local spool for
  later forwarding.
- Hash-chained audit, role-based API access, glass-style dashboard, no external CDN and no
  third-party frontend framework.
- Passive/read-only adapters for Modbus TCP, MQTT, BACnet/IP, SNMP (v1/v2c GET), PCAP and HTTP
  management-UI metadata.

### Access Gate (`retailgate`, default-deny enforcement)

- Write plans with current value, new value, reason, ticket reference (optional), window, and an
  immutable plan hash.
- Approval workflow with MFA (TOTP in this alpha), idempotent approvals, self-approval denial, and
  four-eyes for critical assets.
- Single-use token and source-IP-bound write session; replay, expiry and wrong-source attempts are
  denied and alarmed.
- Modbus TCP enforcement proxy and HTTP(S) reverse proxy for supervisor web UIs.
- Register and URL allowlists; allowlisting is necessary but not sufficient — an approved plan must
  match as well.
- Deny timeline, denial evidence and audit for every refused write.
- Fail-safe matrix: store/audit errors, clock jumps and invalid policy deny the write path; a dead
  gate leaves the plant untouched.
- HMAC-signed webhook notifications with escalation and acknowledgement (`GET /escalations`,
  `POST /escalations/{id}/ack`).

### New in 0.2.0-alpha.2

- **Setup wizard** (first-run, loopback-only) with guided steps for language, site, access
  whitelist, admin account, collectors and completion.
- **IP whitelist** enforced for dashboard, API, SSE, static assets and setup once configured
  (`require_whitelist` defaults to on; fail-closed).
- **Eight UI languages**: English, German, French, Italian, Spanish, Japanese, Chinese, Russian.
- **Original GeDefense logo** and mascot integrated as local assets (no external CDN).
- Linux and Windows packages with installer scripts and SHA-256 checksums.

### Security hardening in 0.2.0-alpha.3

- Hardened installers: dedicated service accounts; Linux config `root:gedefense` `0750`/`0640`,
  Windows `LocalService` with explicit `icacls` DACLs and no inherited `Users` access.
- Release integrity: `SHA256SUMS`, `SHA256SUMS.archives`, cosign keyless signatures and an SPDX
  `SBOM.spdx.json`; Windows binaries remain **NOT_SIGNED** (no Authenticode certificate).
- Bearer-token rotation, mandatory mTLS for the optional central connection, reproducible builds
  with `SOURCE_DATE_EPOCH`, hardened CI permissions and cleaner shutdown/audit flushing.

<a id="architecture"></a>
## Architecture (short)

```text
 Service company / operator
 (VPN / ZTNA, whitelisted)
        │
        ▼
 ┌──────────────────────────────┐        ┌──────────────────────────────┐
 │ retaild (monitoring)         │        │ retailgate (enforcement)     │
 │ passive TAP/SPAN, read-only  │        │ identity, approval, token    │
 │ detection, alerts, audit, UI │        │ audit, Modbus/HTTP proxies   │
 └──────────────┬───────────────┘        └──────────────┬───────────────┘
                │ passive observation                    │ management path only
                │ (never writes)                         │ (plan-bound, default-deny)
                ▼                                        ▼
        OT monitoring segment                  Controllers / supervisors
        (TAP/SPAN, read-only polls)            (Modbus TCP, HTTP(S) admin UI)
```

- One gateway per store; local operation does not depend on the internet.
- The Access Gate is deployed as a **separate appliance/VM with two network interfaces**: a
  management/vendor side and an OT-management conduit. It is not a router and does not sit in the
  process communication between controller and actuators.
- Optional central management is outbound-only (mTLS).

<a id="alpha-limitations"></a>
## Honest alpha limitations

- **No real OT hardware tested.** The data-plane evidence comes from fake controllers and
  supervisors on loopback. Real unit IDs, vendor login flows, certificates and firmware states are
  pilot topics.
- **TOTP is not a phishing-resistant factor.** FIDO2/WebAuthn is planned for a later release; no
  resistance claim is made for the alpha factor.
- **Segmentation is the operator's job.** Without a real "no second path" network design, the gate
  can be bypassed. The monitoring service makes bypasses visible; it cannot prevent them.
- **No automatic bypass correlation.** The gate and the monitoring service are separate; denied
  writes and passive `retail.write-attempt` alerts are correlated manually in this alpha.
- **Certificate pinning and parameter allowlists** are implemented in the proxy but not yet exposed
  in the configuration schema.
- **`write_unknown` without automatic read-back.** If a controller answer is unclear (timeout,
  disconnect), the write is marked `write_unknown` with a critical alert; an operator must verify the
  value with a read-back and must **not retry automatically**.
- **API sessions are in-memory.** A restart logs users out; this is intentional fail-closed
  behavior.
- **No BACnet/MQTT data plane, no vendor-cloud/local-HMI/USB control.** Those are out of scope for
  this alpha and remain operator topics.
- **No compliance statement.** GeDefense Retail does not claim HACCP, NIS2, IEC 62443 or any other
  certification.
- **Windows permissions differ from Linux.** POSIX `0600/0700` is not an access-control mechanism on
  Windows; use a dedicated service account and explicit ACLs. This is a documented beta condition.

<a id="download"></a>
## Download

**Latest alpha release: [v0.2.0-alpha.3](https://github.com/visiongaiatechnology/gedefense-retail/releases/tag/v0.2.0-alpha.3).**
Assets: four archives, [SHA256SUMS](https://github.com/visiongaiatechnology/gedefense-retail/releases/download/v0.2.0-alpha.3/SHA256SUMS),
[SHA256SUMS.archives](https://github.com/visiongaiatechnology/gedefense-retail/releases/download/v0.2.0-alpha.3/SHA256SUMS.archives),
[SBOM.spdx.json](https://github.com/visiongaiatechnology/gedefense-retail/releases/download/v0.2.0-alpha.3/SBOM.spdx.json)
and cosign signatures (`*.sig`/`*.pem`). Windows binaries are **NOT_SIGNED** with Authenticode
(alpha); use the hashes/signatures.

| Platform | Archive | Checksums |
|---|---|---|
| Linux amd64 | [gedefense-retail-0.2.0-alpha.3-linux-amd64.tar.gz](https://github.com/visiongaiatechnology/gedefense-retail/releases/download/v0.2.0-alpha.3/gedefense-retail-0.2.0-alpha.3-linux-amd64.tar.gz) | [SHA256SUMS](https://github.com/visiongaiatechnology/gedefense-retail/releases/download/v0.2.0-alpha.3/SHA256SUMS) · [archives](https://github.com/visiongaiatechnology/gedefense-retail/releases/download/v0.2.0-alpha.3/SHA256SUMS.archives) |
| Linux arm64 | [gedefense-retail-0.2.0-alpha.3-linux-arm64.tar.gz](https://github.com/visiongaiatechnology/gedefense-retail/releases/download/v0.2.0-alpha.3/gedefense-retail-0.2.0-alpha.3-linux-arm64.tar.gz) | [SHA256SUMS](https://github.com/visiongaiatechnology/gedefense-retail/releases/download/v0.2.0-alpha.3/SHA256SUMS) · [archives](https://github.com/visiongaiatechnology/gedefense-retail/releases/download/v0.2.0-alpha.3/SHA256SUMS.archives) |
| Windows amd64 | [gedefense-retail-0.2.0-alpha.3-windows-amd64.zip](https://github.com/visiongaiatechnology/gedefense-retail/releases/download/v0.2.0-alpha.3/gedefense-retail-0.2.0-alpha.3-windows-amd64.zip) | [SHA256SUMS](https://github.com/visiongaiatechnology/gedefense-retail/releases/download/v0.2.0-alpha.3/SHA256SUMS) · [archives](https://github.com/visiongaiatechnology/gedefense-retail/releases/download/v0.2.0-alpha.3/SHA256SUMS.archives) |
| Windows arm64 | [gedefense-retail-0.2.0-alpha.3-windows-arm64.zip](https://github.com/visiongaiatechnology/gedefense-retail/releases/download/v0.2.0-alpha.3/gedefense-retail-0.2.0-alpha.3-windows-arm64.zip) | [SHA256SUMS](https://github.com/visiongaiatechnology/gedefense-retail/releases/download/v0.2.0-alpha.3/SHA256SUMS) · [archives](https://github.com/visiongaiatechnology/gedefense-retail/releases/download/v0.2.0-alpha.3/SHA256SUMS.archives) |

**Verify before installing:** `sha256sum -c SHA256SUMS` inside the unpacked bundle and
`sha256sum -c SHA256SUMS.archives` for the downloaded archives. Archives and `SHA256SUMS` are signed
with cosign keyless; verify a file with `cosign verify-blob --certificate <file>.pem --signature
<file>.sig --certificate-oidc-issuer https://token.actions.githubusercontent.com
--certificate-identity-regexp 'https://github.com/visiongaiatechnology/gedefense-retail/.github/workflows/release.yml@refs/tags/v.*' <file>` (exact identity in
[docs/BUILD-AND-RELEASE.md](docs/BUILD-AND-RELEASE.md)). `SBOM.spdx.json` is the SPDX component
inventory. **If a signature asset is missing, treat the download as unsigned.**

Each bundle contains `bin/` (binaries), `config/` (example configuration and systemd units),
`docs/`, `README.md`, `LICENSE`, `VERSION`, `THIRD-PARTY-NOTICES.md`, the installer scripts and a
`SHA256SUMS` file.

<a id="install-linux"></a>
## Installation — Linux

**Prerequisites**

- Linux x86-64 or arm64 with systemd.
- Administrator rights for installation.
- A management client inside the planned whitelist CIDR (loopback during setup).
- No Go toolchain required for binary packages.
- Plan the whitelist and the OT/management segmentation **before** enabling remote access.

**1. Download and verify**

```bash
tar -xzf gedefense-retail-<version>-linux-amd64.tar.gz
cd gedefense-retail-<version>-linux-amd64
sha256sum -c SHA256SUMS
```

**2. Install**

```bash
sudo ./install.sh
```

The installer creates the service user(s), installs the systemd units from `config/`
(`gedefense-retail.service`, `gedefense-retailgate.service`), prepares `/etc/gedefense-retail/`,
`/var/lib/gedefense-retail/`, `/var/lib/gedefense-gate/` and `/var/log/gedefense-retail/`, and
leaves the monitoring service ready for first-run setup. It copies the **example** configuration
only (`retail.example.json`, `gate.example.json`, `gate-policy.example.json`) and never overwrites
existing files. Configuration is installed `root:gedefense` (`0750` directories, `0640` files), data
directories are owned by the service users, and the installer aborts if these permission steps fail
(fail-closed). The operator creates the productive configuration from the examples:

```bash
sudo cp /etc/gedefense-retail/retail.example.json /etc/gedefense-retail/retail.json
# edit retail.json: site, users, collectors, security whitelist, gate targets/upstreams
```

**3. First-run setup (loopback only)**

```bash
sudo systemctl enable --now gedefense-retail
```

With `setup.completed=false` the first start binds **only to loopback** (configure `listen` as
`127.0.0.1:8080` for the URL below). Open `http://127.0.0.1:8080/setup` on the gateway itself
(SSH tunnel or local browser) and complete the wizard: language, site/timezone, access whitelist
(for example `127.0.0.1/32`, `::1/128` plus your management CIDR), admin token (displayed **once**),
optional collectors, completion (`restart_required: true`). `security.setup_token_ttl_s` defaults to
3600 seconds. The whitelist is fail-closed: without an entry, non-loopback clients receive
`403 ip_not_allowed` and no login page is exposed.

```bash
sudo systemctl restart gedefense-retail
```

**4. Verify**

```bash
systemctl status gedefense-retail --no-pager
retaild version
curl -s http://127.0.0.1:8080/api/v1/health
```

Only source IPs inside `security.dashboard_whitelist_cidrs` can reach dashboard, API, SSE and
static assets. A request from outside the whitelist receives `403 ip_not_allowed`; there is no
fallback login page.

**5. Optional: enable the Access Gate**

Enable the gate only after the monitoring setup is complete. It requires **both** `gate.json` and
`gate-policy.json`; without a valid configuration and policy it refuses to start (fail-closed).

```bash
sudo cp /etc/gedefense-retail/gate.example.json /etc/gedefense-retail/gate.json
sudo cp /etc/gedefense-retail/gate-policy.example.json /etc/gedefense-retail/gate-policy.json
# edit both files: targets, users, whitelist, critical assets, allowlists
sudo retailgate hash-password --password "<at least 12 characters>"
sudo retailgate gen-totp
# insert the printed password hash and TOTP secret into gate.json, then validate and start:
sudo -u gedefense-gate retailgate check --config /etc/gedefense-retail/gate.json
sudo systemctl enable --now gedefense-retailgate
```

The gate must run on the separate two-NIC appliance/VM (management side and OT-management conduit),
not on the monitoring host. Without correct segmentation, the gate is bypassable.

<a id="install-windows"></a>
## Installation — Windows

**Prerequisites**

- Windows 10/11 or Windows Server 2019+ (x64 or arm64), PowerShell 5.1+.
- Administrator rights.
- A management client inside the planned whitelist CIDR; setup runs from loopback only.

**1. Download, extract, verify**

```powershell
Expand-Archive .\gedefense-retail-<version>-windows-amd64.zip -DestinationPath .
cd .\gedefense-retail-<version>-windows-amd64
Get-FileHash .\bin\retaild.exe -Algorithm SHA256
# compare with the values in SHA256SUMS (all files in the bundle)
```

**2. Install**

```powershell
# elevated PowerShell
.\install-windows.ps1
```

The installer creates the program directory `C:\Program Files\GeDefense\Retail\` (with `bin\` and
`config\`), the data directory `C:\ProgramData\GeDefense\Retail\`, and registers the Windows
services via `sc.exe` (`gedefense-retail`, `gedefense-retailgate`). It copies the **example**
configuration only; the operator creates the productive `retail.json` / `gate.json` from the examples
in `config\`. **Firewall rules are not created automatically** — add only the whitelist and
management ports you actually need.

**3. First-run setup**

```powershell
Start-Service gedefense-retail
```

Open `http://127.0.0.1:8080/setup` on the gateway (with `listen` set to `127.0.0.1:8080`), complete
the six setup steps, then restart:

```powershell
Restart-Service gedefense-retail
Get-Service gedefense-retail
.\bin\retaild.exe version
```

**Windows permissions (alpha):** the installer runs both services as `NT AUTHORITY\LocalService`
and sets explicit `icacls` DACLs with inheritance disabled: `config\` read for the service,
`C:\ProgramData\GeDefense\Retail\` modify for the service, Administrators full, `Users` no access.
POSIX modes do not protect NTFS; do not re-enable inherited ACLs. Uninstall does not restore
previous ACLs.

**4. Optional: Access Gate**

```powershell
# config examples: C:\Program Files\GeDefense\Retail\config\gate.example.json / gate-policy.example.json
# productive files: ...\config\gate.json and ...\config\gate-policy.json (edit targets/users/allowlists)
.\bin\retailgate.exe hash-password --password "<at least 12 characters>"
.\bin\retailgate.exe gen-totp
# insert the printed password hash and TOTP secret into gate.json, then validate and start:
.\bin\retailgate.exe check --config "C:\Program Files\GeDefense\Retail\config\gate.json"
Start-Service gedefense-retailgate
```

The gate requires both configuration files and refuses to start without a valid policy
(fail-closed). Run it on a separate two-NIC appliance/VM; the Windows installer does not set up
segmentation or firewall rules.

<a id="quickstart"></a>
## Quickstart

1. Install the package for your platform.
2. Start the monitoring service and finish the loopback setup wizard.
3. Add at least one management client CIDR to the whitelist — otherwise every non-loopback request
   is denied.
4. Sign in to the dashboard with the admin token printed once by the wizard.
5. For simulation or development, run `retail-sim` on the gateway (loopback only, simulation flag
   required) — never against production OT devices.

From source (developers, Go 1.23+, standard library only, no CGO):

```bash
go build ./...
go vet ./...
go test ./...
```

<a id="security"></a>
## Security model

- **Read-only monitoring.** `retaild` has no OT write path. Passive adapters never send write
  function codes, never perform active scans and never send raw probes.
- **Default-deny management path.** `retailgate` forwards only operations that exactly match an
  approved plan; everything else is denied, audited and alarmed.
- **Exact binding.** Target, protocol, function, address and value are approved as a unit. A
  different value or address is a denial even inside the approved time window.
- **Human approval.** Self-approval is rejected; critical assets require two distinct approvers,
  including a `master_admin`. The one-time token is displayed once and bound to the plan hash and
  source IP.
- **Audit before effect.** Denied and allowed operations are written to a hash-chained audit log;
  the gate refuses to start if the chain is broken.
- **Fail-closed.** Gate, store, clock or policy problems close the management path; the plant keeps
  running.
- **Network.** Whitelist enforcement is fail-closed. Do not expose the dashboard or gate to the
  internet; use a VPN/ZTNA path and documented proxy settings if you need remote access.
- **Reporting.** Please report vulnerabilities privately as described in [SECURITY.md](SECURITY.md).
  Do not test against production refrigeration equipment.
- **No compliance claim.** See [SECURITY.md](SECURITY.md) and [NOTICE](NOTICE).

<a id="evidence"></a>
## Verification status (honest)

| Area | Status |
|---|---|
| Build, vet, unit/integration tests, race detector | green (loopback/CI) |
| 0.1 end-to-end acceptance (monitoring) | 39/39 checks passed (loopback/simulation) |
| 0.2.0-alpha.1 Access Gate end-to-end | 25/25 checks passed (loopback, fake controllers) |
| Design QA | mock-data screenshots generated; no screen-reader/touch/long-run validation |
| Real OT hardware | not tested yet (pilot topic) |
| Independent gate penetration test | not yet available |
| Compliance/certification | none claimed |

Counts refer to the verification runs described in the release notes; they are not a production
release statement.

<a id="documentation"></a>
## Documentation

- [README (English)](README.md) · [README (Deutsch)](README.de.md)
- [SECURITY.md](SECURITY.md) — reporting, alpha status, scope
- [CONTRIBUTING.md](CONTRIBUTING.md) — build, tests, safety invariants, pull requests
- [CHANGELOG.md](CHANGELOG.md) — release history
- [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md) — dependencies and assets
- [NOTICE](NOTICE) — copyright and license notice
- [LICENSE](LICENSE) — GNU Affero General Public License v3.0
- [Documentation index](docs/README.md)
- [Releases](https://github.com/visiongaiatechnology/gedefense-retail/releases) ·
  [Issues](https://github.com/visiongaiatechnology/gedefense-retail/issues)

<a id="license"></a>
## License

GeDefense Retail is licensed under the **GNU Affero General Public License v3.0** (AGPL-3.0).
See [LICENSE](LICENSE) and [NOTICE](NOTICE).

Copyright © 2026 VisionGaiaTechnology.
