# Deployment guide

## Prerequisites

- Linux with systemd (amd64 or arm64) or Windows 10/11 / Server 2019+ (amd64 or arm64).
- A dedicated management host or VM for `retaild`/`retailgate`. No Go toolchain is required for
  the binary packages.
- Planned IP whitelist and network segmentation: the dashboard must only be reachable from
  management clients, and the controllers only from the gate/monitoring host.
- Planned OT targets (IPs, protocols, read-only register ranges) and, for the gate, the exact
  configuration values that may ever be changed.

## Linux

```bash
tar -xzf gedefense-retail-<version>-linux-amd64.tar.gz
cd gedefense-retail-<version>-linux-amd64
sha256sum -c SHA256SUMS
sudo ./install.sh            # copies binaries, examples, systemd units; does not enable services
```

The installer copies the example configuration to `/etc/gedefense-retail/` only if the files are
missing. Production configuration (`retail.json`, `gate.json`, `gate-policy.json`) is created by
the operator — never ship the examples as-is. Release bundles contain only the curated public
documentation listed in `docs/PUBLIC-DOCS.manifest` (including `docs/retail/`) plus
`data/ot-catalog/`; internal audits, reviews, raw reports and handoffs are never packaged (the
packaging denies unexpected docs fail-closed). The vendor catalog is runtime knowledge for
discovery/API/UI/gate advisory and **not** an auto-allow for writes.

```bash
sudo systemctl daemon-reload
sudo systemctl start gedefense-retail     # monitoring + dashboard
sudo systemctl start gedefense-retailgate # optional: management-path enforcement
sudo journalctl -u gedefense-retail -f
```

First run: `retaild` detects an incomplete setup, binds to loopback only, and serves the guided
setup wizard at `http://127.0.0.1:8080/setup`. The wizard asks for language, store data,
**the IP whitelist**, admin access, optional collectors and finishes with a restart hint.

## Windows

```powershell
Expand-Archive .\gedefense-retail-<version>-windows-amd64.zip -DestinationPath .
cd .\gedefense-retail-<version>-windows-amd64
Get-FileHash .\bin\retaild.exe            # compare with SHA256SUMS
.\bin\retaild.exe version
.\install-windows.ps1                      # registers services and directories (no firewall rules)
```

Configuration examples are placed under `C:\Program Files\GeDefense\Retail\config\`; runtime data
lives in `C:\ProgramData\GeDefense\Retail\`. Services are registered with `sc.exe`
(`gedefense-retail`, `gedefense-retailgate`).

First run: start `retaild.exe serve --config ...`, then open `http://127.0.0.1:8080/setup`.
The setup wizard configures the IP whitelist; without it the dashboard rejects every client.

Firewall rules are intentionally **not** created automatically: decide explicitly which management
clients may reach the dashboard and only open those paths.

## Dashboard access and whitelist

Only source IPs/CIDRs from `security.dashboard_whitelist_cidrs` may access the dashboard, API, SSE
and static assets. Everything else receives `403 ip_not_allowed`. Keep loopback in the whitelist for
local administration. `trust_proxy_headers` is off by default; enable it only behind a trusted
reverse proxy and use the last hop.

## Gate configuration

The gate requires `gate.json` plus a `gate-policy.json` (default-deny). Create credentials with
`retailgate hash-password --password "<at least 12 characters>"` and `retailgate gen-totp`, then
enable the service. Every write approval requires MFA; critical assets require four eyes.

**Read-before-write (Modbus):** immediately before forwarding a write, the gate re-reads the
current value (FC3/FC1) and compares it with the plan's bound current value. `current_value_missing`
(empty), `current_value_unreadable` (read error/timeout) and `current_value_mismatch` (different
value) deny the write and are audited; the write is not forwarded. A new plan/approval is required.
For FC5/FC15 coil writes, configure a separate `read_coils` window on the Modbus target
(`read_coils: {"fc":1,"start":0,"count":N}`); without it the gate denies and `retailgate check`
reports a failing check `RBC-<target>`. Values carry `value_scale` (default `1.0`; raw =
round(display/scale)); decimal values without a scale are rejected (`400`) and flagged by the check.

**HTTP boundary:** there is no generic current-value re-check for HTTP(S) supervisor UIs; URL/method
allowlisting and value binding remain, and the gate check warns when verification is not possible.
Do not treat HTTP writes as equivalent to Modbus read-before-write.

**Vendor catalog:** `data/ot-catalog/` is shipped in the bundle and used for discovery/API/UI/gate
advisory. It never grants write access or whitelist admission (no auto-allow).

## Setpoint integrity and automatic recovery (0.3.0-alpha.1)

Configure the optional `integrity` block in `gate.json`:

```json
"integrity": {
  "enabled": true, "poll_interval_s": 60, "confirm_reads": 3, "stale_after_s": 180,
  "references": [{"target_id":"aksm-1","fc":3,"register":40002,"unit_id":1,
                  "value":"4.0","scale":0.1,"unit":"celsius",
                  "note":"meat room setpoint","recovery":true}],
  "recovery": {"enabled": false, "max_actions_per_hour": 3, "max_actions_per_day": 10,
               "cooldown_s": 300, "require_no_active_window": true}
}
```

- Integrity monitoring polls references via FC3 and confirms deviations (`confirm_reads`) before
  reporting `gate.integrity.mismatch`; `stale_after` flags missing data. `GET
  /api/v1/gate/integrity` exposes state; SSE event `gate_integrity`.
- **Recovery is opt-in and off by default.** Only references with `"recovery": true` are written
  (FC6, no plan/session), subject to hourly/daily limits, cooldown and
  `require_no_active_window`; a read-back verifies the result and events
  `gate.recovery.applied|failed|unknown` are audited. `failed`/`unknown` require manual action.
- Recovery is **not** proof that nobody wrote outside the gate; read→write TOCTOU remains.


**Operator requirements (fail-safe, audit, TOCTOU):**

- **Fail-safe:** while the gate fail-safe status has `AllowWrite=false` (audit store failure/full,
  clock jump, unreadable policy/plan/session store, network split, gate core down), the integrity
  worker performs **no reads and no recovery**. Do not expect or force recovery in that state.
- **Audit fail-closed:** recovery requires an audit intent. Without a successful audit intent no
  recovery write is performed; if the audit append fails **after** the write, the result is
  `gate.recovery.unknown` and there is **no automatic retry**.
- **One attempt per confirmed mismatch:** each confirmed mismatch triggers at most one recovery
  attempt; no flapping loop. A persistent mismatch needs operator triage.
- **TOCTOU:** recovery re-reads shortly before the FC6 write, but read and write are **not atomic**;
  a residual read→write window remains.
- **Scope:** references are operator-approved values and **not** a HACCP/compliance proof. This
  version supports only Modbus `modbus_tcp` FC3 reads and FC6 recovery writes; HTTP targets have no
  integrity monitoring or recovery.
- **Kill switch / escalation:** set `integrity.recovery.enabled=false` (then reload/restart the gate)
  to stop automatic recovery. Respect `max_actions_per_hour/day`, `cooldown_s` and
  `require_no_active_window` (mandatory true when recovery is enabled). Escalate
  `gate.recovery.failed|unknown` to the operator; audit events:
  `gate.integrity.mismatch`, `gate.recovery.applied|failed|unknown`.

## Network enforcement (`retailgate netpolicy`, 0.3.0-alpha.1)

`retailgate netpolicy --config gate.json --format nftables|iptables --gate-source <CIDR>
[--out FILE] [--check] [--apply] [--rollback]`

- Accepts new connections to controllers only from the given gate-source CIDR(s); other new
  connections are dropped and logged. Rules are placed in a dedicated table/chain; `--check` validates
  without applying, `--out` writes the ruleset, `--apply`/`--rollback` manage it.
- **Precondition:** routing/NAT/bridge and segmentation must already work on the gate host; the tool
  is not a router. It only enforces on that host — bypass paths elsewhere remain operator duty.
- Review the generated rules before `--apply`; keep an out-of-band rollback path.

## Bypass detection in `retaild` (0.3.0-alpha.1)

```json
"bypass": {"enabled": true, "gate_source_cidrs": ["10.10.40.0/24", "10.10.50.10/32"]}
```

- `bypass.gate_source_cidrs` accepts CIDR or single-IP entries (IPv4/IPv6 only, max. 64, normalized
  duplicates rejected, no IPv6 zones). Entries are validated even when `enabled:false`; unknown fields
  are configuration errors. `enabled:true` without a valid list **refuses to start** (fail-closed;
  `retaild check` exits non-zero).
- Passive write attempts (`write_attempt`) whose source is outside `gate_source_cidrs` raise the
  monitoring alert `retail.bypass-suspected` (critical, category `access`, rule version 1). Gate
  sources produce no bypass alert; reads/non-write events do not either. The alert carries
  evidence/facts/hypothesis/recommendations from the gate-bypass alert and is deduplicated as
  `retail.bypass-suspected|<site>|<source>|<target>|<register>` (one open alert per source/target/
  register; write storms do not create alert floods).
- The rule is an adapter/gate-signal rule (not part of the passive rule pack, which stays at 15
  rules). It feeds the normal alert engine, correlation and incident chains.
- **Limit:** passive observation proves only the write attempt and that the source is outside the
  gate CIDRs — **not** the actor, an approval, or a proven segmentation gap. The alert states this
  as a hypothesis; verify with device logs/operator evidence. This is a visibility control, not
  prevention.

## Permissions and service accounts (0.3.0-alpha.1)

**Linux (installer)**

- `/etc/gedefense-retail/` is `root:gedefense`, mode `0750`; configuration files are `0640`
  `root:gedefense` (gate files `root:gedefense-gate`).
- Services run as `gedefense` / `gedefense-gate`. Data lives in `/var/lib/gedefense-retail`
  (`gedefense:gedefense` `0700`) and `/var/lib/gedefense-gate` (`gedefense-gate:gedefense-gate`
  `0700`), logs in `/var/log/gedefense-retail` (`0750`).
- The installer fails closed if `chown`/`chmod` steps fail and verifies that the service user can
  read the configuration (and runs `retaild check` when `retail.json` already exists). **Do not**
  use `0644` for configuration: it exposes token hashes and the HMAC secret. Verify with
  `sudo -u gedefense test -r /etc/gedefense-retail/retail.json` and
  `stat -c '%U:%G %a' /etc/gedefense-retail/retail.json` (expect `root:gedefense 640`).
- The uninstaller validates absolute paths (rejects `/`, drive roots, `..` and symlinks), requires
  the installer marker and supports `--dry-run`.

**Windows (installer)**

- Both services run as `NT AUTHORITY\LocalService` (`sc.exe config obj=`).
- `icacls` DACLs are set with inheritance disabled: install directory (Users read+execute,
  LocalService read+execute), `config\` (LocalService read only),
  `C:\ProgramData\GeDefense\Retail\` (LocalService modify), Administrators full.
- Firewall rules are **not** created automatically. The installer writes the marker
  `.gedefense-retail-install`; the uninstaller validates paths and this marker, supports `-DryRun`
  and does **not** restore previous ACLs. Verify with `sc.exe qc gedefense-retail` and
  `icacls "C:\Program Files\GeDefense\Retail\config"`.

## Token rotation (token rotation)

Bearer tokens are stored only as SHA-256 hashes; the plaintext token is printed once. Rotation:

1. Generate a replacement with
   `retaild token rotate --user <id> [--role viewer|operator|admin]` (prints the new token and
   `token_sha256`; it never writes the configuration). `retaild token hash --token <token>` hashes an
   existing token; `retaild gen-token` remains available for new tokens.
2. Replace `token_sha256` in `retail.json` and **restart** `gedefense-retail` — there is no hot
   reload, and the old token stays valid until the restart.
3. Verify the old token is rejected (`401`) and the new token works; `retaild check` rejects empty,
   duplicate and placeholder token hashes.
4. Rotate gate passwords/TOTP secrets and the HMAC webhook secret separately. There is no KMS/HSM
   integration in the alpha; document where secrets are stored.

## Central mTLS (mTLS)

The optional central connection is outbound-only. When `central` is configured, `require_mtls`
defaults to true: an `https://` URL requires `central.client_cert_file`, `central.client_key_file`
and `central.ca_file`, otherwise validation/startup fails. An explicit `require_mtls:false` is a
documented opt-out only for loopback/test endpoints; plain `http://` is accepted only for loopback.
Rotate the client certificate/key/CA files and restart, then check `/api/v1/health` and the spool.
There is no inbound WAN path and no remote control.

## Release verification (checksums, signatures, SBOM)

For release `v0.3.0-alpha.1`:

1. `sha256sum -c SHA256SUMS` inside the unpacked bundle; `sha256sum -c SHA256SUMS.archives` for the
   downloaded archives.
2. Verify the cosign keyless signature of an archive, `SHA256SUMS`, `SHA256SUMS.archives` or
   `SBOM.spdx.json` with
   `cosign verify-blob --signature <file>.sig --certificate <file>.pem
   --certificate-identity-regexp 'https://github.com/visiongaiatechnology/gedefense-retail/.github/workflows/release.yml@refs/tags/v.*'
   --certificate-oidc-issuer https://token.actions.githubusercontent.com <file>`.
3. Review `SBOM.spdx.json` (SPDX-2.3 JSON, generated by `scripts/generate-sbom.py`) for the release
   archives/binaries, hashes and Go version; every bundle file is covered by the bundle `SHA256SUMS`.
4. Windows binaries are **NOT_SIGNED** with Authenticode (alpha); rely on SHA-256 and cosign assets.
   If a signature asset is missing, treat the download as unsigned and report it.

## Graceful shutdown and audit flush (shutdown flush)

Stop services with `systemctl stop` / `Stop-Service` so setup/gate audit buffers are flushed. Avoid a
hard kill: the last buffered entries (up to 128 setup-trail entries on the affected version) can be
lost. Stop during a maintenance window and verify the audit chain on the next start.

## Updating

1. Download the new archive and verify `SHA256SUMS`.
2. Stop both services (plant stays autonomous).
3. Replace binaries; keep `/etc/gedefense-retail` and the data directories.
4. Review `CHANGELOG.md` for configuration changes.
5. Start services and check `/api/v1/health`, the setup state and the audit chain.

## Rollback

Reinstall the previous archive and restart. Configuration and audit data are preserved; the gate
fails closed (remote management disabled) if its configuration cannot be read.
