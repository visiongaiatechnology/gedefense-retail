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
the operator — never ship the examples as-is.

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

## Permissions and service accounts (0.2.0-alpha.3)

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

## Token rotation (FIND-007)

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

## Central mTLS (FIND-008)

The optional central connection is outbound-only. When `central` is configured, `require_mtls`
defaults to true: an `https://` URL requires `central.client_cert_file`, `central.client_key_file`
and `central.ca_file`, otherwise validation/startup fails. An explicit `require_mtls:false` is a
documented opt-out only for loopback/test endpoints; plain `http://` is accepted only for loopback.
Rotate the client certificate/key/CA files and restart, then check `/api/v1/health` and the spool.
There is no inbound WAN path and no remote control.

## Release verification (checksums, signatures, SBOM)

For release `v0.2.0-alpha.3`:

1. `sha256sum -c SHA256SUMS` inside the unpacked bundle; `sha256sum -c SHA256SUMS.archives` for the
   downloaded archives.
2. Verify the cosign keyless signature of an archive, `SHA256SUMS`, `SHA256SUMS.archives` or
   `SBOM.spdx.json` with
   `cosign verify-blob --signature <file>.sig --certificate <file>.pem
   --certificate-identity-regexp 'https://github.com/visiongaiatechnology/gedefense-retail/.github/workflows/release.yml@refs/tags/v.*'
   --certificate-oidc-issuer https://token.actions.githubusercontent.com <file>`.
3. Review `SBOM.spdx.json` (SPDX-2.3 JSON, generated by `scripts/generate-sbom.py`) for bundled
   components, hashes and Go version.
4. Windows binaries are **NOT_SIGNED** with Authenticode (alpha); rely on SHA-256 and cosign assets.
   If a signature asset is missing, treat the download as unsigned and report it.

## Graceful shutdown and audit flush (FIND-010)

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
