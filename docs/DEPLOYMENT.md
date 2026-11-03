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

## Updating

1. Download the new archive and verify `SHA256SUMS`.
2. Stop both services (plant stays autonomous).
3. Replace binaries; keep `/etc/gedefense-retail` and the data directories.
4. Review `CHANGELOG.md` for configuration changes.
5. Start services and check `/api/v1/health`, the setup state and the audit chain.

## Rollback

Reinstall the previous archive and restart. Configuration and audit data are preserved; the gate
fails closed (remote management disabled) if its configuration cannot be read.
