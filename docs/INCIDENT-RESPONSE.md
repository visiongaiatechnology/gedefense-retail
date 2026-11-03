# Incident response runbook

Scope: a GeDefense Retail deployment (`retaild` monitoring gateway and optional `retailgate`
management-path enforcement). This is an alpha runbook, not a certification.

## 1. Classification

| Severity | Example | First action |
|---|---|---|
| SEV-1 | Unauthorised write reached a controller, gate bypassed, ransomware on the gateway host | Isolate the host, notify the store operator and the security contact |
| SEV-2 | Repeated gate denials, whitelist anomaly, audit-chain break, credentials suspected leaked | Preserve evidence, stop remote management, start investigation |
| SEV-3 | Alert storm, collector outage, dashboard unavailable | Restore monitoring, verify the plant is still controlled by its own automation |
| SEV-4 | Cosmetic UI/translation issue, documentation defect | Normal backlog |

## 2. First 15 minutes

1. **Confirm the plant is safe.** GeDefense never controls the plant. Check that the refrigeration
   controller still runs its own regulation; never disable plant safety functions.
2. **Preserve evidence before cleanup:** copy `var/` (event log, audit log, gate audit), the
   configuration files, and `retaild`/`retailgate` service logs to a separate evidence store.
   Do not edit or truncate the audit files.
3. **Close remote management if in doubt:** stop `retailgate` (fail-safe: management path closed,
   plant untouched) and/or remove the affected source networks from
   `security.dashboard_whitelist_cidrs`.
4. **Do not reboot or reinstall** until the evidence copy is verified.
5. Inform the store operator and, for SEV-1/SEV-2, the security contact; keep a timeline of actions.

## 3. Containment

- `retailgate` down or misconfigured → remote management is closed by design; the plant keeps
  running. Do not bypass the gate to "fix" something quickly.
- Suspected credential compromise → rotate dashboard bearer tokens (`retaild token rotate`),
  rotate gate passwords (`retailgate hash-password`), and revoke gate sessions.
- Suspected host compromise → isolate the host at the network layer; do not continue to use its
  dashboard; rebuild from the signed release archive and restore only configuration and data that
  were verified against the audit chain.

## 4. Eradication and recovery

1. Identify the root cause from the audit chain and gate denies; check `retailgate` denies,
   `write_unknown` records and the 0.1 rule `retail.write-attempt`.
2. Patch or reconfigure; retest with `retaild check`, `retailgate check`, the E2E suites and a
   controlled management-window write (four eyes, exact value).
3. Verify the audit chain (`/api/v1/audit`, `/api/v1/gate/audit`) before returning to normal
   operation.
4. Restore monitoring first, then remote management; keep the whitelist minimal.

## 5. Post-incident

- Write a short report: timeline, affected assets, evidence hashes, root cause, fixes, residual risk.
- Update the whitelist, maintenance-window and vendor-access policy if the incident involved access.
- Feed new observable patterns into detection rules or the gate policy; document gaps honestly.

## 6. Contacts

Use the private GitHub security advisory of this repository for vulnerability reports. For an active
incident, follow the operator's escalation plan (store operator, IT security, management).
