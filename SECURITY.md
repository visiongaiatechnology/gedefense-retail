# Security policy

## Supported versions

GeDefense Retail is in an **experimental alpha**. Security fixes are provided on a best-effort
basis; there is no long-term support or response-time guarantee.

| Version | Status |
|---|---|
| `0.2.x` (alpha) | Best-effort security fixes during the alpha |
| `0.1.0` | Previous milestone, monitoring only; no active support commitment |
| Older / unreleased builds | Not supported |

## Reporting a vulnerability

**Please do not open a public issue for security problems.**

Use GitHub's private security advisory for this repository:

<https://github.com/visiongaiatechnology/gedefense-retail/security/advisories/new>

Include, as far as possible:

- affected version and platform (Linux/Windows, architecture),
- deployment mode (monitoring only, or with the Access Gate),
- configuration relevant to the issue (redact secrets and tokens),
- reproduction steps or a minimal proof of concept,
- impact assessment and whether the issue is already public.

**Do not include**: passwords, access tokens, TOTP secrets, private keys, real plant credentials or
personal data. Use synthetic test values.

**Do not test against production refrigeration equipment.** GeDefense Retail is a defensive
project; do not run active scans, write tests or denial-of-service tests against OT devices you do
not own or are not explicitly authorized to test. Test against the simulator or isolated lab setups.

## What to expect

- Acknowledgement and triage on a best-effort basis (alpha project, small team).
- Coordinated disclosure: we will agree on a publication date with you where possible.
- Credit in the advisory/changelog if you wish.
- No bug bounty is offered.

## Scope and honest limits

The alpha has been verified on **loopback with fake controllers and supervisors**. It has not been
tested against real refrigeration hardware in a store, and there is no independent penetration test
of the Access Gate yet.

Security-relevant limitations that are known and documented (see the README section
“Honest alpha limitations”):

- TOTP is the alpha MFA factor; it is not phishing-resistant (FIDO2 is planned).
- Network segmentation is the operator's responsibility; the gate cannot prevent a bypass.
- The gate and the monitoring service are separate; bypass correlation is manual in this alpha.
- Certificate pinning and parameter allowlists are implemented in the proxy but not exposed in the
  configuration schema yet.
- `write_unknown` has no automatic read-back; operators must verify with a read-back and must not
  retry automatically.
- API sessions are in-memory; a restart logs users out.
- POSIX `0600/0700` does not restrict access on Windows; use a dedicated service account and
  explicit ACLs.

**No compliance claim.** This project does not claim HACCP, NIS2, IEC 62443 or any other
certification or regulatory conformity.

## Out of scope

- Vulnerabilities in third-party controller firmware, vendor clouds or local HMI/USB access that are
  outside the gate's scope.
- Issues that require physical access to the gateway or an already-compromised host.
- Findings that require testing against live production OT systems.
- Social engineering of operators.

Operational incidents (e.g. a refrigeration fault) belong to the operator's incident process, not to
this security policy.
