# Documentation index

This repository contains the public release material of **GeDefense Retail** (ColdChain & Store
Infrastructure Security). The main entry point is the [README](../README.md).

## User guides

- [Installation and first-run setup (Linux/Windows)](../README.md#install-linux) — package
  installation, loopback setup wizard, whitelist, systemd/Windows service
- [Deployment guide](DEPLOYMENT.md) — prerequisites, Linux/Windows install, whitelist, gate, update, rollback
- [Architecture](ARCHITECTURE.md) — services, data flows, zones, storage, extension points
- [HTTP API v1](API.md) — authentication, roles, monitoring/setup/gate endpoints, error format
- [Security model and honest alpha limits](SECURITY-MODEL.md)
- [Access Gate API contract](retail/access-gate-api-contract.md) — plans, values/`value_scale`,
  read-before-write/TOCTOU, `read_coils`, deny reasons
- [Incident response runbook](INCIDENT-RESPONSE.md)
- [Build and release, including release verification](BUILD-AND-RELEASE.md)
- [Quickstart](../README.md#quickstart)

## Vendor & pilot documentation

- [Vendor and device landscape (DE/EU)](retail/vendor-landscape.md) — vendors, protocols, remote-access models
- [Protocol support matrix](retail/protocol-support-matrix.md) — read-only support, enforcement semantics
  (including Modbus read-before-write), HTTP limits
- [Market and threat context](retail/market-research.md)
- [Pilot acceptance](retail/pilot-acceptance.md) — criteria, status model, exit gates
- [Operations runbook](retail/operations-runbook.md)
- [Deployment guide (product)](retail/deployment-guide.md)
- [Retail policy reference](retail/retail-policy-reference.md)
- [Access Gate vendor workflows](retail/access-gate-vendor-workflows.md)
- [Access Gate vendor onboarding](retail/access-gate-vendor-onboarding.md)
- [Safety boundaries](retail/safety-boundaries.md)
- [Threat model](retail/threat-model.md)

These documents are curated for publication; they contain no internal audit, release or handoff
reports. The vendor catalog (`data/ot-catalog/`) is runtime knowledge for discovery, API, UI and
gate advisory — it is **not** an auto-allow for writes.

## Policies and legal

- [SECURITY.md](../SECURITY.md) — vulnerability reporting, supported versions, alpha status
- [CONTRIBUTING.md](../CONTRIBUTING.md) — build, tests, safety invariants, pull requests
- [CODE_OF_CONDUCT.md](../CODE_OF_CONDUCT.md)
- [CHANGELOG.md](../CHANGELOG.md) — release history
- [NOTICE](../NOTICE) · [LICENSE](../LICENSE) · [THIRD-PARTY-NOTICES.md](../THIRD-PARTY-NOTICES.md)

## Languages

The README is available in English, German, French, Italian, Spanish, Japanese, Chinese and Russian:
[README.md](../README.md) · [README.de.md](../README.de.md) · [README.fr.md](../README.fr.md) ·
[README.it.md](../README.it.md) · [README.es.md](../README.es.md) · [README.ja.md](../README.ja.md) ·
[README.zh.md](../README.zh.md) · [README.ru.md](../README.ru.md).

## Status

0.2.0-alpha.8 — experimental alpha, not production-ready and without compliance claims.
