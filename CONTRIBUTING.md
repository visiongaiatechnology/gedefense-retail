# Contributing to GeDefense Retail

Thanks for your interest. GeDefense Retail is an experimental alpha; contributions are welcome when
they respect the product's safety boundaries and the AGPL-3.0 license.

By participating you agree to the [Code of Conduct](CODE_OF_CONDUCT.md).

## License of contributions

This project is licensed under **AGPL-3.0** (see [LICENSE](LICENSE)). By submitting a contribution
you agree that it is licensed under the same terms (inbound = outbound). Please sign off your
commits:

```bash
git commit -s -m "your message"
```

The sign-off certifies that you wrote the change or have the right to submit it under AGPL-3.0.

## Development prerequisites

- Go **1.23+** for the runtime and tests.
- Python 3 for the end-to-end test harnesses (standard library only).
- No external Go modules, no CGO, no third-party frontend frameworks, no CDN assets.

```bash
go build ./...
go vet ./...
gofmt -l .          # must be empty
go test ./...
go test -race ./...
```

End-to-end harnesses (loopback, fake controllers; never against production OT):

```bash
python tests/e2e.py        # monitoring
python tests/gate_e2e.py   # access gate
```

## Architecture and conventions

- Go code lives under the module directory; the monitoring service is `retaild`, the gate is
  `retailgate`, the simulator is `retail-sim`.
- Keep files small and modular; the project convention is ≤500 lines per file.
- Use only the Go standard library. New dependencies require a strong justification and a license
  review; the default answer is no.
- Code comments and commit messages in English. User-facing documentation may be translated; the
  English README is the master.
- No secrets, tokens, private keys or real customer/plant data in code, tests, fixtures, logs or
  issues. Use synthetic values.
- No external runtime requests from the UI and no telemetry/analytics SDK.

## Safety invariants (must not regress)

1. **Read-only monitoring.** No code path in `retaild`, the passive adapters or the detection
   pipeline may write to a controller, PLC, BMS or actuator.
2. **No active OT scanning.** No raw probes, SYN scans, fuzzing against production devices or
   unsolicited protocol traffic.
3. **Gate writes only by approved plan.** A write to a controller is allowed only if it exactly
   matches an approved write plan and an approved window; everything else is denied, audited and
   alarmed.
4. **Fail-closed management path.** Gate/store/clock/policy problems must deny writes; an outage
   must never affect the refrigeration process.
5. **No compliance claims.** Do not add text that claims HACCP, NIS2, IEC 62443 or any certification
   without independent evidence and maintainer approval.
6. **Data minimization.** No packet payloads, no personal data, no secrets in logs or audit.

A pull request that weakens one of these invariants will be rejected.

## Pull request process

1. Open an issue or discussion for non-trivial changes before writing code.
2. Keep the change focused; avoid unrelated refactoring and formatting churn.
3. Add or update tests. Bug fixes need a regression test; new behavior needs positive and negative
   cases.
4. Run the commands above locally and describe the results in the pull request.
5. Update `CHANGELOG.md` for user-visible changes.
6. Describe the security impact: what can now be written, read or executed that could not before.

## Reporting security issues

**Do not open public issues for vulnerabilities.** Follow [SECURITY.md](SECURITY.md) and use the
private GitHub security advisory. Never test against production refrigeration equipment.

## Documentation

- The English `README.md` is the master for public documentation; translations follow its structure
  and language switcher.
- Keep relative links valid and do not reference internal project notes.
- Do not include local machine paths, internal hostnames, tokens or personal data.

## Questions

Open a GitHub issue for general questions, or use the security advisory channel for sensitive
topics.
