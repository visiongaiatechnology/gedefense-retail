// Package correlate turns independent rule alerts into documented incidents.
//
// Three chains are defined by the product contract:
//
//   - chain-thermal-manipulation: access outside the approved window, unknown
//     peer, setpoint/mode deviation and a thermal trend within 30 minutes,
//   - chain-sensor-integrity: frozen value / sensor divergence / telemetry gap /
//     clock skew,
//   - chain-remote-intrusion: unknown peer, management-UI access outside the
//     window, new asset and optionally an observed write attempt or setpoint
//     deviation.
//
// The engine never claims an attack. An incident separates observed facts from
// the derived hypothesis and lists alternative explanations and recommended
// checks (hard product rule). Escalation happens only when at least three
// independent indicators match inside a chain window; incidents are deduplicated
// per site + chain + 24 h.
//
// The package performs no I/O and no network access. It reads its context from a
// consumer-defined World (the composition root wires the in-memory registry) and
// keeps a bounded in-memory window of recent alerts so indicators that arrive one
// event at a time can still be correlated. Losing that buffer on restart only
// means that a chain re-starts its window; the incident dedup against the stored
// incidents keeps the case history stable.
package correlate
