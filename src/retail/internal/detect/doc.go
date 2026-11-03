// Package detect is the deterministic, passive detection engine of GeDefense
// Retail.
//
// The engine evaluates normalized events (one event at a time) and a periodic
// tick against a small, consumer-defined read model (World). It never performs
// I/O, never writes to an OT device and never uses wall-clock time except through
// the injected ports.Clock and the World, which makes every rule testable with a
// synthetic world and a fixed clock.
//
// Design rules that the implementation enforces:
//
//   - Every alert separates observed facts from a hypothesis and from
//     recommended checks (domain.CorrelationSummary), so the operator never
//     reads a technical signal as an attack proof.
//   - No single rule emits "critical". Critical severity is reserved for the
//     correlation engine, which requires at least three independent indicators.
//   - Temperature rules depend exclusively on operator-configured policy limits.
//     If a limit is missing, nothing is alerted (hard product rule).
//   - Alerts are deterministic: timestamps come from the injected clock, dedup
//     keys from stable dimensions, and the returned slice is sorted.
//   - Invalid rule output is dropped instead of reaching the store; the test
//     suite asserts that every shipped rule always produces valid alerts.
package detect
