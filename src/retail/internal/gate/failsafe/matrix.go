// Package failsafe implements the Access Gate fail-safe matrix as executable
// code and provides a test harness for injected dependency failures.
//
// The invariant behind every row: a gate problem may block the management path,
// but it must NEVER touch the refrigeration process. ColdChainAffected is
// therefore always false and a test asserts it for every condition.
//
// The matrix is the operator-visible decision table; the Engine combines the
// active conditions of one evaluation into a single Result (deny/allow, listener
// closure, API availability, health, alert notices, clock stability).
package failsafe

import "github.com/visiongaiatechnology/gedefense/retail/internal/domain"

// Condition is one fail-safe condition from the operator matrix.
type Condition string

const (
	CondAuditStoreFailure   Condition = "audit_store_failure"
	CondAuditStoreFull      Condition = "audit_store_full"
	CondClockJump           Condition = "clock_jump"
	CondPolicyUnreadable    Condition = "policy_unreadable"
	CondPlanStoreCorrupt    Condition = "plan_store_corrupt"
	CondSessionStoreCorrupt Condition = "session_store_corrupt"
	CondGateCoreDown        Condition = "gate_core_down"
	CondMonitoringDown      Condition = "monitoring_down"
	CondUpstreamDown        Condition = "upstream_down"
	CondNetworkSplit        Condition = "network_split"
)

// Decision is one row of the fail-safe matrix.
type Decision struct {
	Condition Condition `json:"condition"`
	// AllowWrite reports whether the data plane may authorize writes at all.
	AllowWrite bool `json:"allow_write"`
	// CloseListeners reports whether the data-plane listeners must be closed
	// (the management path becomes unreachable for the operator).
	CloseListeners bool `json:"close_listeners"`
	// APIUp reports whether the admin/status API stays reachable for recovery.
	APIUp bool `json:"api_up"`
	// ColdChainAffected is always false (hard product invariant).
	ColdChainAffected bool `json:"cold_chain_affected"`
	// Health is ok | degraded | blocked | stopped.
	Health string `json:"health"`
	// Severity is the severity of the fail-safe alert.
	Severity domain.Severity `json:"severity"`
	// DenyReason is the stable domain.Deny* reason reported to the proxy.
	DenyReason string `json:"deny_reason,omitempty"`
	// Alert reports whether an alert must be raised.
	Alert bool `json:"alert"`
	// Note is the operator-facing explanation.
	Note string `json:"note"`
}

// Decisions returns the complete fail-safe matrix in deterministic order.
func Decisions() []Decision {
	return []Decision{
		{
			Condition:  CondAuditStoreFailure,
			AllowWrite: false, CloseListeners: false, APIUp: true, ColdChainAffected: false,
			Health: "degraded", Severity: domain.SeverityCritical, DenyReason: domain.DenyFailsafeStore, Alert: true,
			Note: "Audit-Append fehlgeschlagen: keine Schreibfreigabe ohne Audit. Lesen/Status bleiben für die Recovery erreichbar.",
		},
		{
			Condition:  CondAuditStoreFull,
			AllowWrite: false, CloseListeners: false, APIUp: true, ColdChainAffected: false,
			Health: "degraded", Severity: domain.SeverityCritical, DenyReason: domain.DenyFailsafeStore, Alert: true,
			Note: "Audit-Speicher voll: Gate muss fail-closed schreiben verweigern (kritischer Alarm).",
		},
		{
			Condition:  CondClockJump,
			AllowWrite: false, CloseListeners: false, APIUp: true, ColdChainAffected: false,
			Health: "degraded", Severity: domain.SeverityHigh, DenyReason: domain.DenyFailsafeClock, Alert: true,
			Note: "Clock-Sprung: TTL-/Fensterprüfung ist unzuverlässig; Schreiben deny bis die Zeit stabil ist.",
		},
		{
			Condition:  CondPolicyUnreadable,
			AllowWrite: false, CloseListeners: true, APIUp: true, ColdChainAffected: false,
			Health: "blocked", Severity: domain.SeverityCritical, DenyReason: domain.DenyPolicyMissing, Alert: true,
			Note: "Keine gültige Autorisierungsbasis: Datenpfad gesperrt, Admin-API bleibt für Policy-Reload erreichbar.",
		},
		{
			Condition:  CondPlanStoreCorrupt,
			AllowWrite: false, CloseListeners: false, APIUp: true, ColdChainAffected: false,
			Health: "degraded", Severity: domain.SeverityCritical, DenyReason: domain.DenyFailsafeStore, Alert: true,
			Note: "Plan-Store nicht lesbar: eine Freigabe kann nicht geprüft werden; Schreiben deny, API bleibt für Recovery.",
		},
		{
			Condition:  CondSessionStoreCorrupt,
			AllowWrite: false, CloseListeners: false, APIUp: true, ColdChainAffected: false,
			Health: "degraded", Severity: domain.SeverityCritical, DenyReason: domain.DenyFailsafeStore, Alert: true,
			Note: "Session-Store nicht lesbar: Autorisierung nicht prüfbar; Schreiben deny, API bleibt für Recovery.",
		},
		{
			Condition:  CondGateCoreDown,
			AllowWrite: false, CloseListeners: true, APIUp: false, ColdChainAffected: false,
			Health: "stopped", Severity: domain.SeverityHigh, DenyReason: "", Alert: true,
			Note: "Gate-Kern tot: Listener zu, Management nicht erreichbar; die Kälteanlage läuft unverändert weiter.",
		},
		{
			Condition:  CondMonitoringDown,
			AllowWrite: true, CloseListeners: false, APIUp: true, ColdChainAffected: false,
			Health: "degraded", Severity: domain.SeverityMedium, DenyReason: "", Alert: true,
			Note: "Monitoring (retaild) blind: Enforcement unbeeinflusst, best-effort-Alarm 'Monitoring blind'.",
		},
		{
			Condition:  CondUpstreamDown,
			AllowWrite: true, CloseListeners: false, APIUp: true, ColdChainAffected: false,
			Health: "degraded", Severity: domain.SeverityMedium, DenyReason: "", Alert: true,
			Note: "Upstream-Gerät tot: Proxy-Fehler an den Client, kein Retry-Sturm; Gate-Regeln unverändert.",
		},
		{
			Condition:  CondNetworkSplit,
			AllowWrite: false, CloseListeners: false, APIUp: true, ColdChainAffected: false,
			Health: "degraded", Severity: domain.SeverityHigh, DenyReason: "", Alert: true,
			Note: "Netz-Split OT↔Gate: Lesen/Schreiben nicht möglich, Alarm; Kälteprozess unverändert.",
		},
	}
}

// DecisionFor resolves one matrix row.
func DecisionFor(condition Condition) (Decision, bool) {
	for _, decision := range Decisions() {
		if decision.Condition == condition {
			return decision, true
		}
	}
	return Decision{}, false
}
