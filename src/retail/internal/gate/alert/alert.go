// Package alert turns Access Gate security events into prioritized, evidenced
// alerts. It does not enforce anything: the Gate core decides and records a
// denial; this package explains it, deduplicates it, audits it, publishes it to
// dashboards/SSE and hands it to the notifier.
//
// Product rules:
//
//   - A denial is a fact, not an attack proof. Every alert text separates
//     observed facts ("Beobachtet"), the derived hypothesis ("Abgeleitet") and
//     recommended checks ("Empfohlene Prüfung").
//   - Severity comes from a documented matrix (DenySeverityMatrix). An unknown or
//     unapproved write is critical; a wrong value/address is critical; an expired
//     token is medium; a self-approval attempt is high.
//   - Alerts are deduplicated with a stable key (for denials:
//     gate.deny|<target>|<source>|<function>|<address>), so a deny storm becomes
//     one alert with an increasing count instead of notification spam.
//   - Audit happens before publication/notification. If the audit sink fails, the
//     alert is not reported as audited: the caller treats the write path as
//     fail-closed/degraded.
package alert

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
	"sync/atomic"
	"time"

	"github.com/visiongaiatechnology/gedefense/retail/internal/domain"
)

// Alert families (rule IDs). They are stable and used by the API/UI filters.
const (
	RuleDeniedWrite  = "gate.deny"
	RuleBypass       = "gate.bypass"
	RuleFailsafe     = "gate.failsafe"
	RuleApproval     = "gate.approval"
	RuleWriteUnknown = "gate.write.unknown"
)

// KindWriteUnknown is the alert/event kind for a write whose device outcome is
// unknown (timeout/disconnect/read error). It is neither "allowed" nor "denied":
// the domain transport kinds do not contain it yet, so the alert layer owns the
// stable identifier and the gate API/SSE mapping.
const KindWriteUnknown domain.GateEventKind = "write_unknown"

// ReasonSelfApproval is an approval violation, not a wire deny reason. All wire
// deny reasons are the stable domain.Deny* constants from internal/domain/gate.go
// and are the only strings used in the severity matrix, dedup keys and alert
// texts.
const ReasonSelfApproval = "self_approval"

// SeverityRule is one row of the documented deny-severity matrix.
type SeverityRule struct {
	Reason    string          `json:"reason"`
	Severity  domain.Severity `json:"severity"`
	Rationale string          `json:"rationale"`
}

// DenySeverityMatrix returns the complete, ordered severity matrix. The reasons
// are exactly the stable domain.Deny* constants.
func DenySeverityMatrix() []SeverityRule {
	return []SeverityRule{
		{domain.DenyNoSession, domain.SeverityCritical, "Schreibversuch ohne jede Gate-Session/Freigabe (unbekannter Schreibversuch)."},
		{domain.DenyWrongSource, domain.SeverityCritical, "Session ist an eine andere Quell-IP gebunden; fremde Quelle."},
		{domain.DenyWrongTarget, domain.SeverityCritical, "Ziel weicht von der freigegebenen Bindung ab."},
		{domain.DenyNotApproved, domain.SeverityCritical, "Schreibversuch gegen einen nicht freigegebenen Plan."},
		{domain.DenyOperationNotApproved, domain.SeverityCritical, "Operation ist nicht Teil der Freigabe."},
		{domain.DenyValueMismatch, domain.SeverityCritical, "Wert weicht von der Freigabe ab (falscher Wert)."},
		{domain.DenyAddressMismatch, domain.SeverityCritical, "Adresse/Register weicht von der Freigabe ab."},
		{domain.DenyFailsafeStore, domain.SeverityCritical, "Audit-/Store-Fehler: Gate muss fail-closed sperren."},
		{domain.DenySessionExpired, domain.SeverityHigh, "Vorhandene, aber abgelaufene Session."},
		{domain.DenySessionRevoked, domain.SeverityHigh, "Vorhandene, aber widerrufene Session."},
		{domain.DenyOutsideWindow, domain.SeverityHigh, "Freigabe existiert, das Zeitfenster ist aber nicht aktiv."},
		{domain.DenyMFARequired, domain.SeverityHigh, "Master-Freigabe ohne MFA-Voraussetzung."},
		{domain.DenyPolicyMissing, domain.SeverityHigh, "Policy fehlt/unlesbar: ohne Freigabebasis wird abgelehnt."},
		{domain.DenyFailsafeClock, domain.SeverityHigh, "Clock-Sprung: Fenster-/TTL-Prüfung unzuverlässig."},
		{ReasonSelfApproval, domain.SeverityHigh, "Freigabe durch den Antragsteller (Vier-Augen-Verletzung)."},
		{domain.DenyTokenInvalid, domain.SeverityMedium, "Ungültiges Token."},
		{domain.DenyTokenExpired, domain.SeverityMedium, "Abgelaufenes Token."},
		{domain.DenyTokenUsed, domain.SeverityMedium, "Bereits verbrauchtes Einmal-Token."},
	}
}

// SeverityForDenyReason resolves the matrix entry. Unknown reasons are treated
// as high: an unexplained denial must not be downgraded silently.
func SeverityForDenyReason(reason string) (domain.Severity, string) {
	for _, rule := range DenySeverityMatrix() {
		if rule.Reason == reason {
			return rule.Severity, rule.Rationale
		}
	}
	return domain.SeverityHigh, "Unbekannter Ablehnungsgrund: konservativ als high bewertet."
}

// Evidence is one auditable fact behind an alert (no secrets, no payload bytes).
type Evidence struct {
	Kind        string    `json:"kind"` // deny, session, plan, failsafe, bypass
	RefID       string    `json:"ref_id,omitempty"`
	Description string    `json:"description"`
	At          time.Time `json:"at"`
	Source      string    `json:"source"`
	Value       string    `json:"value,omitempty"`
	Confidence  float64   `json:"confidence"`
}

// Alert is the gate-alert record exposed to the API/SSE/notifier.
type Alert struct {
	AlertID    string               `json:"alert_id"`
	At         time.Time            `json:"at"`
	LastSeenAt time.Time            `json:"last_seen_at"`
	Count      int                  `json:"count"`
	Kind       domain.GateEventKind `json:"kind"`
	RuleID     string               `json:"rule_id"`
	Severity   domain.Severity      `json:"severity"`
	Confidence float64              `json:"confidence"`
	Title      string               `json:"title"`
	Summary    string               `json:"summary"`
	DedupKey   string               `json:"dedup_key"`

	SiteID    domain.SiteID     `json:"site_id,omitempty"`
	TargetID  domain.TargetID   `json:"target_id,omitempty"`
	AssetID   domain.AssetID    `json:"asset_id,omitempty"`
	SourceIP  string            `json:"source_ip,omitempty"`
	DenyID    domain.DenyID     `json:"deny_id,omitempty"`
	SessionID domain.SessionID  `json:"session_id,omitempty"`
	PlanID    domain.PlanID     `json:"plan_id,omitempty"`
	UserID    domain.GateUserID `json:"user_id,omitempty"`
	Reason    string            `json:"reason,omitempty"`

	Protocol  string `json:"protocol,omitempty"`
	Function  string `json:"function,omitempty"`
	Address   string `json:"address,omitempty"`
	ValueHint string `json:"value_hint,omitempty"`

	Evidence                []Evidence                 `json:"evidence"`
	ObservedFacts           []string                   `json:"observed_facts"`
	Hypothesis              string                     `json:"hypothesis"`
	AlternativeExplanations []string                   `json:"alternative_explanations,omitempty"`
	RecommendedChecks       []string                   `json:"recommended_checks,omitempty"`
	RecommendedActions      []domain.RecommendedAction `json:"recommended_actions,omitempty"`
	SafetyConstraints       []string                   `json:"safety_constraints,omitempty"`
}

// Validate enforces the alert contract before it is stored, published or sent.
func (a Alert) Validate() error {
	if err := domain.AlertID(a.AlertID).Validate(); err != nil {
		return fmt.Errorf("gate alert: %w", err)
	}
	if a.Kind == "" {
		return fmt.Errorf("gate alert %q: kind is required", a.AlertID)
	}
	if a.RuleID == "" {
		return fmt.Errorf("gate alert %q: rule id is required", a.AlertID)
	}
	if !a.Severity.Valid() {
		return fmt.Errorf("gate alert %q: invalid severity %q", a.AlertID, a.Severity)
	}
	if a.Confidence < 0 || a.Confidence > 1 {
		return fmt.Errorf("gate alert %q: confidence %v outside [0,1]", a.AlertID, a.Confidence)
	}
	if a.At.IsZero() {
		return fmt.Errorf("gate alert %q: at is required", a.AlertID)
	}
	if a.LastSeenAt.IsZero() {
		return fmt.Errorf("gate alert %q: last_seen_at is required", a.AlertID)
	}
	if a.LastSeenAt.Before(a.At) {
		return fmt.Errorf("gate alert %q: last_seen_at before at", a.AlertID)
	}
	if a.Count < 1 {
		return fmt.Errorf("gate alert %q: count must be >= 1", a.AlertID)
	}
	if a.Title == "" || a.Summary == "" {
		return fmt.Errorf("gate alert %q: title and summary are required", a.AlertID)
	}
	if a.DedupKey == "" {
		return fmt.Errorf("gate alert %q: dedup key is required", a.AlertID)
	}
	if len(a.ObservedFacts) == 0 || a.Hypothesis == "" {
		return fmt.Errorf("gate alert %q: observed facts and hypothesis are required", a.AlertID)
	}
	if len(a.Evidence) == 0 {
		return fmt.Errorf("gate alert %q: evidence is required", a.AlertID)
	}
	for i, evidence := range a.Evidence {
		if evidence.Kind == "" || evidence.Description == "" || evidence.At.IsZero() || evidence.Source == "" {
			return fmt.Errorf("gate alert %q: evidence %d is incomplete", a.AlertID, i)
		}
		if evidence.Confidence < 0 || evidence.Confidence > 1 {
			return fmt.Errorf("gate alert %q: evidence %d confidence outside [0,1]", a.AlertID, i)
		}
	}
	if !strings.Contains(a.Summary, "Beobachtet:") || !strings.Contains(a.Summary, "Abgeleitet") {
		return fmt.Errorf("gate alert %q: summary does not separate observed/derived", a.AlertID)
	}
	return nil
}

// DenyDedupKey is the stable dedup key for a denied write attempt:
// gate.deny|<target>|<source>|<function>|<address>.
func DenyDedupKey(d domain.DeniedWriteAttempt) string {
	return dedupKey("gate.deny", string(d.TargetID), d.SourceIP, d.Function, d.Address)
}

// BypassDedupKey is the stable dedup key for a suspected bypass.
func BypassDedupKey(target, source, function, address string) string {
	return dedupKey("gate.bypass", target, source, function, address)
}

func gateSafetyConstraints() []string {
	return []string{
		"GeDefense führt keine Anlagenänderung, keine Anlagenabschaltung und keine Auto-Isolation aus.",
		"Die OT-Prozesskommunikation wird durch das Gate nicht unterbrochen.",
		"Eine Ablehnung ist ein Fakt; eine Angriffsbehauptung erfordert zusätzliche Evidenz.",
		"Keine Secrets, Token oder Zugangsdaten in Alert, Audit oder Webhook-Payload.",
	}
}

func composeSummary(facts []string, hypothesis string, checks []string) string {
	var b strings.Builder
	b.WriteString("Beobachtet: ")
	for i, fact := range facts {
		if i > 0 {
			b.WriteString("; ")
		}
		b.WriteString(strings.TrimSuffix(strings.TrimSpace(fact), "."))
	}
	b.WriteString(". Abgeleitet (Hypothese): ")
	b.WriteString(strings.TrimSuffix(strings.TrimSpace(hypothesis), "."))
	if len(checks) > 0 {
		b.WriteString(". Empfohlene Prüfung: ")
		limit := 3
		if len(checks) < limit {
			limit = len(checks)
		}
		for i := 0; i < limit; i++ {
			if i > 0 {
				b.WriteString("; ")
			}
			b.WriteString(strings.TrimSuffix(strings.TrimSpace(checks[i]), "."))
		}
	}
	b.WriteString(".")
	return truncateRunes(b.String(), 1600)
}

const (
	dedupMaxLen     = 256
	dedupPartMaxLen = 64
	dedupAllowed    = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._:/-"
)

func dedupKey(parts ...string) string {
	var b strings.Builder
	for _, part := range parts {
		cleaned := sanitizeDedupPart(part)
		if cleaned == "" {
			continue
		}
		if b.Len() > 0 {
			b.WriteString("|")
		}
		b.WriteString(cleaned)
		if b.Len() >= dedupMaxLen {
			break
		}
	}
	key := b.String()
	if len(key) > dedupMaxLen {
		key = key[:dedupMaxLen]
	}
	return key
}

func sanitizeDedupPart(part string) string {
	part = strings.TrimSpace(part)
	if part == "" {
		return ""
	}
	if len(part) > dedupPartMaxLen {
		part = part[:dedupPartMaxLen]
	}
	var b strings.Builder
	b.Grow(len(part))
	for i := 0; i < len(part); i++ {
		c := part[i]
		if strings.IndexByte(dedupAllowed, c) >= 0 {
			b.WriteByte(c)
		} else {
			b.WriteByte('_')
		}
	}
	return b.String()
}

func truncateRunes(s string, max int) string {
	runes := []rune(s)
	if len(runes) <= max {
		return s
	}
	return string(runes[:max]) + "…"
}

func valueOr(value, fallback string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return fallback
	}
	return value
}

var alertFallbackSeq uint64

// newAlertID returns an unpredictable gate alert identifier ("gal_" prefix).
func newAlertID() string {
	var buf [16]byte
	if _, err := rand.Read(buf[:]); err == nil {
		return "gal_" + hex.EncodeToString(buf[:])
	}
	seq := atomic.AddUint64(&alertFallbackSeq, 1)
	return fmt.Sprintf("gal_%032x", seq)
}
