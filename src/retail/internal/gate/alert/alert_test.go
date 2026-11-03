package alert_test

import (
	"strings"
	"testing"
	"time"

	"github.com/visiongaiatechnology/gedefense/retail/internal/domain"
	"github.com/visiongaiatechnology/gedefense/retail/internal/gate/alert"
)

var (
	baseTime = time.Date(2026, 11, 4, 2, 14, 0, 0, time.UTC)
	testSite = domain.SiteID("filiale-001")
)

func denialFixture(reason string, severity domain.Severity) domain.DeniedWriteAttempt {
	return domain.DeniedWriteAttempt{
		DenyID:    "den_test_1",
		At:        baseTime,
		SourceIP:  "10.10.40.99",
		TargetID:  "aksm-1",
		Protocol:  "modbus_tcp",
		Function:  "fc6",
		Address:   "40001",
		ValueHint: "3.5",
		Reason:    reason,
		Severity:  severity,
	}
}

func TestDenySeverityMatrixUsesDomainConstants(t *testing.T) {
	t.Parallel()
	expected := map[string]domain.Severity{
		domain.DenyNoSession:            domain.SeverityCritical,
		domain.DenyWrongSource:          domain.SeverityCritical,
		domain.DenyWrongTarget:          domain.SeverityCritical,
		domain.DenyNotApproved:          domain.SeverityCritical,
		domain.DenyOperationNotApproved: domain.SeverityCritical,
		domain.DenyValueMismatch:        domain.SeverityCritical,
		domain.DenyAddressMismatch:      domain.SeverityCritical,
		domain.DenyFailsafeStore:        domain.SeverityCritical,
		domain.DenySessionExpired:       domain.SeverityHigh,
		domain.DenySessionRevoked:       domain.SeverityHigh,
		domain.DenyOutsideWindow:        domain.SeverityHigh,
		domain.DenyMFARequired:          domain.SeverityHigh,
		domain.DenyPolicyMissing:        domain.SeverityHigh,
		domain.DenyFailsafeClock:        domain.SeverityHigh,
		alert.ReasonSelfApproval:        domain.SeverityHigh,
		domain.DenyTokenInvalid:         domain.SeverityMedium,
		domain.DenyTokenExpired:         domain.SeverityMedium,
		domain.DenyTokenUsed:            domain.SeverityMedium,
	}
	matrix := alert.DenySeverityMatrix()
	if len(matrix) != len(expected) {
		t.Fatalf("matrix has %d rows, expected %d", len(matrix), len(expected))
	}
	seen := make(map[string]bool, len(matrix))
	for _, rule := range matrix {
		if seen[rule.Reason] {
			t.Fatalf("duplicate reason %q in severity matrix", rule.Reason)
		}
		seen[rule.Reason] = true
		want, ok := expected[rule.Reason]
		if !ok {
			t.Fatalf("unexpected reason %q in severity matrix", rule.Reason)
		}
		if rule.Severity != want {
			t.Fatalf("reason %q: severity %s, want %s", rule.Reason, rule.Severity, want)
		}
		if rule.Rationale == "" {
			t.Fatalf("reason %q has no rationale", rule.Reason)
		}
	}
	// Unknown reasons are never downgraded silently.
	severity, rationale := alert.SeverityForDenyReason("something-new")
	if severity != domain.SeverityHigh || rationale == "" {
		t.Fatalf("unknown reason must map to high with rationale, got %s %q", severity, rationale)
	}
}

func TestDeniedWriteAlert(t *testing.T) {
	t.Parallel()
	attempt := denialFixture(domain.DenyNoSession, domain.SeverityInfo) // Info must not downgrade
	denied := alert.NewDeniedWriteAlert(attempt, testSite)
	if denied.RuleID != alert.RuleDeniedWrite {
		t.Fatalf("rule id = %q", denied.RuleID)
	}
	if denied.Kind != domain.GateEventWriteDenied {
		t.Fatalf("kind = %q", denied.Kind)
	}
	if denied.Severity != domain.SeverityCritical {
		t.Fatalf("no_session must be critical even if the attempt value is lower, got %s", denied.Severity)
	}
	if denied.DedupKey != "gate.deny|aksm-1|10.10.40.99|fc6|40001" {
		t.Fatalf("dedup key = %q", denied.DedupKey)
	}
	if denied.SiteID != testSite {
		t.Fatalf("site = %q", denied.SiteID)
	}
	if denied.Confidence <= 0 || denied.Confidence > 1 {
		t.Fatalf("confidence = %v", denied.Confidence)
	}
	if len(denied.ObservedFacts) == 0 || denied.Hypothesis == "" || len(denied.RecommendedChecks) == 0 {
		t.Fatalf("alert does not separate facts/hypothesis/checks: %+v", denied)
	}
	if !strings.Contains(denied.Summary, "Beobachtet:") ||
		!strings.Contains(denied.Summary, "Abgeleitet") ||
		!strings.Contains(denied.Summary, "Empfohlene Prüfung:") {
		t.Fatalf("summary does not separate observed/derived/recommended: %q", denied.Summary)
	}
	if len(denied.Evidence) == 0 || denied.Evidence[0].Kind != "deny" {
		t.Fatalf("missing deny evidence: %+v", denied.Evidence)
	}
	if len(denied.SafetyConstraints) == 0 || len(denied.RecommendedActions) == 0 {
		t.Fatal("missing safety constraints or recommended actions")
	}
	approvalAction := false
	for _, action := range denied.RecommendedActions {
		if action.RequiresApproval {
			approvalAction = true
		}
	}
	if !approvalAction {
		t.Fatal("deny alert must contain at least one approval-required action")
	}
}

func TestDeniedWriteAlertEscalatesProvidedSeverity(t *testing.T) {
	t.Parallel()
	attempt := denialFixture(domain.DenyTokenExpired, domain.SeverityCritical)
	denied := alert.NewDeniedWriteAlert(attempt, testSite)
	if denied.Severity != domain.SeverityCritical {
		t.Fatalf("provided critical severity must escalate the medium matrix entry, got %s", denied.Severity)
	}
	tokenExpired := alert.NewDeniedWriteAlert(denialFixture(domain.DenyTokenExpired, domain.SeverityMedium), testSite)
	if tokenExpired.Severity != domain.SeverityMedium {
		t.Fatalf("expired token must be medium, got %s", tokenExpired.Severity)
	}
}

func TestWriteUnknownAlert(t *testing.T) {
	t.Parallel()
	unknown := alert.UnknownWrite{
		At:        baseTime,
		SessionID: "ses_1",
		PlanID:    "pln_1",
		UserID:    "vendor-acme",
		SourceIP:  "10.10.40.12",
		TargetID:  "aksm-1",
		Protocol:  "modbus_tcp",
		Function:  "fc6",
		Address:   "40001",
		ValueHint: "3.5",
		Outcome:   "timeout",
		Detail:    "no response within 5s",
	}
	writeUnknown := alert.NewWriteUnknownAlert(unknown, testSite)
	if writeUnknown.RuleID != alert.RuleWriteUnknown || writeUnknown.Kind != alert.KindWriteUnknown {
		t.Fatalf("unexpected rule/kind: %q/%q", writeUnknown.RuleID, writeUnknown.Kind)
	}
	if writeUnknown.Severity != domain.SeverityCritical {
		t.Fatalf("write-unknown must be critical, got %s", writeUnknown.Severity)
	}
	if !strings.HasPrefix(writeUnknown.DedupKey, "gate.write.unknown|") {
		t.Fatalf("dedup key = %q", writeUnknown.DedupKey)
	}
	joined := strings.Join(writeUnknown.RecommendedChecks, " ")
	if !strings.Contains(joined, "Read-back") || !strings.Contains(joined, "KEIN automatischer Retry") {
		t.Fatalf("write-unknown must require read-back and forbid retry: %v", writeUnknown.RecommendedChecks)
	}
	if !strings.Contains(writeUnknown.Summary, "weder als erlaubt noch als verweigert") {
		t.Fatalf("summary must state the unknown semantics: %q", writeUnknown.Summary)
	}
	if len(writeUnknown.Evidence) == 0 || writeUnknown.Evidence[0].Kind != "write_unknown" {
		t.Fatalf("missing write-unknown evidence: %+v", writeUnknown.Evidence)
	}
}

func TestBypassAlert(t *testing.T) {
	t.Parallel()
	bypass := alert.NewBypassAlert(alert.BypassDetails{
		SiteID:         testSite,
		At:             baseTime,
		TargetID:       "aksm-1",
		AssetID:        "asset-danfoss",
		SourceIP:       "10.10.99.7",
		Protocol:       "modbus_tcp",
		Function:       "fc6",
		Address:        "40001",
		ObservedTarget: "10.10.20.10",
		GateSources:    []string{"10.10.40.0/24"},
		Allowed:        true,
	})
	if bypass.RuleID != alert.RuleBypass || bypass.Kind != domain.GateEventBypass {
		t.Fatalf("unexpected rule/kind: %q/%q", bypass.RuleID, bypass.Kind)
	}
	if bypass.Severity != domain.SeverityCritical {
		t.Fatalf("bypass suspicion must be critical, got %s", bypass.Severity)
	}
	if !strings.HasPrefix(bypass.DedupKey, "gate.bypass|") {
		t.Fatalf("dedup key = %q", bypass.DedupKey)
	}
	facts := strings.Join(bypass.ObservedFacts, " ")
	if !strings.Contains(facts, "außerhalb der konfigurierten Gate-Quellen") {
		t.Fatalf("bypass facts must state the documented limit: %v", bypass.ObservedFacts)
	}
	checks := strings.Join(bypass.RecommendedChecks, " ")
	if !strings.Contains(checks, "Segmentierung") {
		t.Fatalf("bypass checks must ask for segmentation review: %v", bypass.RecommendedChecks)
	}
	if !strings.Contains(bypass.Hypothesis, "beweist weder") && !strings.Contains(bypass.Hypothesis, "nicht bewiesen") {
		t.Fatalf("bypass hypothesis must not claim an attack: %q", bypass.Hypothesis)
	}
}

func TestFailsafeAlertSeverity(t *testing.T) {
	t.Parallel()
	store := alert.NewFailsafeAlert(testSite, baseTime, domain.DenyFailsafeStore, "audit append failed")
	if store.Severity != domain.SeverityCritical {
		t.Fatalf("store fail-safe must be critical, got %s", store.Severity)
	}
	clock := alert.NewFailsafeAlert(testSite, baseTime, domain.DenyFailsafeClock, "clock jumped backwards")
	if clock.Severity != domain.SeverityHigh {
		t.Fatalf("clock fail-safe must be high, got %s", clock.Severity)
	}
	policy := alert.NewFailsafeAlert(testSite, baseTime, domain.DenyPolicyMissing, "policy unreadable")
	if policy.Severity != domain.SeverityCritical {
		t.Fatalf("authorization fail-safe must be critical, got %s", policy.Severity)
	}
	if !strings.HasPrefix(clock.DedupKey, "gate.failsafe|") {
		t.Fatalf("dedup key = %q", clock.DedupKey)
	}
	if !strings.Contains(store.Summary, "Abgeleitet") {
		t.Fatalf("fail-safe summary missing derived section: %q", store.Summary)
	}
}

func TestApprovalAlertSeverity(t *testing.T) {
	t.Parallel()
	selfApproval := alert.NewApprovalAlert(testSite, baseTime, domain.GateEventPlanRejected, "pln_1", alert.ReasonSelfApproval, "vendor-acme")
	if selfApproval.Severity != domain.SeverityHigh {
		t.Fatalf("self-approval must be high, got %s", selfApproval.Severity)
	}
	rejected := alert.NewApprovalAlert(testSite, baseTime, domain.GateEventPlanRejected, "pln_2", "window_expired", "approver-1")
	if rejected.Severity != domain.SeverityMedium {
		t.Fatalf("ordinary rejection must be medium, got %s", rejected.Severity)
	}
	expired := alert.NewApprovalAlert(testSite, baseTime, domain.GateEventPlanExpired, "pln_3", "", "")
	if expired.Severity != domain.SeverityMedium {
		t.Fatalf("expired plan must be medium, got %s", expired.Severity)
	}
	if !strings.Contains(rejected.DedupKey, "pln_2") {
		t.Fatalf("dedup key must identify the plan: %q", rejected.DedupKey)
	}
}

func TestDedupKeysAreStableAndDistinct(t *testing.T) {
	t.Parallel()
	base := denialFixture(domain.DenyNoSession, domain.SeverityCritical)
	first := alert.DenyDedupKey(base)
	if first != alert.DenyDedupKey(base) {
		t.Fatal("deny dedup key is not deterministic")
	}
	otherSource := base
	otherSource.SourceIP = "10.10.40.100"
	if alert.DenyDedupKey(otherSource) == first {
		t.Fatal("different source IPs must not share a dedup key")
	}
	otherTarget := base
	otherTarget.TargetID = "xweb-1"
	if alert.DenyDedupKey(otherTarget) == first {
		t.Fatal("different targets must not share a dedup key")
	}
	otherValue := base
	otherValue.Address = "40002"
	if alert.DenyDedupKey(otherValue) == first {
		t.Fatal("different addresses must not share a dedup key")
	}
	// Sanitisation: weird characters cannot break the key format.
	broken := base
	broken.TargetID = "aksm|1\ninjected"
	key := alert.DenyDedupKey(broken)
	if strings.Contains(key, "\n") || strings.Count(key, "|") < 4 {
		t.Fatalf("dedup key not sanitised: %q", key)
	}
	if alert.BypassDedupKey("t", "s", "f", "a") != alert.BypassDedupKey("t", "s", "f", "a") {
		t.Fatal("bypass dedup key is not deterministic")
	}
}
