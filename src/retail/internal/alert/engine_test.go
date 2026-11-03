package alert

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/visiongaiatechnology/gedefense/retail/internal/domain"
	"github.com/visiongaiatechnology/gedefense/retail/internal/store"
)

type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func newFakeClock(start time.Time) *fakeClock { return &fakeClock{now: start} }

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

var baseTime = time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)

// recordingNotifier captures notifications and can be configured to fail.
type recordingNotifier struct {
	mu       sync.Mutex
	alerts   []domain.Alert
	failWith error
}

func (n *recordingNotifier) Notify(_ context.Context, alert domain.Alert) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.failWith != nil {
		return n.failWith
	}
	n.alerts = append(n.alerts, alert)
	return nil
}

func (n *recordingNotifier) count() int {
	n.mu.Lock()
	defer n.mu.Unlock()
	return len(n.alerts)
}

// harness bundles an engine with its real store, audit log and recordings.
type harness struct {
	engine   *Engine
	store    *store.AlertStore
	audit    *store.AuditLog
	notifier *recordingNotifier
	clock    *fakeClock

	mu      sync.Mutex
	publish []domain.Alert
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	dir := t.TempDir()
	clock := newFakeClock(baseTime)
	alertStore, err := store.OpenAlertStore(store.Options{Dir: dir, Clock: clock})
	if err != nil {
		t.Fatalf("OpenAlertStore: %v", err)
	}
	t.Cleanup(func() {
		if cerr := alertStore.Close(); cerr != nil {
			t.Errorf("AlertStore.Close: %v", cerr)
		}
	})
	audit, err := store.OpenAuditLog(store.Options{Dir: dir, Clock: clock})
	if err != nil {
		t.Fatalf("OpenAuditLog: %v", err)
	}
	t.Cleanup(func() {
		if cerr := audit.Close(); cerr != nil {
			t.Errorf("AuditLog.Close: %v", cerr)
		}
	})
	h := &harness{store: alertStore, audit: audit, notifier: &recordingNotifier{}, clock: clock}
	h.engine = NewEngine(Options{
		Store:    alertStore,
		Notifier: h.notifier,
		Clock:    clock,
		Audit:    audit,
		Publish: func(_ string, payload any) {
			if alert, ok := payload.(domain.Alert); ok {
				h.mu.Lock()
				h.publish = append(h.publish, alert)
				h.mu.Unlock()
			}
		},
	})
	return h
}

func (h *harness) publishCount() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.publish)
}

func testAlert(id, dedup string, severity domain.Severity, at time.Time) domain.Alert {
	return domain.Alert{
		AlertID:     domain.AlertID(id),
		SiteID:      "filiale-001",
		Category:    domain.CategoryThermal,
		Severity:    severity,
		Confidence:  0.8,
		Title:       "Temperature above limit",
		Summary:     "Zone 1 exceeded the configured maximum for 5 minutes.",
		RuleID:      domain.RuleID("retail.thermal.limit"),
		RuleVersion: "1",
		FirstSeenAt: at,
		LastSeenAt:  at,
		Status:      domain.AlertOpen,
		DedupKey:    dedup,
		Evidence:    []domain.Evidence{},
		CreatedAt:   at,
		UpdatedAt:   at,
	}
}

func TestObserveCreatesAlert(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	if err := h.engine.Observe(ctx, []domain.Alert{testAlert("alr-1", "dedup-1", domain.SeverityHigh, baseTime)}); err != nil {
		t.Fatalf("Observe: %v", err)
	}
	alert, ok, err := h.engine.Get(ctx, "alr-1")
	if err != nil || !ok {
		t.Fatalf("Get: ok=%v err=%v", ok, err)
	}
	if alert.Status != domain.AlertOpen {
		t.Errorf("status = %q", alert.Status)
	}
	if len(alert.AuditHistory) != 1 || alert.AuditHistory[0].Action != "alert.created" {
		t.Errorf("audit history = %+v", alert.AuditHistory)
	}
	if len(alert.Evidence) != 0 {
		t.Errorf("evidence = %+v", alert.Evidence)
	}
	if h.notifier.count() != 1 {
		t.Errorf("notifications = %d, want 1 (high >= default threshold)", h.notifier.count())
	}
	if h.publishCount() != 1 {
		t.Errorf("publishes = %d, want 1", h.publishCount())
	}
	if count, cerr := h.engine.Count(ctx); cerr != nil || count != 1 {
		t.Errorf("Count = %d, %v", count, cerr)
	}
}

func TestObserveGeneratesMissingIdentity(t *testing.T) {
	h := newHarness(t)
	alert := testAlert("", "", domain.SeverityMedium, baseTime)
	if err := h.engine.Observe(context.Background(), []domain.Alert{alert}); err != nil {
		t.Fatalf("Observe: %v", err)
	}
	stored, err := h.engine.Snapshot(context.Background())
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	if len(stored) != 1 {
		t.Fatalf("stored alerts = %d, want 1", len(stored))
	}
	if stored[0].AlertID == "" || stored[0].DedupKey != string(stored[0].AlertID) {
		t.Errorf("normalised alert = %+v", stored[0])
	}
	if stored[0].Status != domain.AlertOpen {
		t.Errorf("status = %q", stored[0].Status)
	}
}

func TestObserveDeduplicatesByKey(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	first := testAlert("alr-1", "dedup-1", domain.SeverityHigh, baseTime)
	if err := h.engine.Observe(ctx, []domain.Alert{first}); err != nil {
		t.Fatalf("Observe first: %v", err)
	}

	// A second detection with a different alert id but the same dedup key must
	// merge into the open alert instead of creating a new one.
	second := testAlert("alr-2", "dedup-1", domain.SeverityMedium, baseTime.Add(5*time.Minute))
	second.Evidence = []domain.Evidence{{Kind: "event", RefID: "evt-9", Description: "second sample", At: baseTime, Source: "detect", Confidence: 0.7}}
	h.clock.Advance(5 * time.Minute)
	if err := h.engine.Observe(ctx, []domain.Alert{second}); err != nil {
		t.Fatalf("Observe second: %v", err)
	}

	alerts, err := h.engine.Snapshot(ctx)
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	if len(alerts) != 1 {
		t.Fatalf("alerts after dedup = %d, want 1", len(alerts))
	}
	merged := alerts[0]
	if merged.AlertID != "alr-1" {
		t.Errorf("merge kept id %q, want alr-1", merged.AlertID)
	}
	if !merged.LastSeenAt.Equal(second.LastSeenAt) {
		t.Errorf("LastSeenAt = %v, want %v", merged.LastSeenAt, second.LastSeenAt)
	}
	if merged.Severity != domain.SeverityHigh {
		t.Errorf("severity must never be lowered, got %q", merged.Severity)
	}
	if len(merged.Evidence) != 1 {
		t.Errorf("evidence = %+v", merged.Evidence)
	}
	if h.notifier.count() != 1 {
		t.Errorf("notifications = %d, want 1 (no escalation, no re-notify)", h.notifier.count())
	}
}

func TestObserveEscalatesSeverityAndNotifies(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	if err := h.engine.Observe(ctx, []domain.Alert{testAlert("alr-1", "dedup-1", domain.SeverityHigh, baseTime)}); err != nil {
		t.Fatalf("Observe: %v", err)
	}
	escalated := testAlert("alr-2", "dedup-1", domain.SeverityCritical, baseTime.Add(time.Minute))
	escalated.Summary = "Three independent indicators matched."
	escalated.Correlation = &domain.CorrelationSummary{ObservedFacts: []string{"access outside window"}, Hypothesis: "thermal manipulation"}
	if err := h.engine.Observe(ctx, []domain.Alert{escalated}); err != nil {
		t.Fatalf("Observe escalation: %v", err)
	}

	alerts, err := h.engine.Snapshot(ctx)
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	if len(alerts) != 1 || alerts[0].Severity != domain.SeverityCritical {
		t.Fatalf("alerts = %+v", alerts)
	}
	if alerts[0].Summary != escalated.Summary {
		t.Errorf("summary not updated on escalation: %q", alerts[0].Summary)
	}
	if alerts[0].Correlation == nil {
		t.Error("correlation lost on escalation")
	}
	actions := 0
	for _, entry := range alerts[0].AuditHistory {
		if entry.Action == "alert.escalate" {
			actions++
		}
	}
	if actions != 1 {
		t.Errorf("escalation audit entries = %d, want 1", actions)
	}
	if h.notifier.count() != 2 {
		t.Errorf("notifications = %d, want 2 (create + escalation)", h.notifier.count())
	}
}

func TestObserveNeverDowngradesStatus(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	if err := h.engine.Observe(ctx, []domain.Alert{testAlert("alr-1", "dedup-1", domain.SeverityHigh, baseTime)}); err != nil {
		t.Fatalf("Observe: %v", err)
	}
	if _, err := h.engine.Ack(ctx, "alr-1", "operator-1", "operator", "seen"); err != nil {
		t.Fatalf("Ack: %v", err)
	}
	if err := h.engine.Observe(ctx, []domain.Alert{testAlert("alr-2", "dedup-1", domain.SeverityHigh, baseTime.Add(time.Minute))}); err != nil {
		t.Fatalf("Observe after ack: %v", err)
	}
	alert, _, err := h.engine.Get(ctx, "alr-1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if alert.Status != domain.AlertAcknowledged {
		t.Errorf("status = %q, must stay acknowledged", alert.Status)
	}
}

func TestObserveEvidenceBounded(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	first := testAlert("alr-1", "dedup-1", domain.SeverityHigh, baseTime)
	if err := h.engine.Observe(ctx, []domain.Alert{first}); err != nil {
		t.Fatalf("Observe: %v", err)
	}
	for i := 0; i < 40; i++ {
		next := testAlert("alr-x", "dedup-1", domain.SeverityHigh, baseTime)
		next.Evidence = []domain.Evidence{{
			Kind: "event", RefID: fmt.Sprintf("evt-%d", i), Description: "sample",
			At: baseTime.Add(time.Duration(i) * time.Second), Source: "detect", Confidence: 0.5,
		}}
		if err := h.engine.Observe(ctx, []domain.Alert{next}); err != nil {
			t.Fatalf("Observe %d: %v", i, err)
		}
	}
	alert, _, err := h.engine.Get(ctx, "alr-1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if len(alert.Evidence) != maxEvidence {
		t.Errorf("evidence = %d, want %d", len(alert.Evidence), maxEvidence)
	}
}

func TestObserveRejectsInvalidAndKeepsValidBatch(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	invalid := testAlert("alr-bad", "dedup-bad", domain.SeverityHigh, baseTime)
	invalid.Title = ""
	valid := testAlert("alr-ok", "dedup-ok", domain.SeverityHigh, baseTime)

	err := h.engine.Observe(ctx, []domain.Alert{invalid, valid})
	if err == nil {
		t.Fatal("expected error for invalid alert")
	}
	alerts, serr := h.engine.Snapshot(ctx)
	if serr != nil {
		t.Fatalf("Snapshot: %v", serr)
	}
	if len(alerts) != 1 || alerts[0].AlertID != "alr-ok" {
		t.Errorf("valid alert of the batch was not stored: %+v", alerts)
	}
}

func TestObserveRejectsAlertWithTerminalStatus(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	created := testAlert("alr-1", "dedup-1", domain.SeverityHigh, baseTime)
	if err := h.engine.Observe(ctx, []domain.Alert{created}); err != nil {
		t.Fatalf("Observe: %v", err)
	}
	if _, err := h.engine.Close(ctx, "alr-1", "operator-1", "operator", domain.AlertResolved, "done"); err != nil {
		t.Fatalf("Close: %v", err)
	}
	again := testAlert("alr-1", "dedup-1", domain.SeverityHigh, baseTime.Add(time.Minute))
	if err := h.engine.Observe(ctx, []domain.Alert{again}); !errors.Is(err, ErrConflict) {
		t.Fatalf("Observe closed alert = %v, want ErrConflict", err)
	}
}
