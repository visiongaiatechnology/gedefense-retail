package alert

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/visiongaiatechnology/gedefense/retail/internal/domain"
	"github.com/visiongaiatechnology/gedefense/retail/internal/ports"
)

func TestWorkflowAckAssignClose(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	if err := h.engine.Observe(ctx, []domain.Alert{testAlert("alr-1", "dedup-1", domain.SeverityHigh, baseTime)}); err != nil {
		t.Fatalf("Observe: %v", err)
	}

	acked, err := h.engine.Ack(ctx, "alr-1", "operator-1", "operator", "Betreiber informiert")
	if err != nil {
		t.Fatalf("Ack: %v", err)
	}
	if acked.Status != domain.AlertAcknowledged {
		t.Errorf("status = %q", acked.Status)
	}

	assigned, err := h.engine.Assign(ctx, "alr-1", "operator-1", "operator", "technik-01", "Kälte Nord")
	if err != nil {
		t.Fatalf("Assign: %v", err)
	}
	if assigned.Assignee != "technik-01" {
		t.Errorf("assignee = %q", assigned.Assignee)
	}

	closed, err := h.engine.Close(ctx, "alr-1", "operator-1", "operator", domain.AlertFalsePositive, "Türöffnung 12 min")
	if err != nil {
		t.Fatalf("Close: %v", err)
	}
	if closed.Status != domain.AlertFalsePositive {
		t.Errorf("status = %q", closed.Status)
	}
	if h.publishCount() != 4 { // create + ack + assign + close
		t.Errorf("publishes = %d, want 4", h.publishCount())
	}

	entries, err := h.audit.List(ctx, 10)
	if err != nil {
		t.Fatalf("audit List: %v", err)
	}
	if len(entries) != 3 {
		t.Fatalf("audit entries = %d, want 3", len(entries))
	}
	wantActions := []string{"alert.ack", "alert.assign", "alert.close"}
	for i, want := range wantActions {
		if entries[i].Action != want {
			t.Errorf("audit[%d].Action = %q, want %q", i, entries[i].Action, want)
		}
		if entries[i].Actor != "operator-1" || entries[i].Role != "operator" {
			t.Errorf("audit[%d] actor/role = %q/%q", i, entries[i].Actor, entries[i].Role)
		}
	}
	if ok, _, verr := h.audit.Verify(ctx); verr != nil || !ok {
		t.Fatalf("audit chain = %v, %v", ok, verr)
	}
}

func TestWorkflowErrors(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	if err := h.engine.Observe(ctx, []domain.Alert{testAlert("alr-1", "dedup-1", domain.SeverityHigh, baseTime)}); err != nil {
		t.Fatalf("Observe: %v", err)
	}

	if _, err := h.engine.Ack(ctx, "alr-missing", "operator-1", "operator", ""); !errors.Is(err, ErrNotFound) {
		t.Errorf("Ack missing = %v, want ErrNotFound", err)
	}
	if _, err := h.engine.Ack(ctx, "alr-1", "operator-1", "viewer", ""); !errors.Is(err, ErrForbidden) {
		t.Errorf("Ack as viewer = %v, want ErrForbidden", err)
	}
	if _, err := h.engine.Ack(ctx, "alr-1", "bad id!", "operator", ""); !errors.Is(err, ErrInvalidActor) {
		t.Errorf("Ack with bad actor = %v, want ErrInvalidActor", err)
	}
	if _, err := h.engine.Assign(ctx, "alr-1", "operator-1", "operator", "bad id!", ""); !errors.Is(err, ErrInvalidAssignee) {
		t.Errorf("Assign bad assignee = %v, want ErrInvalidAssignee", err)
	}
	if _, err := h.engine.Close(ctx, "alr-1", "operator-1", "operator", domain.AlertOpen, ""); !errors.Is(err, ErrInvalidStatus) {
		t.Errorf("Close with open status = %v, want ErrInvalidStatus", err)
	}
	if _, err := h.engine.Close(ctx, "alr-1", "operator-1", "operator", domain.AlertResolved, ""); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if _, err := h.engine.Ack(ctx, "alr-1", "operator-1", "operator", ""); !errors.Is(err, ErrConflict) {
		t.Errorf("Ack terminal alert = %v, want ErrConflict", err)
	}
	if _, err := h.engine.Close(ctx, "alr-1", "operator-1", "operator", domain.AlertResolved, ""); !errors.Is(err, ErrConflict) {
		t.Errorf("Close twice = %v, want ErrConflict", err)
	}
}

func TestNotifierFailureNeverBlocks(t *testing.T) {
	h := newHarness(t)
	h.notifier.failWith = errors.New("webhook down")
	if err := h.engine.Observe(context.Background(), []domain.Alert{testAlert("alr-1", "dedup-1", domain.SeverityCritical, baseTime)}); err != nil {
		t.Fatalf("Observe must not fail on notifier error: %v", err)
	}
	if got := h.engine.NotifyFailures(); got != 1 {
		t.Errorf("NotifyFailures = %d, want 1", got)
	}
}

func TestNotificationThreshold(t *testing.T) {
	h := newHarness(t)
	h.engine = NewEngine(Options{
		Store:     h.store,
		Notifier:  h.notifier,
		Clock:     h.clock,
		Audit:     h.audit,
		MinNotify: func() domain.Severity { return domain.SeverityCritical },
	})
	ctx := context.Background()
	if err := h.engine.Observe(ctx, []domain.Alert{testAlert("alr-1", "dedup-1", domain.SeverityHigh, baseTime)}); err != nil {
		t.Fatalf("Observe high: %v", err)
	}
	if h.notifier.count() != 0 {
		t.Errorf("notifications = %d, want 0 below threshold", h.notifier.count())
	}
	if err := h.engine.Observe(ctx, []domain.Alert{testAlert("alr-2", "dedup-2", domain.SeverityCritical, baseTime)}); err != nil {
		t.Fatalf("Observe critical: %v", err)
	}
	if h.notifier.count() != 1 {
		t.Errorf("notifications = %d, want 1 at threshold", h.notifier.count())
	}
}

func TestEngineWithoutStore(t *testing.T) {
	engine := NewEngine(Options{})
	ctx := context.Background()
	if err := engine.Observe(ctx, []domain.Alert{testAlert("alr-1", "d", domain.SeverityHigh, baseTime)}); !errors.Is(err, ErrNoStore) {
		t.Errorf("Observe = %v, want ErrNoStore", err)
	}
	if _, _, err := engine.Get(ctx, "alr-1"); !errors.Is(err, ErrNoStore) {
		t.Errorf("Get = %v, want ErrNoStore", err)
	}
	if _, err := engine.List(ctx, ports.AlertQuery{}); !errors.Is(err, ErrNoStore) {
		t.Errorf("List = %v, want ErrNoStore", err)
	}
}

func TestConcurrentObserveKeepsSingleAlertPerDedupKey(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	var wg sync.WaitGroup
	for worker := 0; worker < 8; worker++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			alert := testAlert("", "shared-dedup", domain.SeverityHigh, baseTime)
			if err := h.engine.Observe(ctx, []domain.Alert{alert}); err != nil {
				t.Errorf("Observe: %v", err)
			}
		}(worker)
	}
	wg.Wait()
	alerts, err := h.engine.Snapshot(ctx)
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	if len(alerts) != 1 {
		t.Fatalf("alerts = %d, want 1 for one dedup key", len(alerts))
	}
}
