package alert_test

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/visiongaiatechnology/gedefense/retail/internal/domain"
	"github.com/visiongaiatechnology/gedefense/retail/internal/gate/alert"
	"github.com/visiongaiatechnology/gedefense/retail/internal/gate/notify"
)

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

type auditRecorder struct {
	mu      sync.Mutex
	entries []domain.AuditEntry
	err     error
}

func (a *auditRecorder) Append(_ context.Context, entry domain.AuditEntry) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.err != nil {
		return a.err
	}
	a.entries = append(a.entries, entry)
	return nil
}

func (a *auditRecorder) count() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.entries)
}

func (a *auditRecorder) all() []domain.AuditEntry {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]domain.AuditEntry(nil), a.entries...)
}

type publisherRecorder struct {
	mu     sync.Mutex
	alerts []alert.Alert
}

func (p *publisherRecorder) Publish(a alert.Alert) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.alerts = append(p.alerts, a)
}

func (p *publisherRecorder) count() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.alerts)
}

type notifierRecorder struct {
	mu            sync.Mutex
	notifications []notify.Notification
	err           error
}

func (n *notifierRecorder) Notify(_ context.Context, notification notify.Notification) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.err != nil {
		return n.err
	}
	n.notifications = append(n.notifications, notification)
	return nil
}

func (n *notifierRecorder) count() int {
	n.mu.Lock()
	defer n.mu.Unlock()
	return len(n.notifications)
}

func (n *notifierRecorder) all() []notify.Notification {
	n.mu.Lock()
	defer n.mu.Unlock()
	return append([]notify.Notification(nil), n.notifications...)
}

type testEngine struct {
	clock     *fakeClock
	audit     *auditRecorder
	publisher *publisherRecorder
	notifier  *notifierRecorder
	engine    *alert.Engine
}

func newTestEngine(t *testing.T, mutate func(*alert.Options)) *testEngine {
	t.Helper()
	deps := &testEngine{
		clock:     &fakeClock{t: baseTime},
		audit:     &auditRecorder{},
		publisher: &publisherRecorder{},
		notifier:  &notifierRecorder{},
	}
	opts := alert.Options{
		Clock:     deps.clock,
		SiteID:    testSite,
		Audit:     deps.audit,
		Publisher: deps.publisher,
		Notifier:  deps.notifier,
	}
	if mutate != nil {
		mutate(&opts)
	}
	engine, err := alert.New(opts)
	if err != nil {
		t.Fatalf("alert.New: %v", err)
	}
	deps.engine = engine
	return deps
}

func requireValidAlert(t *testing.T, a alert.Alert) {
	t.Helper()
	if err := a.Validate(); err != nil {
		t.Fatalf("invalid gate alert: %v", err)
	}
	if !strings.HasPrefix(a.AlertID, "gal_") {
		t.Fatalf("alert id %q has no gal_ prefix", a.AlertID)
	}
	if a.Count < 1 {
		t.Fatalf("alert count = %d", a.Count)
	}
}

func TestOnDeniedWriteEmitsAlert(t *testing.T) {
	t.Parallel()
	deps := newTestEngine(t, nil)
	denied, err := deps.engine.OnDeniedWrite(context.Background(), denialFixture(domain.DenyNoSession, domain.SeverityCritical))
	if err != nil {
		t.Fatalf("OnDeniedWrite: %v", err)
	}
	requireValidAlert(t, denied)
	if denied.RuleID != alert.RuleDeniedWrite || denied.Severity != domain.SeverityCritical || denied.Count != 1 {
		t.Fatalf("unexpected alert: %+v", denied)
	}
	if denied.SiteID != testSite {
		t.Fatalf("site fallback missing: %q", denied.SiteID)
	}
	if deps.publisher.count() != 1 {
		t.Fatalf("expected one published alert, got %d", deps.publisher.count())
	}
	if deps.audit.count() != 1 {
		t.Fatalf("expected one audit entry, got %d", deps.audit.count())
	}
	entry := deps.audit.all()[0]
	if entry.Action != "gate.alert.raised" || entry.ObjectType != "gate.alert" || entry.ObjectID != denied.AlertID {
		t.Fatalf("unexpected audit entry: %+v", entry)
	}
	if strings.Contains(entry.Reason, "password") || strings.Contains(entry.Reason, "token=") {
		t.Fatalf("audit reason contains secret-like content: %q", entry.Reason)
	}
	if deps.notifier.count() != 1 {
		t.Fatalf("expected one notification, got %d", deps.notifier.count())
	}
	notification := deps.notifier.all()[0]
	if !notification.AckRequired || notification.ID != denied.AlertID {
		t.Fatalf("unexpected notification: %+v", notification)
	}
	if len(notification.ObservedFacts) == 0 || notification.Hypothesis == "" {
		t.Fatalf("notification does not separate facts and hypothesis: %+v", notification)
	}
	stats := deps.engine.Stats()
	if stats.Emitted != 1 || stats.Notified != 1 || stats.Published != 1 || stats.AuditFailed != 0 {
		t.Fatalf("unexpected stats: %+v", stats)
	}
}

func TestDenyAlertsDeduplicateWithinWindow(t *testing.T) {
	t.Parallel()
	deps := newTestEngine(t, nil)
	attempt := denialFixture(domain.DenyNoSession, domain.SeverityCritical)
	first, err := deps.engine.OnDeniedWrite(context.Background(), attempt)
	if err != nil {
		t.Fatalf("first deny: %v", err)
	}
	deps.clock.Advance(time.Minute)
	second, err := deps.engine.OnDeniedWrite(context.Background(), attempt)
	if err != nil {
		t.Fatalf("second deny: %v", err)
	}
	if second.AlertID != first.AlertID {
		t.Fatalf("deny storm must dedupe, got %q vs %q", second.AlertID, first.AlertID)
	}
	if second.Count != 2 || !second.LastSeenAt.Equal(baseTime.Add(time.Minute)) {
		t.Fatalf("unexpected merged alert: count=%d last=%v", second.Count, second.LastSeenAt)
	}
	if deps.publisher.count() != 2 {
		t.Fatalf("updates must be published, got %d", deps.publisher.count())
	}
	if deps.notifier.count() != 1 {
		t.Fatalf("dedup without escalation must not notify again, got %d", deps.notifier.count())
	}
	if deps.audit.count() != 1 {
		t.Fatalf("dedup must not audit again, got %d", deps.audit.count())
	}
	if stats := deps.engine.Stats(); stats.Deduped != 1 || stats.Emitted != 1 {
		t.Fatalf("unexpected stats: %+v", stats)
	}
}

func TestDenyDedupEscalatesSeverity(t *testing.T) {
	t.Parallel()
	deps := newTestEngine(t, nil)
	low := denialFixture(domain.DenyTokenExpired, domain.SeverityMedium)
	first, err := deps.engine.OnDeniedWrite(context.Background(), low)
	if err != nil {
		t.Fatalf("first deny: %v", err)
	}
	if first.Severity != domain.SeverityMedium {
		t.Fatalf("expected medium token alert, got %s", first.Severity)
	}
	deps.clock.Advance(time.Minute)
	high := denialFixture(domain.DenyValueMismatch, domain.SeverityCritical)
	second, err := deps.engine.OnDeniedWrite(context.Background(), high)
	if err != nil {
		t.Fatalf("second deny: %v", err)
	}
	if second.AlertID != first.AlertID {
		t.Fatal("same dedup dimensions must merge")
	}
	if second.Severity != domain.SeverityCritical {
		t.Fatalf("severity must escalate to critical, got %s", second.Severity)
	}
	if deps.notifier.count() != 2 {
		t.Fatalf("escalation must notify again, got %d", deps.notifier.count())
	}
	actions := make(map[string]bool)
	for _, entry := range deps.audit.all() {
		actions[entry.Action] = true
	}
	if !actions["gate.alert.raised"] || !actions["gate.alert.escalated"] {
		t.Fatalf("expected raised and escalated audit entries, got %v", actions)
	}
}

func TestDenyDedupWindowExpires(t *testing.T) {
	t.Parallel()
	deps := newTestEngine(t, nil)
	attempt := denialFixture(domain.DenyNoSession, domain.SeverityCritical)
	first, err := deps.engine.OnDeniedWrite(context.Background(), attempt)
	if err != nil {
		t.Fatalf("first deny: %v", err)
	}
	deps.clock.Advance(6 * time.Minute) // default dedup window is 5 minutes
	second, err := deps.engine.OnDeniedWrite(context.Background(), attempt)
	if err != nil {
		t.Fatalf("second deny: %v", err)
	}
	if second.AlertID == first.AlertID {
		t.Fatal("expired dedup window must create a new alert")
	}
	if second.Count != 1 {
		t.Fatalf("new alert count = %d", second.Count)
	}
	if deps.notifier.count() != 2 {
		t.Fatalf("new occurrence must notify, got %d", deps.notifier.count())
	}
}

func TestAuditFailureBlocksPublication(t *testing.T) {
	t.Parallel()
	deps := newTestEngine(t, nil)
	deps.audit.err = errors.New("audit disk full")
	emitted, err := deps.engine.OnDeniedWrite(context.Background(), denialFixture(domain.DenyNoSession, domain.SeverityCritical))
	if err == nil {
		t.Fatal("audit failure must be returned to the deny path")
	}
	if emitted.AlertID == "" {
		t.Fatal("the alert draft should still be returned for diagnostics")
	}
	if deps.publisher.count() != 0 || deps.notifier.count() != 0 {
		t.Fatal("unaudited alert must not be published or notified")
	}
	if stats := deps.engine.Stats(); stats.AuditFailed != 1 {
		t.Fatalf("unexpected stats: %+v", stats)
	}
	// After the store recovers, the next attempt must be audited (no phantom
	// dedup entry from the failed emit).
	deps.audit.mu.Lock()
	deps.audit.err = nil
	deps.audit.mu.Unlock()
	if _, err := deps.engine.OnDeniedWrite(context.Background(), denialFixture(domain.DenyNoSession, domain.SeverityCritical)); err != nil {
		t.Fatalf("recovered deny: %v", err)
	}
	if deps.audit.count() != 1 {
		t.Fatalf("expected the retried alert to be audited, got %d entries", deps.audit.count())
	}
}

func TestNotifierFailureDoesNotBlockDenyPath(t *testing.T) {
	t.Parallel()
	deps := newTestEngine(t, nil)
	deps.notifier.err = notify.ErrQueueFull
	denied, err := deps.engine.OnDeniedWrite(context.Background(), denialFixture(domain.DenyNoSession, domain.SeverityCritical))
	if err != nil {
		t.Fatalf("notifier failure must not fail the deny path: %v", err)
	}
	requireValidAlert(t, denied)
	if deps.audit.count() != 1 || deps.publisher.count() != 1 {
		t.Fatal("audit and publication must still happen")
	}
	if stats := deps.engine.Stats(); stats.NotifyFailed != 1 || stats.Notified != 0 {
		t.Fatalf("unexpected stats: %+v", stats)
	}
}

// blockingSender lets a real notify.Dispatcher fill up while the worker blocks.
type blockingSender struct {
	started chan struct{}
	release chan struct{}
	once    sync.Once
}

func (b *blockingSender) Notify(ctx context.Context, _ notify.Notification) error {
	b.once.Do(func() { close(b.started) })
	select {
	case <-b.release:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func waitFor(t *testing.T, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("condition not reached before deadline")
}

func TestDenyPathUnaffectedByFullNotifyQueue(t *testing.T) {
	t.Parallel()
	sender := &blockingSender{started: make(chan struct{}), release: make(chan struct{})}
	dispatcher, err := notify.NewDispatcher(sender, notify.DispatcherConfig{QueueSize: 1, Workers: 1})
	if err != nil {
		t.Fatalf("NewDispatcher: %v", err)
	}
	dispatcher.Start(context.Background())
	defer func() {
		close(sender.release)
		dispatcher.Stop()
	}()
	// Fill the queue: one notification is consumed by the blocked worker, one
	// fills the single slot.
	if err := dispatcher.Notify(context.Background(), notify.TestNotification(baseTime, testSite)); err != nil {
		t.Fatalf("prime dispatcher: %v", err)
	}
	<-sender.started
	if err := dispatcher.Notify(context.Background(), notify.TestNotification(baseTime, testSite)); err != nil {
		t.Fatalf("fill dispatcher: %v", err)
	}
	// A third notification is rejected, but the deny path stays healthy.
	deps := newTestEngine(t, func(opts *alert.Options) { opts.Notifier = dispatcher })
	denied, err := deps.engine.OnDeniedWrite(context.Background(), denialFixture(domain.DenyNoSession, domain.SeverityCritical))
	if err != nil {
		t.Fatalf("full notify queue must not block the deny path: %v", err)
	}
	requireValidAlert(t, denied)
	if deps.audit.count() != 1 || deps.publisher.count() != 1 {
		t.Fatal("audit and publication must happen although the queue is full")
	}
	if stats := deps.engine.Stats(); stats.NotifyFailed != 1 {
		t.Fatalf("expected one notify failure, got %+v", stats)
	}
}

func TestMinNotifyThreshold(t *testing.T) {
	t.Parallel()
	deps := newTestEngine(t, func(opts *alert.Options) { opts.MinNotify = domain.SeverityCritical })
	alerted, err := deps.engine.OnDeniedWrite(context.Background(), denialFixture(domain.DenyOutsideWindow, domain.SeverityInfo))
	if err != nil {
		t.Fatalf("OnDeniedWrite: %v", err)
	}
	if alerted.Severity != domain.SeverityHigh {
		t.Fatalf("expected high outside-window alert, got %s", alerted.Severity)
	}
	if deps.notifier.count() != 0 {
		t.Fatal("severity below MinNotify must not notify")
	}
}
