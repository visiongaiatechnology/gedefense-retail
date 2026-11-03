package notify_test

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/visiongaiatechnology/gedefense/retail/internal/domain"
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

func (c *fakeClock) Set(t time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = t.UTC()
}

type channelRecorder struct {
	mu  sync.Mutex
	got []notify.Notification
	err error
}

func (c *channelRecorder) Notify(_ context.Context, n notify.Notification) error {
	if c.err != nil {
		return c.err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.got = append(c.got, n)
	return nil
}

func (c *channelRecorder) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.got)
}

func (c *channelRecorder) deliveries() []notify.Notification {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]notify.Notification(nil), c.got...)
}

func defaultSteps() []notify.EscalationStep {
	return []notify.EscalationStep{
		{AfterMinutes: 5, Role: "approver"},
		{AfterMinutes: 15, Role: "master_admin"},
		{AfterMinutes: 30, Role: "on_call"},
	}
}

func newTestEscalator(t *testing.T, clock *fakeClock, steps []notify.EscalationStep, mutate func(*notify.EscalationConfig)) (*notify.Escalator, *channelRecorder) {
	t.Helper()
	recorder := &channelRecorder{}
	cfg := notify.EscalationConfig{
		Steps:       steps,
		Channels:    map[string]notify.Notifier{"webhook": recorder},
		MinSeverity: domain.SeverityHigh,
	}
	if mutate != nil {
		mutate(&cfg)
	}
	escalator, err := notify.NewEscalator(clock, cfg)
	if err != nil {
		t.Fatalf("NewEscalator: %v", err)
	}
	return escalator, recorder
}

// TestEscalationNightScenario is the "02:14-Szenario" evidence: a critical deny
// at 02:14 wakes the escalation chain without any wall-clock dependency.
func TestEscalationNightScenario(t *testing.T) {
	t.Parallel()
	clock := &fakeClock{t: baseTime} // 2026-11-04 02:14:00 UTC
	escalator, recorder := newTestEscalator(t, clock, defaultSteps(), nil)

	notification := testNotification()
	notification.At = baseTime
	id, tracked, err := escalator.Track(context.Background(), notification)
	if err != nil {
		t.Fatalf("Track: %v", err)
	}
	if !tracked || id != notification.ID {
		t.Fatalf("unexpected track result: tracked=%t id=%q", tracked, id)
	}

	if events := escalator.Tick(baseTime); len(events) != 0 {
		t.Fatalf("no escalation before the first rung, got %+v", events)
	}

	first := escalator.Tick(baseTime.Add(5 * time.Minute)) // 02:19
	if len(first) != 1 {
		t.Fatalf("expected one escalation at 02:19, got %d", len(first))
	}
	if first[0].Level != 1 || first[0].Role != "approver" || first[0].Channel != "webhook" || !first[0].Delivered {
		t.Fatalf("unexpected first escalation: %+v", first[0])
	}
	if !first[0].At.Equal(baseTime.Add(5 * time.Minute)) {
		t.Fatalf("unexpected escalation time: %v", first[0].At)
	}
	if first[0].Notification.EscalationLevel != 1 || first[0].Notification.EscalationRole != "approver" {
		t.Fatalf("notification not annotated for escalation: %+v", first[0].Notification)
	}
	if recorder.count() != 1 {
		t.Fatalf("expected one delivered notification, got %d", recorder.count())
	}

	second := escalator.Tick(baseTime.Add(15 * time.Minute)) // 02:29
	if len(second) != 1 || second[0].Level != 2 || second[0].Role != "master_admin" {
		t.Fatalf("unexpected second escalation: %+v", second)
	}
	third := escalator.Tick(baseTime.Add(30 * time.Minute)) // 02:44
	if len(third) != 1 || third[0].Level != 3 || third[0].Role != "on_call" {
		t.Fatalf("unexpected third escalation: %+v", third)
	}
	if replay := escalator.Tick(baseTime.Add(30 * time.Minute)); len(replay) != 0 {
		t.Fatalf("escalation must not repeat on the same tick: %+v", replay)
	}
	if recorder.count() != 3 {
		t.Fatalf("expected three delivered escalations, got %d", recorder.count())
	}
	pending := escalator.Pending()
	if len(pending) != 1 || pending[0].Escalations != 3 || pending[0].Acked {
		t.Fatalf("unexpected pending state: %+v", pending)
	}
}

func TestEscalationAckStopsChain(t *testing.T) {
	t.Parallel()
	clock := &fakeClock{t: baseTime}
	escalator, recorder := newTestEscalator(t, clock, defaultSteps(), nil)
	notification := testNotification()
	if _, tracked, err := escalator.Track(context.Background(), notification); err != nil || !tracked {
		t.Fatalf("Track: tracked=%t err=%v", tracked, err)
	}
	if events := escalator.Tick(baseTime.Add(5 * time.Minute)); len(events) != 1 {
		t.Fatalf("expected first escalation, got %d", len(events))
	}
	ackAt := baseTime.Add(6 * time.Minute)
	record, ok := escalator.Ack(notification.ID, "operator-7", ackAt)
	if !ok {
		t.Fatal("expected acknowledgement to change state")
	}
	if record.Actor != "operator-7" || !record.At.Equal(ackAt) || record.Escalations != 1 {
		t.Fatalf("unexpected ack record: %+v", record)
	}
	if _, second := escalator.Ack(notification.ID, "operator-7", ackAt); second {
		t.Fatal("second acknowledgement must not change state")
	}
	if events := escalator.Tick(baseTime.Add(15 * time.Minute)); len(events) != 0 {
		t.Fatalf("acked notification must not escalate: %+v", events)
	}
	if events := escalator.Tick(baseTime.Add(30 * time.Minute)); len(events) != 0 {
		t.Fatalf("acked notification must not escalate later: %+v", events)
	}
	if recorder.count() != 1 {
		t.Fatalf("expected exactly one delivery before ack, got %d", recorder.count())
	}
	pending := escalator.Pending()
	if len(pending) != 1 || !pending[0].Acked || pending[0].AckedBy != "operator-7" || !pending[0].AckedAt.Equal(ackAt) {
		t.Fatalf("ack was not documented: %+v", pending)
	}
}

func TestEscalationMissingChannelIsNotFaked(t *testing.T) {
	t.Parallel()
	clock := &fakeClock{t: baseTime}
	escalator, recorder := newTestEscalator(t, clock, []notify.EscalationStep{{AfterMinutes: 5, Role: "on_call", Channel: "sms"}}, nil)
	notification := testNotification()
	if _, tracked, err := escalator.Track(context.Background(), notification); err != nil || !tracked {
		t.Fatalf("Track: tracked=%t err=%v", tracked, err)
	}
	events := escalator.Tick(baseTime.Add(5 * time.Minute))
	if len(events) != 1 {
		t.Fatalf("expected one escalation event, got %d", len(events))
	}
	if events[0].Delivered {
		t.Fatal("missing provider must not be reported as delivered")
	}
	if !strings.Contains(events[0].Error, "not configured") {
		t.Fatalf("expected 'not configured' error, got %q", events[0].Error)
	}
	if recorder.count() != 0 {
		t.Fatalf("no webhook delivery expected, got %d", recorder.count())
	}
}

func TestEscalationBelowMinimumSeverityIsIgnored(t *testing.T) {
	t.Parallel()
	clock := &fakeClock{t: baseTime}
	escalator, _ := newTestEscalator(t, clock, defaultSteps(), nil)
	notification := testNotification()
	notification.Severity = domain.SeverityMedium
	_, tracked, err := escalator.Track(context.Background(), notification)
	if err != nil {
		t.Fatalf("Track: %v", err)
	}
	if tracked {
		t.Fatal("medium severity must not start the high/critical escalation chain")
	}
	if events := escalator.Tick(baseTime.Add(30 * time.Minute)); len(events) != 0 {
		t.Fatalf("untracked notification escalated: %+v", events)
	}
}

func TestEscalationTrackIsIdempotent(t *testing.T) {
	t.Parallel()
	clock := &fakeClock{t: baseTime}
	escalator, _ := newTestEscalator(t, clock, defaultSteps(), nil)
	notification := testNotification()
	firstID, _, err := escalator.Track(context.Background(), notification)
	if err != nil {
		t.Fatalf("first Track: %v", err)
	}
	secondID, tracked, err := escalator.Track(context.Background(), notification)
	if err != nil || !tracked || secondID != firstID {
		t.Fatalf("idempotent Track failed: id=%q tracked=%t err=%v", secondID, tracked, err)
	}
	if len(escalator.Pending()) != 1 {
		t.Fatalf("duplicate tracking created %d pending entries", len(escalator.Pending()))
	}
	if events := escalator.Tick(baseTime.Add(5 * time.Minute)); len(events) != 1 {
		t.Fatalf("expected a single escalation, got %d", len(events))
	}
}

func TestEscalationRepeatsUntilAck(t *testing.T) {
	t.Parallel()
	clock := &fakeClock{t: baseTime}
	escalator, recorder := newTestEscalator(t, clock, []notify.EscalationStep{{AfterMinutes: 5, Role: "approver"}}, func(cfg *notify.EscalationConfig) {
		cfg.RepeatAfterMinutes = 30
	})
	notification := testNotification()
	if _, _, err := escalator.Track(context.Background(), notification); err != nil {
		t.Fatalf("Track: %v", err)
	}
	if events := escalator.Tick(baseTime.Add(5 * time.Minute)); len(events) != 1 || events[0].Level != 1 {
		t.Fatalf("expected first rung at 02:19, got %+v", events)
	}
	repeat1 := escalator.Tick(baseTime.Add(35 * time.Minute)) // 02:49 = 02:19 + 30
	if len(repeat1) != 1 || repeat1[0].RepeatCount != 1 {
		t.Fatalf("expected first repeat at 02:49, got %+v", repeat1)
	}
	repeat2 := escalator.Tick(baseTime.Add(65 * time.Minute)) // 03:19 = 02:19 + 60
	if len(repeat2) != 1 || repeat2[0].RepeatCount != 2 {
		t.Fatalf("expected second repeat at 03:19, got %+v", repeat2)
	}
	escalator.Ack(notification.ID, "operator-7", baseTime.Add(66*time.Minute))
	if events := escalator.Tick(baseTime.Add(95 * time.Minute)); len(events) != 0 {
		t.Fatalf("acked notification repeated after ack: %+v", events)
	}
	if recorder.count() != 3 {
		t.Fatalf("expected three deliveries, got %d", recorder.count())
	}
}

func TestEscalationCapacity(t *testing.T) {
	t.Parallel()
	clock := &fakeClock{t: baseTime}
	escalator, _ := newTestEscalator(t, clock, defaultSteps(), func(cfg *notify.EscalationConfig) {
		cfg.MaxPending = 1
	})
	first := testNotification()
	if _, tracked, err := escalator.Track(context.Background(), first); err != nil || !tracked {
		t.Fatalf("first Track: tracked=%t err=%v", tracked, err)
	}
	second := testNotification()
	second.ID = "gal_second"
	if _, _, err := escalator.Track(context.Background(), second); !errors.Is(err, notify.ErrCapacity) {
		t.Fatalf("expected ErrCapacity, got %v", err)
	}
}

func TestEscalationPendingNextDue(t *testing.T) {
	t.Parallel()
	clock := &fakeClock{t: baseTime}
	escalator, _ := newTestEscalator(t, clock, defaultSteps(), nil)
	if _, _, err := escalator.Track(context.Background(), testNotification()); err != nil {
		t.Fatalf("Track: %v", err)
	}
	pending := escalator.Pending()
	if len(pending) != 1 {
		t.Fatalf("expected one pending entry, got %d", len(pending))
	}
	if !pending[0].NextDueAt.Equal(baseTime.Add(5 * time.Minute)) {
		t.Fatalf("unexpected next due: %v", pending[0].NextDueAt)
	}
	escalator.Tick(baseTime.Add(5 * time.Minute))
	pending = escalator.Pending()
	if len(pending) != 1 || !pending[0].NextDueAt.Equal(baseTime.Add(15*time.Minute)) {
		t.Fatalf("unexpected next due after first rung: %+v", pending)
	}
}

func TestEscalationValidation(t *testing.T) {
	t.Parallel()
	clock := &fakeClock{t: baseTime}
	cases := []struct {
		name string
		cfg  notify.EscalationConfig
	}{
		{name: "negative delay", cfg: notify.EscalationConfig{Steps: []notify.EscalationStep{{AfterMinutes: -1, Role: "approver"}}}},
		{name: "missing role", cfg: notify.EscalationConfig{Steps: []notify.EscalationStep{{AfterMinutes: 5}}}},
		{name: "invalid minimum severity", cfg: notify.EscalationConfig{MinSeverity: "bogus"}},
		{name: "negative repeat", cfg: notify.EscalationConfig{RepeatAfterMinutes: -5}},
		{name: "max pending too large", cfg: notify.EscalationConfig{MaxPending: 100000}},
		{name: "invalid channel", cfg: notify.EscalationConfig{Channels: map[string]notify.Notifier{"": nil}}},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if _, err := notify.NewEscalator(clock, tc.cfg); err == nil {
				t.Fatalf("expected validation error for %s", tc.name)
			}
		})
	}
	if _, err := notify.NewEscalator(nil, notify.EscalationConfig{Steps: defaultSteps()}); err == nil {
		t.Fatal("expected clock requirement")
	}
	escalator, _ := newTestEscalator(t, clock, defaultSteps(), nil)
	if _, _, err := escalator.Track(context.Background(), notify.Notification{ID: "gal_bad"}); err == nil {
		t.Fatal("expected notification validation error")
	}
	// Zero clock must be rejected instead of starting a timer at year 1.
	zeroClock := &fakeClock{}
	zeroEscalator, err := notify.NewEscalator(zeroClock, notify.EscalationConfig{Steps: defaultSteps()})
	if err != nil {
		t.Fatalf("NewEscalator: %v", err)
	}
	if _, _, err := zeroEscalator.Track(context.Background(), testNotification()); err == nil {
		t.Fatal("expected zero-clock error")
	}
}

func TestEscalationNilSafetyAndStop(t *testing.T) {
	t.Parallel()
	var nilEscalator *notify.Escalator
	if events := nilEscalator.Tick(baseTime); events != nil {
		t.Fatal("nil escalator Tick must be safe")
	}
	if pending := nilEscalator.Pending(); pending != nil {
		t.Fatal("nil escalator Pending must be safe")
	}
	if _, ok := nilEscalator.Ack("x", "y", baseTime); ok {
		t.Fatal("nil escalator Ack must report no state change")
	}
	nilEscalator.Stop()

	clock := &fakeClock{t: baseTime}
	escalator, _ := newTestEscalator(t, clock, defaultSteps(), nil)
	if _, _, err := escalator.Track(context.Background(), testNotification()); err != nil {
		t.Fatalf("Track: %v", err)
	}
	escalator.Stop()
	if pending := escalator.Pending(); len(pending) != 0 {
		t.Fatalf("Stop must release tracked state, got %d", len(pending))
	}
	if _, ok := escalator.Ack("gal_test_1", "operator", baseTime); ok {
		t.Fatal("ack after Stop must report no state change")
	}
}
