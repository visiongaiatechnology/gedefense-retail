package notify

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/visiongaiatechnology/gedefense/retail/internal/domain"
	"github.com/visiongaiatechnology/gedefense/retail/internal/ports"
)

// ErrCapacity is returned when the escalation tracker holds too many unacked
// notifications.
var ErrCapacity = errors.New("notify: escalation capacity exhausted")

// EscalationStep is one rung of the operator-approved escalation chain. Channel
// is empty for the default channel (webhook); "sms"/"call" require a registered
// provider and are never faked.
type EscalationStep struct {
	AfterMinutes int    `json:"after_minutes"`
	Role         string `json:"role"`
	Channel      string `json:"channel,omitempty"`
}

// EscalationConfig configures the ack-timer chain.
type EscalationConfig struct {
	Steps              []EscalationStep
	DefaultChannel     string
	Channels           map[string]Notifier
	MinSeverity        domain.Severity
	RepeatAfterMinutes int
	MaxPending         int
}

func (cfg EscalationConfig) normalize() (EscalationConfig, error) {
	steps := make([]EscalationStep, len(cfg.Steps))
	copy(steps, cfg.Steps)
	for i, step := range steps {
		if step.AfterMinutes < 0 {
			return EscalationConfig{}, fmt.Errorf("notify: escalation step %d has negative delay", i)
		}
		if step.Role == "" {
			return EscalationConfig{}, fmt.Errorf("notify: escalation step %d has no role", i)
		}
	}
	sort.SliceStable(steps, func(i, j int) bool { return steps[i].AfterMinutes < steps[j].AfterMinutes })
	if len(steps) > 10 {
		return EscalationConfig{}, fmt.Errorf("notify: too many escalation steps (%d, max 10)", len(steps))
	}
	if cfg.DefaultChannel == "" {
		cfg.DefaultChannel = "webhook"
	}
	if cfg.MinSeverity == "" {
		cfg.MinSeverity = domain.SeverityHigh
	}
	if !cfg.MinSeverity.Valid() {
		return EscalationConfig{}, fmt.Errorf("notify: invalid minimum severity %q", cfg.MinSeverity)
	}
	if cfg.RepeatAfterMinutes < 0 {
		return EscalationConfig{}, fmt.Errorf("notify: negative repeat interval")
	}
	if cfg.MaxPending == 0 {
		cfg.MaxPending = 1024
	}
	if cfg.MaxPending < 1 || cfg.MaxPending > 65536 {
		return EscalationConfig{}, fmt.Errorf("notify: max pending must be in [1, 65536]")
	}
	channels := make(map[string]Notifier, len(cfg.Channels))
	for name, notifier := range cfg.Channels {
		if name == "" || notifier == nil {
			return EscalationConfig{}, fmt.Errorf("notify: invalid channel registration %q", name)
		}
		channels[name] = notifier
	}
	cfg.Steps = steps
	cfg.Channels = channels
	return cfg, nil
}

// PendingState is the operator-visible state of one tracked notification.
type PendingState struct {
	NotificationID  string          `json:"notification_id"`
	DedupKey        string          `json:"dedup_key,omitempty"`
	Severity        domain.Severity `json:"severity"`
	Title           string          `json:"title"`
	TrackedAt       time.Time       `json:"tracked_at"`
	NextStep        int             `json:"next_step"`
	NextDueAt       time.Time       `json:"next_due_at,omitempty"`
	LastEscalatedAt time.Time       `json:"last_escalated_at,omitempty"`
	Escalations     int             `json:"escalations"`
	RepeatCount     int             `json:"repeat_count"`
	Acked           bool            `json:"acked"`
	AckedAt         time.Time       `json:"acked_at,omitempty"`
	AckedBy         string          `json:"acked_by,omitempty"`
}

// EscalationEvent is the audit record of one escalation attempt, including
// channels that are not configured (Delivered=false, Error set, no fake send).
type EscalationEvent struct {
	NotificationID string       `json:"notification_id"`
	DedupKey       string       `json:"dedup_key,omitempty"`
	Level          int          `json:"level"`
	Role           string       `json:"role"`
	Channel        string       `json:"channel"`
	At             time.Time    `json:"at"`
	Delivered      bool         `json:"delivered"`
	Error          string       `json:"error,omitempty"`
	RepeatCount    int          `json:"repeat_count,omitempty"`
	Notification   Notification `json:"notification"`
}

// AckRecord documents who acknowledged a tracked notification and when.
type AckRecord struct {
	NotificationID string    `json:"notification_id"`
	Actor          string    `json:"actor"`
	At             time.Time `json:"at"`
	Escalations    int       `json:"escalations"`
}

type trackedNotification struct {
	notification  Notification
	trackedAt     time.Time
	nextStep      int
	lastEscalated time.Time
	escalations   int
	repeatCount   int
	acked         bool
	ackedAt       time.Time
	ackedBy       string
}

// Escalator implements the 24/7 escalation chain. It is deterministic: time only
// advances through Tick(now), and Track/Ack use the injected clock. Notifications
// are handed to registered channels without blocking the Gate core (wire a
// Dispatcher as the webhook channel).
type Escalator struct {
	mu      sync.Mutex
	clock   ports.Clock
	cfg     EscalationConfig
	pending map[string]*trackedNotification
	order   []string
}

// NewEscalator validates the chain and creates the tracker.
func NewEscalator(clock ports.Clock, cfg EscalationConfig) (*Escalator, error) {
	if clock == nil {
		return nil, fmt.Errorf("notify: escalator requires a clock")
	}
	normalized, err := cfg.normalize()
	if err != nil {
		return nil, err
	}
	return &Escalator{
		clock:   clock,
		cfg:     normalized,
		pending: make(map[string]*trackedNotification, 16),
	}, nil
}

// Track starts the ack timer for a notification. It returns tracked=false for
// notifications below the configured minimum severity. Tracking is idempotent per
// notification ID (an unacked duplicate returns the existing id).
func (e *Escalator) Track(ctx context.Context, n Notification) (string, bool, error) {
	if e == nil {
		return "", false, fmt.Errorf("notify: nil escalator")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return "", false, err
	}
	if err := n.Validate(); err != nil {
		return "", false, err
	}
	if n.Severity.Rank() < e.cfg.MinSeverity.Rank() {
		return "", false, nil // below the escalation threshold: no ack timer
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if existing, ok := e.pending[n.ID]; ok {
		if !existing.acked {
			return n.ID, true, nil
		}
		// A previously acknowledged notification that fires again is a new
		// occurrence: replace the acknowledged record.
		delete(e.pending, n.ID)
		e.order = removeID(e.order, n.ID)
	}
	if len(e.pending) >= e.cfg.MaxPending {
		return "", false, ErrCapacity
	}
	now := e.clock.Now().UTC()
	if now.IsZero() {
		return "", false, fmt.Errorf("notify: clock returned zero time")
	}
	n.AckRequired = true
	n.EscalationLevel = 0
	n.EscalationRole = ""
	n.EscalationID = n.ID
	e.pending[n.ID] = &trackedNotification{notification: n, trackedAt: now}
	e.order = append(e.order, n.ID)
	return n.ID, true, nil
}

// Ack marks a tracked notification as acknowledged. It returns the record and
// whether the acknowledgement changed the state (a second ack returns false).
func (e *Escalator) Ack(notificationID, actor string, at time.Time) (AckRecord, bool) {
	if e == nil {
		return AckRecord{}, false
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	tracked, ok := e.pending[notificationID]
	if !ok || tracked.acked {
		return AckRecord{}, false
	}
	if at.IsZero() {
		at = e.clock.Now().UTC()
	}
	tracked.acked = true
	tracked.ackedAt = at.UTC()
	tracked.ackedBy = actor
	return AckRecord{
		NotificationID: notificationID,
		Actor:          actor,
		At:             tracked.ackedAt,
		Escalations:    tracked.escalations,
	}, true
}

// Tick advances the escalation chain to the given instant and returns the audit
// events of all delivery attempts. It is the only clock source for escalations,
// which makes "02:14 deny -> 02:19 on-call" fully reproducible in tests.
func (e *Escalator) Tick(now time.Time) []EscalationEvent {
	if e == nil {
		return nil
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if now.IsZero() {
		return nil
	}
	now = now.UTC()
	ctx := context.Background()
	events := make([]EscalationEvent, 0, 4)
	for _, id := range e.order {
		tracked, ok := e.pending[id]
		if !ok || tracked.acked {
			continue
		}
		// Chain steps.
		for tracked.nextStep < len(e.cfg.Steps) {
			step := e.cfg.Steps[tracked.nextStep]
			due := tracked.trackedAt.Add(time.Duration(step.AfterMinutes) * time.Minute)
			if now.Before(due) {
				break
			}
			events = append(events, e.fireLocked(ctx, tracked, step, tracked.nextStep+1, tracked.repeatCount, now))
			tracked.nextStep++
			tracked.escalations++
			tracked.lastEscalated = now
		}
		// Repetition of the final rung until acknowledgement.
		if e.cfg.RepeatAfterMinutes > 0 && len(e.cfg.Steps) > 0 && tracked.nextStep >= len(e.cfg.Steps) {
			step := e.cfg.Steps[len(e.cfg.Steps)-1]
			lastDue := tracked.trackedAt.Add(time.Duration(step.AfterMinutes) * time.Minute)
			repeat := time.Duration(e.cfg.RepeatAfterMinutes) * time.Minute
			// Bound the catch-up loop so a large clock jump cannot spin.
			for repeats := 0; repeats < 10; repeats++ {
				nextDue := lastDue.Add(repeat * time.Duration(tracked.repeatCount+1))
				if now.Before(nextDue) {
					break
				}
				events = append(events, e.fireLocked(ctx, tracked, step, len(e.cfg.Steps), tracked.repeatCount+1, now))
				tracked.repeatCount++
				tracked.escalations++
				tracked.lastEscalated = now
			}
		}
	}
	e.pruneLocked(now)
	return events
}

func (e *Escalator) fireLocked(ctx context.Context, tracked *trackedNotification, step EscalationStep, level, repeat int, now time.Time) EscalationEvent {
	channel := step.Channel
	if channel == "" {
		channel = e.cfg.DefaultChannel
	}
	notification := tracked.notification
	notification.EscalationLevel = level
	notification.EscalationRole = step.Role
	notification.EscalationID = tracked.notification.ID
	notification.AckRequired = true
	event := EscalationEvent{
		NotificationID: tracked.notification.ID,
		DedupKey:       tracked.notification.DedupKey,
		Level:          level,
		Role:           step.Role,
		Channel:        channel,
		At:             now,
		RepeatCount:    repeat,
		Notification:   notification,
	}
	notifier, ok := e.cfg.Channels[channel]
	if !ok {
		event.Error = fmt.Sprintf("%v: %q (role %q)", ErrNotConfigured, channel, step.Role)
		return event
	}
	if err := notifier.Notify(ctx, notification); err != nil {
		event.Error = err.Error()
		return event
	}
	event.Delivered = true
	return event
}

// Pending returns the tracked notifications in deterministic order.
func (e *Escalator) Pending() []PendingState {
	if e == nil {
		return nil
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make([]PendingState, 0, len(e.order))
	for _, id := range e.order {
		tracked, ok := e.pending[id]
		if !ok {
			continue
		}
		state := PendingState{
			NotificationID:  tracked.notification.ID,
			DedupKey:        tracked.notification.DedupKey,
			Severity:        tracked.notification.Severity,
			Title:           tracked.notification.Title,
			TrackedAt:       tracked.trackedAt,
			NextStep:        tracked.nextStep,
			LastEscalatedAt: tracked.lastEscalated,
			Escalations:     tracked.escalations,
			RepeatCount:     tracked.repeatCount,
			Acked:           tracked.acked,
			AckedAt:         tracked.ackedAt,
			AckedBy:         tracked.ackedBy,
		}
		state.NextDueAt = tracked.nextDue(e.cfg)
		out = append(out, state)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if !out[i].TrackedAt.Equal(out[j].TrackedAt) {
			return out[i].TrackedAt.Before(out[j].TrackedAt)
		}
		return out[i].NotificationID < out[j].NotificationID
	})
	return out
}

func (t *trackedNotification) nextDue(cfg EscalationConfig) time.Time {
	if t.nextStep < len(cfg.Steps) {
		return t.trackedAt.Add(time.Duration(cfg.Steps[t.nextStep].AfterMinutes) * time.Minute)
	}
	if cfg.RepeatAfterMinutes > 0 && len(cfg.Steps) > 0 {
		lastDue := t.trackedAt.Add(time.Duration(cfg.Steps[len(cfg.Steps)-1].AfterMinutes) * time.Minute)
		return lastDue.Add(time.Duration(cfg.RepeatAfterMinutes) * time.Minute * time.Duration(t.repeatCount+1))
	}
	return time.Time{}
}

// Stop releases all tracked state (shutdown path; no goroutines are owned).
func (e *Escalator) Stop() {
	if e == nil {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	e.pending = make(map[string]*trackedNotification, 16)
	e.order = nil
}

// pruneLocked drops acknowledged records after a retention period and bounds the
// order slice to the pending set.
func (e *Escalator) pruneLocked(now time.Time) {
	const ackRetention = 24 * time.Hour
	kept := e.order[:0]
	for _, id := range e.order {
		tracked, ok := e.pending[id]
		if !ok {
			continue
		}
		if tracked.acked && now.Sub(tracked.ackedAt) > ackRetention {
			delete(e.pending, id)
			continue
		}
		kept = append(kept, id)
	}
	e.order = kept
}

func removeID(ids []string, target string) []string {
	out := ids[:0]
	for _, id := range ids {
		if id == target {
			continue
		}
		out = append(out, id)
	}
	return out
}
