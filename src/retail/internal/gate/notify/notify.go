// Package notify delivers GeDefense Retail Access Gate alerts to the outside
// world: an HMAC-signed webhook transport, a bounded asynchronous dispatcher and
// a tick-driven 24/7 escalation chain with acknowledgement tracking.
//
// Design constraints:
//
//   - The Gate core must never block on a notification. Delivery therefore runs
//     through a bounded queue (Dispatcher); a full queue returns an error instead
//     of applying backpressure to the deny path.
//   - Webhook payloads are signed with HMAC-SHA256 over the exact request body
//     and carry an X-GeDefense-Signature header (format "sha256=<hex>").
//   - Retries are bounded (max 5 attempts), use exponential backoff with jitter
//     and honour the caller's context.
//   - The escalation chain is deterministic: it is driven by an explicit Tick
//     with an injected clock, so "02:14 deny -> on-call at 02:19" is testable
//     without sleeping and without wall-clock dependency.
//   - SMS and voice are documented integration points (implement Notifier and
//     register the channel). The MVP ships only the webhook; it never pretends to
//     send an SMS or place a call.
package notify

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/visiongaiatechnology/gedefense/retail/internal/domain"
)

// Delivery errors returned by the notifier layer.
var (
	// ErrQueueFull is returned when the bounded delivery queue has no capacity.
	// Callers must treat it as "notification dropped, Gate continues".
	ErrQueueFull = errors.New("notify: delivery queue full")
	// ErrStopped is returned when the dispatcher has been stopped.
	ErrStopped = errors.New("notify: dispatcher stopped")
	// ErrNotConfigured is returned for escalation channels that have no
	// registered provider. It is never converted into a fake delivery.
	ErrNotConfigured = errors.New("notify: channel not configured")
)

// Notification is the transport payload handed to a channel. It is deliberately
// self-contained and secret-free: no tokens, hashes or passwords are included.
// Facts, hypothesis and recommended checks stay separated.
type Notification struct {
	ID                string          `json:"id"`
	Kind              string          `json:"kind"`
	At                time.Time       `json:"at"`
	Severity          domain.Severity `json:"severity"`
	Title             string          `json:"title"`
	Summary           string          `json:"summary"`
	DedupKey          string          `json:"dedup_key,omitempty"`
	SiteID            domain.SiteID   `json:"site_id,omitempty"`
	TargetID          domain.TargetID `json:"target_id,omitempty"`
	SourceIP          string          `json:"source_ip,omitempty"`
	Reason            string          `json:"reason,omitempty"`
	ObservedFacts     []string        `json:"observed_facts,omitempty"`
	Hypothesis        string          `json:"hypothesis,omitempty"`
	RecommendedChecks []string        `json:"recommended_checks,omitempty"`
	// EscalationLevel is 0 for the initial notification and >= 1 for a
	// chain escalation. EscalationRole names the responsible role.
	EscalationLevel int       `json:"escalation_level,omitempty"`
	EscalationRole  string    `json:"escalation_role,omitempty"`
	EscalationID    string    `json:"escalation_id,omitempty"`
	AckRequired     bool      `json:"ack_required"`
	Acked           bool      `json:"acked,omitempty"`
	AckedAt         time.Time `json:"acked_at,omitempty"`
	AckedBy         string    `json:"acked_by,omitempty"`
}

// Validate enforces the minimal payload contract before anything is delivered.
func (n Notification) Validate() error {
	if n.ID == "" {
		return fmt.Errorf("notification: id is required")
	}
	if n.Kind == "" {
		return fmt.Errorf("notification %q: kind is required", n.ID)
	}
	if n.At.IsZero() {
		return fmt.Errorf("notification %q: at is required", n.ID)
	}
	if !n.Severity.Valid() {
		return fmt.Errorf("notification %q: invalid severity %q", n.ID, n.Severity)
	}
	if n.Title == "" || n.Summary == "" {
		return fmt.Errorf("notification %q: title and summary are required", n.ID)
	}
	if n.EscalationLevel < 0 {
		return fmt.Errorf("notification %q: negative escalation level", n.ID)
	}
	return nil
}

// Notifier delivers one notification. Implementations must be safe for
// concurrent use, must respect the context deadline and must not block the Gate
// core indefinitely (use Dispatcher for the asynchronous path).
type Notifier interface {
	Notify(ctx context.Context, n Notification) error
}

// NotifierFunc adapts a function to Notifier (tests, wiring, custom channels).
type NotifierFunc func(ctx context.Context, n Notification) error

// Notify implements Notifier.
func (f NotifierFunc) Notify(ctx context.Context, n Notification) error { return f(ctx, n) }

// ChannelProvider is the documented integration point for SMS or voice
// providers. A provider is a Notifier that talks to the operator-approved
// provider API; the MVP does not ship an implementation and never fabricates a
// delivery ("no fake send"). Register a real provider in EscalationConfig.Channels
// to use it for an escalation step.
//
//	type smsProvider struct { client *providersms.Client }
//	func (p smsProvider) Notify(ctx context.Context, n notify.Notification) error { ... }
type ChannelProvider = Notifier

// TestNotification builds the payload used by the gate's "notify test" action.
func TestNotification(at time.Time, site domain.SiteID) Notification {
	if at.IsZero() {
		at = time.Unix(0, 0).UTC()
	}
	return Notification{
		ID:       "nft_test",
		Kind:     "gate.notify.test",
		At:       at.UTC(),
		Severity: domain.SeverityInfo,
		Title:    "GeDefense Access Gate — Notify-Test",
		Summary:  "Beobachtet: Testnachricht des Access Gate. Abgeleitet: Zustellung über den konfigurierten Kanal funktioniert. Empfohlene Prüfung: keine.",
		SiteID:   site,
	}
}
