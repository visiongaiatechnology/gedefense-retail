// Reconnect backoff shared by the read-only adapters.
package collect

import (
	"math/rand/v2"
	"time"
)

// Default backoff parameters used by the polling/stream adapters.
const (
	DefaultBackoffBase = 500 * time.Millisecond
	DefaultBackoffMax  = 30 * time.Second
)

// Backoff produces exponential, jittered reconnect delays. It is intentionally
// not safe for concurrent use: every adapter owns exactly one backoff in the
// goroutine that reconnects.
type Backoff struct {
	base time.Duration
	max  time.Duration
	cur  time.Duration
}

// NewBackoff creates a backoff with the given base and cap. Non-positive
// values fall back to the defaults.
func NewBackoff(base, max time.Duration) *Backoff {
	if base <= 0 {
		base = DefaultBackoffBase
	}
	if max < base {
		max = DefaultBackoffMax
	}
	if max < base {
		max = base
	}
	return &Backoff{base: base, max: max, cur: base}
}

// Next returns the next delay: exponential growth capped at max plus up to 25%
// jitter. Jitter matters because many adapters reconnect at the same time after
// a gateway restart and must not synchronize their retries.
func (b *Backoff) Next() time.Duration {
	delay := b.cur
	b.cur *= 2
	if b.cur > b.max {
		b.cur = b.max
	}
	jitter := time.Duration(rand.Float64() * 0.25 * float64(delay))
	return delay + jitter
}

// Reset returns the backoff to its base delay after a successful connection.
func (b *Backoff) Reset() { b.cur = b.base }

// Base returns the configured base delay.
func (b *Backoff) Base() time.Duration { return b.base }
