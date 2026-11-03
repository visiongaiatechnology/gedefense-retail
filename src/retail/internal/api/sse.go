package api

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/visiongaiatechnology/gedefense/retail/internal/ports"
)

// hubBufferSize is the per-client SSE buffer. A slow client loses the oldest
// events instead of blocking the pipeline; the loss is reported on the next
// health event.
const hubBufferSize = 64

// defaultMaxSubscribers bounds the number of concurrent SSE clients. Every stream
// costs one goroutine plus one buffer; an unbounded count would let a single
// viewer token exhaust file descriptors and starve the local alerting path.
const defaultMaxSubscribers = 8

// streamRetryAfterSeconds is the Retry-After value returned when the subscriber
// limit is reached.
const streamRetryAfterSeconds = 30

// Event is one server-sent event.
type Event struct {
	Kind string
	Data any
}

// subscriber is one connected SSE client.
type subscriber struct {
	id      int64
	events  chan Event
	dropped atomic.Int64
}

// Hub fans out live events to all connected SSE clients. The subscriber count is
// bounded (default 8) so a hostile or broken client cannot exhaust the gateway.
type Hub struct {
	mu        sync.Mutex
	subs      map[int64]*subscriber
	byChannel map[<-chan Event]int64
	nextID    int64
	maxSubs   int
}

// NewHub builds a live-event hub with the default subscriber limit.
func NewHub() *Hub { return NewHubWithLimit(defaultMaxSubscribers) }

// NewHubWithLimit builds a hub with an explicit subscriber limit. A limit below 1
// falls back to the default; the bound is never disabled.
func NewHubWithLimit(maxSubscribers int) *Hub {
	if maxSubscribers < 1 {
		maxSubscribers = defaultMaxSubscribers
	}
	return &Hub{
		subs:      make(map[int64]*subscriber),
		byChannel: make(map[<-chan Event]int64),
		maxSubs:   maxSubscribers,
	}
}

// MaxSubscribers returns the configured subscriber bound.
func (h *Hub) MaxSubscribers() int { return h.maxSubs }

// Publish delivers one event to every subscriber. A full subscriber buffer drops
// the event and increments that client's drop counter.
func (h *Hub) Publish(kind string, payload any) {
	if kind == "" {
		return
	}
	event := Event{Kind: kind, Data: payload}
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, sub := range h.subs {
		select {
		case sub.events <- event:
		default:
			sub.dropped.Add(1)
		}
	}
}

// Subscribe registers one client. The cancel function is idempotent and is also
// invoked automatically when ctx is done. When the hub is at its subscriber limit
// the returned channel is already closed; callers that must report the condition
// use TrySubscribe instead.
func (h *Hub) Subscribe(ctx context.Context) (<-chan Event, func()) {
	events, cancel, ok := h.TrySubscribe(ctx)
	if !ok {
		closed := make(chan Event)
		close(closed)
		return closed, func() {}
	}
	return events, cancel
}

// TrySubscribe registers one client unless the subscriber limit is reached.
func (h *Hub) TrySubscribe(ctx context.Context) (<-chan Event, func(), bool) {
	sub := &subscriber{events: make(chan Event, hubBufferSize)}

	h.mu.Lock()
	if len(h.subs) >= h.maxSubs {
		h.mu.Unlock()
		return nil, func() {}, false
	}
	sub.id = h.nextID
	h.nextID++
	h.subs[sub.id] = sub
	h.byChannel[sub.events] = sub.id
	h.mu.Unlock()

	done := make(chan struct{})
	var once sync.Once
	cancel := func() {
		once.Do(func() {
			close(done)
			h.mu.Lock()
			if _, ok := h.subs[sub.id]; ok {
				delete(h.subs, sub.id)
				delete(h.byChannel, sub.events)
				close(sub.events)
			}
			h.mu.Unlock()
		})
	}
	go func() {
		select {
		case <-ctx.Done():
			cancel()
		case <-done:
		}
	}()
	return sub.events, cancel, true
}

// Dropped returns and resets the number of dropped events of one subscription.
func (h *Hub) Dropped(ch <-chan Event) int64 {
	h.mu.Lock()
	defer h.mu.Unlock()
	id, ok := h.byChannel[ch]
	if !ok {
		return 0
	}
	sub, ok := h.subs[id]
	if !ok {
		return 0
	}
	return sub.dropped.Swap(0)
}

// Subscribers returns the number of connected streaming clients.
func (h *Hub) Subscribers() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.subs)
}

// sseHealth is the payload of the periodic health event.
type sseHealth struct {
	Collectors []ports.CollectorHealth `json:"collectors"`
	Dropped    int64                   `json:"dropped"`
}

// handleStream serves GET /api/v1/stream.
//
// Hardening: the hub bounds the number of concurrent streams, each write is
// armed with its own deadline so a non-reading client cannot pin a goroutine (and
// therefore cannot prevent the 30-minute lifetime limit), and a rejected stream is
// answered with 429 + Retry-After instead of being silently dropped.
func (s *Server) handleStream(w http.ResponseWriter, r *http.Request, _ params, _ identity) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		s.fail(w, r, http.StatusServiceUnavailable, "unavailable", "streaming is not supported by this connection")
		return
	}

	events, cancel, subscribed := s.hub.TrySubscribe(r.Context())
	if !subscribed {
		w.Header().Set("Retry-After", strconv.Itoa(streamRetryAfterSeconds))
		s.fail(w, r, http.StatusTooManyRequests, "rate_limited", "too many concurrent streams")
		return
	}
	defer cancel()

	// The stream outlives the server-wide write timeout; every individual write
	// then arms its own deadline so a blocked peer is detected.
	controller := http.NewResponseController(w)
	if err := controller.SetWriteDeadline(time.Time{}); err != nil {
		s.logger.Debug("stream write deadline cannot be cleared", "request_id", requestID(r), "error", err)
	}

	header := w.Header()
	header.Set("Content-Type", "text/event-stream; charset=utf-8")
	header.Set("Cache-Control", "no-store")
	header.Set("Connection", "keep-alive")
	header.Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	flusher.Flush()

	ctx := r.Context()
	heartbeat := time.NewTicker(s.stream.Heartbeat)
	defer heartbeat.Stop()
	health := time.NewTicker(s.stream.Health)
	defer health.Stop()
	lifetime := time.NewTimer(s.stream.MaxDuration)
	defer lifetime.Stop()

	// writeRaw arms the per-write deadline and writes one SSE frame. It returns
	// false when the client is gone or too slow; the stream then ends cleanly.
	writeRaw := func(payload string) bool {
		if err := controller.SetWriteDeadline(time.Now().Add(s.stream.WriteTimeout)); err != nil {
			s.logger.Debug("stream write deadline cannot be set", "request_id", requestID(r), "error", err)
		}
		if _, werr := io.WriteString(w, payload); werr != nil {
			s.logger.Debug("stream write failed", "request_id", requestID(r), "error", werr)
			return false
		}
		flusher.Flush()
		return true
	}
	writeEvent := func(kind string, payload any) bool {
		raw, err := json.Marshal(payload)
		if err != nil {
			s.logger.Warn("encode stream event failed", "request_id", requestID(r), "kind", kind, "error", err)
			return true // one malformed event must not kill the stream
		}
		return writeRaw(fmt.Sprintf("event: %s\ndata: %s\n\n", kind, raw))
	}

	healthPayload := func() sseHealth {
		return sseHealth{Collectors: s.collectorHealth(), Dropped: s.hub.Dropped(events)}
	}
	if !writeEvent("health", healthPayload()) {
		return
	}

	for {
		select {
		case <-ctx.Done():
			return
		case <-lifetime.C:
			// The contract closes the stream after its maximum lifetime; the client
			// reconnects with backoff.
			return
		case <-heartbeat.C:
			if !writeRaw(": ping\n\n") {
				return
			}
		case <-health.C:
			if !writeEvent("health", healthPayload()) {
				return
			}
		case event, open := <-events:
			if !open {
				return
			}
			if !writeEvent(event.Kind, event.Data) {
				return
			}
		}
	}
}
