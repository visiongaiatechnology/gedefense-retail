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

	"github.com/visiongaiatechnology/gedefense/retail/internal/domain"
)

// SSE bounds: bounded subscriber count, bounded per-client buffer, per-write
// deadlines so a non-reading client cannot pin a goroutine.
const (
	hubBufferSize    = 64
	maxSubscribers   = 8
	streamRetryAfter = 30
)

// Event is one server-sent event.
type Event struct {
	Kind domain.GateEventKind
	Data any
}

// StreamTimings bounds one SSE connection.
type StreamTimings struct {
	Heartbeat    time.Duration
	Health       time.Duration
	MaxDuration  time.Duration
	WriteTimeout time.Duration
}

func defaultStreamTimings() StreamTimings {
	return StreamTimings{
		Heartbeat:    15 * time.Second,
		Health:       30 * time.Second,
		MaxDuration:  30 * time.Minute,
		WriteTimeout: 10 * time.Second,
	}
}

// subscriber is one connected SSE client.
type subscriber struct {
	id      int64
	events  chan Event
	dropped atomic.Int64
}

// Hub fans gate events out to connected dashboard clients.
type Hub struct {
	mu        sync.Mutex
	subs      map[int64]*subscriber
	byChannel map[<-chan Event]int64
	nextID    int64
	maxSubs   int
}

// NewHub builds a hub with the default subscriber limit.
func NewHub() *Hub { return NewHubWithLimit(maxSubscribers) }

// NewHubWithLimit builds a hub with an explicit subscriber limit (>=1).
func NewHubWithLimit(limit int) *Hub {
	if limit < 1 {
		limit = maxSubscribers
	}
	return &Hub{
		subs:      make(map[int64]*subscriber),
		byChannel: make(map[<-chan Event]int64),
		maxSubs:   limit,
	}
}

// MaxSubscribers returns the subscriber bound.
func (h *Hub) MaxSubscribers() int { return h.maxSubs }

// Publish delivers one event to every subscriber (drop counter on overflow).
func (h *Hub) Publish(kind domain.GateEventKind, payload any) {
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

// Subscribe registers one client; at capacity a closed channel is returned.
func (h *Hub) Subscribe(ctx context.Context) (<-chan Event, func()) {
	events, cancel, ok := h.TrySubscribe(ctx)
	if !ok {
		closed := make(chan Event)
		close(closed)
		return closed, func() {}
	}
	return events, cancel
}

// TrySubscribe registers one client unless the hub is full.
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

// Dropped returns and resets the drop counter of one subscription.
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

// Subscribers returns the number of connected clients.
func (h *Hub) Subscribers() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.subs)
}

// streamPing is the periodic state event (kind "failsafe", contract kind set).
type streamPing struct {
	Active  bool   `json:"active"`
	Reason  string `json:"reason"`
	Dropped int64  `json:"dropped"`
	Streams int    `json:"streams"`
	AuditOK bool   `json:"audit_chain_ok"`
}

// handleStream serves GET /api/v1/gate/stream.
func (s *Server) handleStream(w http.ResponseWriter, r *http.Request, _ params, _ apiSession) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		s.fail(w, r, http.StatusServiceUnavailable, "unavailable", "streaming is not supported")
		return
	}
	events, cancel, subscribed := s.hub.TrySubscribe(r.Context())
	if !subscribed {
		w.Header().Set("Retry-After", strconv.Itoa(streamRetryAfter))
		s.fail(w, r, http.StatusTooManyRequests, "rate_limited", "too many concurrent streams")
		return
	}
	defer cancel()

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

	writeRaw := func(payload string) bool {
		if err := controller.SetWriteDeadline(time.Now().Add(s.stream.WriteTimeout)); err != nil {
			s.logger.Debug("stream write deadline cannot be set", "request_id", requestID(r), "error", err)
		}
		if _, werr := io.WriteString(w, payload); werr != nil {
			return false
		}
		flusher.Flush()
		return true
	}
	writeEvent := func(kind domain.GateEventKind, payload any) bool {
		raw, err := json.Marshal(payload)
		if err != nil {
			s.logger.Warn("encode gate stream event failed", "kind", string(kind), "error", err)
			return true
		}
		return writeRaw(fmt.Sprintf("event: %s\ndata: %s\n\n", kind, raw))
	}
	pingPayload := func() streamPing {
		active, reason := s.failsafeState()
		return streamPing{
			Active: active, Reason: reason,
			Dropped: s.hub.Dropped(events), Streams: s.hub.Subscribers(),
			AuditOK: s.audit.chainOK(r.Context()),
		}
	}
	if !writeEvent(domain.GateEventFailsafe, pingPayload()) {
		return
	}

	ctx := r.Context()
	heartbeat := time.NewTicker(s.stream.Heartbeat)
	defer heartbeat.Stop()
	health := time.NewTicker(s.stream.Health)
	defer health.Stop()
	lifetime := time.NewTimer(s.stream.MaxDuration)
	defer lifetime.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-lifetime.C:
			return
		case <-heartbeat.C:
			if !writeRaw(": ping\n\n") {
				return
			}
		case <-health.C:
			// Reuse the documented "failsafe" kind for the periodic gate state.
			if !writeEvent(domain.GateEventFailsafe, pingPayload()) {
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
