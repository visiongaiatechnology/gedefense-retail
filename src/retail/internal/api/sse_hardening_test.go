package api

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestHubSubscriberLimit(t *testing.T) {
	hub := NewHubWithLimit(2)
	if got := hub.MaxSubscribers(); got != 2 {
		t.Fatalf("MaxSubscribers = %d, want 2", got)
	}
	ctx := context.Background()
	_, cancelA, okA := hub.TrySubscribe(ctx)
	_, cancelB, okB := hub.TrySubscribe(ctx)
	if !okA || !okB {
		t.Fatal("the first two subscriptions must succeed")
	}
	if _, _, ok := hub.TrySubscribe(ctx); ok {
		t.Fatal("a subscription beyond the limit must be rejected")
	}
	if got := hub.Subscribers(); got != 2 {
		t.Errorf("Subscribers = %d, want 2", got)
	}

	// A rejected Subscribe yields an already closed channel instead of a leak.
	closed, cancelC := hub.Subscribe(ctx)
	if _, open := <-closed; open {
		t.Error("Subscribe at capacity returned an open channel")
	}
	cancelC()

	cancelA()
	if _, cancelD, ok := hub.TrySubscribe(ctx); !ok {
		t.Fatal("capacity must be reusable after unsubscribe")
	} else {
		cancelD()
	}
	cancelB()

	if NewHub().MaxSubscribers() != defaultMaxSubscribers {
		t.Errorf("default limit = %d, want %d", NewHub().MaxSubscribers(), defaultMaxSubscribers)
	}
	if NewHubWithLimit(0).MaxSubscribers() != defaultMaxSubscribers {
		t.Error("a non-positive limit must fall back to the default")
	}
}

// streamResponse opens one SSE stream and returns the response.
func streamResponse(t *testing.T, server *httptest.Server, token string) *http.Response {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, server.URL+"/api/v1/stream", nil)
	if err != nil {
		t.Fatalf("new stream request: %v", err)
	}
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	response, err := server.Client().Do(request)
	if err != nil {
		t.Fatalf("open stream: %v", err)
	}
	return response
}

func TestStreamRejectsBeyondSubscriberLimit(t *testing.T) {
	h := newAPIHarness(t, apiTestOptions{hubLimit: 2})
	h.server.SetStreamTimings(StreamTimings{Heartbeat: time.Hour, Health: time.Hour, MaxDuration: time.Hour})
	server := httptest.NewServer(h.handler)
	defer server.Close()

	first := streamResponse(t, server, viewerToken)
	defer first.Body.Close()
	second := streamResponse(t, server, viewerToken)
	defer second.Body.Close()
	if first.StatusCode != http.StatusOK || second.StatusCode != http.StatusOK {
		t.Fatalf("stream status = %d, %d", first.StatusCode, second.StatusCode)
	}
	waitForCondition(t, 2*time.Second, func() bool { return h.server.Hub().Subscribers() == 2 })

	rejected := streamResponse(t, server, viewerToken)
	defer rejected.Body.Close()
	if rejected.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("third stream status = %d, want 429", rejected.StatusCode)
	}
	if retryAfter := rejected.Header.Get("Retry-After"); retryAfter == "" {
		t.Error("rejected stream without Retry-After header")
	}
	if h.server.Hub().Subscribers() != 2 {
		t.Errorf("Subscribers = %d, want 2", h.server.Hub().Subscribers())
	}

	// Closing one stream frees exactly one slot.
	if err := first.Body.Close(); err != nil {
		t.Fatalf("close stream: %v", err)
	}
	waitForCondition(t, 5*time.Second, func() bool { return h.server.Hub().Subscribers() == 1 })
	reopened := streamResponse(t, server, viewerToken)
	defer reopened.Body.Close()
	if reopened.StatusCode != http.StatusOK {
		t.Errorf("stream after a slot was freed = %d, want 200", reopened.StatusCode)
	}
}

// deadlineWriter is a blocking-writer double: it records whether a write deadline
// was armed before every write and fails writes with a timeout error afterwards.
type deadlineWriter struct {
	mu           sync.Mutex
	header       http.Header
	writes       int
	deadlineSet  bool
	failFromN    int
	writeWithout int
}

func newDeadlineWriter(failFromN int) *deadlineWriter {
	return &deadlineWriter{header: make(http.Header), failFromN: failFromN}
}

func (w *deadlineWriter) Header() http.Header { return w.header }

func (w *deadlineWriter) WriteHeader(int) {}

func (w *deadlineWriter) Flush() {}

func (w *deadlineWriter) SetWriteDeadline(deadline time.Time) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.deadlineSet = !deadline.IsZero()
	return nil
}

func (w *deadlineWriter) Write(payload []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.deadlineSet {
		w.writeWithout++
		return 0, errors.New("write attempted without a per-write deadline")
	}
	w.writes++
	if w.writes >= w.failFromN {
		return 0, os.ErrDeadlineExceeded
	}
	return len(payload), nil
}

func TestStreamArmsPerWriteDeadlineAndEndsOnTimeout(t *testing.T) {
	h := newAPIHarness(t, apiTestOptions{hubLimit: 2})
	h.server.SetStreamTimings(StreamTimings{
		Heartbeat:    10 * time.Millisecond,
		Health:       10 * time.Millisecond,
		MaxDuration:  time.Hour,
		WriteTimeout: 50 * time.Millisecond,
	})

	writer := newDeadlineWriter(2) // first frame (health) passes, the next write times out
	request := httptest.NewRequest(http.MethodGet, "/api/v1/stream", nil)
	request.RemoteAddr = defaultRemoteAddr
	request.Header.Set("Authorization", "Bearer "+viewerToken)

	done := make(chan struct{})
	go func() {
		defer close(done)
		h.handler.ServeHTTP(writer, request)
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("stream handler did not end after the write deadline fired")
	}
	waitForCondition(t, 3*time.Second, func() bool { return h.server.Hub().Subscribers() == 0 })
	if writer.writes < 2 {
		t.Errorf("writes = %d, want at least 2", writer.writes)
	}
	if writer.writeWithout != 0 {
		t.Errorf("%d writes happened without an armed deadline", writer.writeWithout)
	}
}

func TestBlockedStreamKeepsServerResponsive(t *testing.T) {
	h := newAPIHarness(t, apiTestOptions{hubLimit: 2})
	h.server.SetStreamTimings(StreamTimings{
		Heartbeat:    50 * time.Millisecond,
		Health:       50 * time.Millisecond,
		MaxDuration:  time.Hour,
		WriteTimeout: 50 * time.Millisecond,
	})
	server := httptest.NewServer(h.handler)
	defer server.Close()

	stream := streamResponse(t, server, viewerToken)
	defer stream.Body.Close()
	waitForCondition(t, 2*time.Second, func() bool { return h.server.Hub().Subscribers() == 1 })

	// A payload large enough to fill the socket buffers while the client does not
	// read: the handler's per-write deadline must reclaim it.
	blob := strings.Repeat("x", 256<<10)
	for i := 0; i < 128; i++ {
		h.server.Hub().Publish("event", map[string]string{"blob": blob})
	}

	// The rest of the API must stay responsive while the slow stream is being
	// reclaimed.
	start := time.Now()
	response, err := server.Client().Get(server.URL + "/api/v1/health")
	if err != nil {
		t.Fatalf("health during blocked stream: %v", err)
	}
	body := make([]byte, 4096)
	n, _ := response.Body.Read(body)
	if err := response.Body.Close(); err != nil {
		t.Errorf("close health body: %v", err)
	}
	if response.StatusCode != http.StatusOK || n == 0 {
		t.Errorf("health during blocked stream = %d", response.StatusCode)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Errorf("health took %v while a stream was blocked", elapsed)
	}

	// The blocked client is disconnected by the write deadline.
	waitForCondition(t, 15*time.Second, func() bool { return h.server.Hub().Subscribers() == 0 })
}

// waitForCondition polls until cond is true or the timeout expires.
func waitForCondition(t *testing.T, timeout time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("condition not met within %v", timeout)
}
