package api

import (
	"bufio"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestHubDeliversAndDrops(t *testing.T) {
	hub := NewHub()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	events, unsubscribe := hub.Subscribe(ctx)
	defer unsubscribe()

	hub.Publish("alert", map[string]string{"alert_id": "alr-1"})
	select {
	case event := <-events:
		if event.Kind != "alert" {
			t.Errorf("kind = %q", event.Kind)
		}
	case <-time.After(time.Second):
		t.Fatal("no event delivered")
	}

	// Fill the buffer and overflow it: the excess must be counted, not queued.
	for i := 0; i < hubBufferSize+10; i++ {
		hub.Publish("event", i)
	}
	dropped := hub.Dropped(events)
	if dropped != 10 {
		t.Errorf("dropped = %d, want 10", dropped)
	}
	if again := hub.Dropped(events); again != 0 {
		t.Errorf("dropped counter was not reset: %d", again)
	}
	if hub.Subscribers() != 1 {
		t.Errorf("subscribers = %d, want 1", hub.Subscribers())
	}

	unsubscribe()
	unsubscribe() // idempotent
	if hub.Subscribers() != 0 {
		t.Errorf("subscribers after unsubscribe = %d, want 0", hub.Subscribers())
	}
	// Publishing after every subscriber left must not panic.
	hub.Publish("alert", nil)
}

func TestHubUnsubscribesOnContextDone(t *testing.T) {
	hub := NewHub()
	ctx, cancel := context.WithCancel(context.Background())
	events, unsubscribe := hub.Subscribe(ctx)
	defer unsubscribe()
	cancel()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) && hub.Subscribers() != 0 {
		time.Sleep(5 * time.Millisecond)
	}
	if hub.Subscribers() != 0 {
		t.Errorf("subscriber not removed after context cancellation")
	}
	if _, open := <-events; open {
		t.Error("event channel still open after unsubscribe")
	}
}

func TestStreamRequiresAuth(t *testing.T) {
	h := newAPIHarness(t, apiTestOptions{})
	recorder := h.do(t, http.MethodGet, "/api/v1/stream", nil, "", nil)
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", recorder.Code)
	}
}

func TestStreamDeliversEvents(t *testing.T) {
	h := newAPIHarness(t, apiTestOptions{})
	h.server.SetStreamTimings(StreamTimings{
		Heartbeat:   10 * time.Millisecond,
		Health:      10 * time.Millisecond,
		MaxDuration: 5 * time.Second,
	})
	server := httptest.NewServer(h.handler)
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, server.URL+"/api/v1/stream", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	request.Header.Set("Authorization", "Bearer "+viewerToken)
	response, err := server.Client().Do(request)
	if err != nil {
		t.Fatalf("stream request: %v", err)
	}
	defer func() {
		if cerr := response.Body.Close(); cerr != nil {
			t.Errorf("close stream body: %v", cerr)
		}
	}()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", response.StatusCode)
	}
	if contentType := response.Header.Get("Content-Type"); !strings.HasPrefix(contentType, "text/event-stream") {
		t.Errorf("content type = %q", contentType)
	}

	reader := bufio.NewReader(response.Body)
	if !readUntil(reader, "event: health") {
		t.Fatal("no initial health event")
	}
	if !readUntil(reader, "data: {") {
		t.Fatal("health event without data")
	}

	h.server.Hub().Publish("alert", map[string]string{"alert_id": "alr-1"})
	if !readUntil(reader, "event: alert") {
		t.Fatal("no alert event delivered")
	}
	if !readUntil(reader, `"alert_id":"alr-1"`) {
		t.Fatal("alert payload missing")
	}
}

// readUntil reads lines until the marker appears or the stream dies.
func readUntil(reader *bufio.Reader, marker string) bool {
	for {
		line, err := reader.ReadString('\n')
		if strings.Contains(line, marker) {
			return true
		}
		if err != nil {
			return false
		}
	}
}
