package api

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// trackingBody counts reads and exposes the unread remainder.
type trackingBody struct {
	data  *bytes.Reader
	reads int
}

func newTrackingBody(content string) *trackingBody {
	return &trackingBody{data: bytes.NewReader([]byte(content))}
}

func (b *trackingBody) Read(payload []byte) (int, error) {
	b.reads++
	return b.data.Read(payload)
}

func (b *trackingBody) Close() error { return nil }

func (b *trackingBody) remaining() int { return b.data.Len() }

func newDrainRequest(body io.ReadCloser, contentLength int64) *http.Request {
	request := httptest.NewRequest(http.MethodPost, "/api/v1/scan", nil)
	request.Body = body
	request.ContentLength = contentLength
	return request
}

func TestDrainRequestBodyConsumesSmallBody(t *testing.T) {
	recorder := httptest.NewRecorder()
	body := newTrackingBody("{}")
	request := newDrainRequest(body, 2)
	drainRequestBody(recorder, request)
	if body.remaining() != 0 {
		t.Errorf("remaining bytes after drain = %d, want 0", body.remaining())
	}
	if got := recorder.Header().Get("Connection"); got != "" {
		t.Errorf("Connection = %q, want empty for a drained body", got)
	}
}

func TestDrainRequestBodyBoundsLargeBody(t *testing.T) {
	recorder := httptest.NewRecorder()
	body := newTrackingBody(strings.Repeat("x", maxErrorBodyDrain+1))
	request := newDrainRequest(body, int64(maxErrorBodyDrain+1))
	drainRequestBody(recorder, request)
	if body.reads != 0 || body.remaining() != maxErrorBodyDrain+1 {
		t.Errorf("large body was read (reads=%d, remaining=%d)", body.reads, body.remaining())
	}
	if got := recorder.Header().Get("Connection"); got != "close" {
		t.Errorf("Connection = %q, want close for an oversized body", got)
	}
}

func TestDrainRequestBodyHandlesUnknownLength(t *testing.T) {
	recorder := httptest.NewRecorder()
	body := newTrackingBody("chunked")
	request := newDrainRequest(body, -1)
	drainRequestBody(recorder, request)
	if body.reads != 0 {
		t.Errorf("chunked body was read (%d reads)", body.reads)
	}
	if got := recorder.Header().Get("Connection"); got != "close" {
		t.Errorf("Connection = %q, want close for an unknown-length body", got)
	}
}

func TestDrainRequestBodyHandlesAbortedBody(t *testing.T) {
	recorder := httptest.NewRecorder()
	body := newTrackingBody("ab")
	request := newDrainRequest(body, 10) // declared more than the sender delivered
	drainRequestBody(recorder, request)
	if got := recorder.Header().Get("Connection"); got != "close" {
		t.Errorf("Connection = %q, want close after an aborted body", got)
	}
}

func TestDrainRequestBodyNilAndEmpty(t *testing.T) {
	recorder := httptest.NewRecorder()
	drainRequestBody(recorder, &http.Request{}) // nil body must not panic
	empty := newDrainRequest(newTrackingBody(""), 0)
	drainRequestBody(recorder, empty)
	if got := recorder.Header().Get("Connection"); got != "" {
		t.Errorf("Connection = %q, want empty for no body", got)
	}
}

func TestErrorPathsAnswerCleanlyWithBody(t *testing.T) {
	type scenario struct {
		name       string
		path       string
		token      string
		wantStatus int
	}
	scenarios := []scenario{
		{"unknown route", "/api/v1/scan", adminToken, http.StatusNotFound},
		{"unknown route 2", "/api/v1/control", adminToken, http.StatusNotFound},
		{"method not allowed", "/api/v1/sites", adminToken, http.StatusMethodNotAllowed},
		{"unauthenticated", "/api/v1/alerts/alr-1/ack", "", http.StatusUnauthorized},
		{"forbidden", "/api/v1/alerts/alr-1/ack", viewerToken, http.StatusForbidden},
	}
	for _, tc := range scenarios {
		t.Run(tc.name, func(t *testing.T) {
			// A fresh harness per scenario keeps the per-token/per-IP rate
			// limiter out of this transport regression test.
			h := newAPIHarness(t, apiTestOptions{})
			server := httptest.NewServer(h.handler)
			defer server.Close()
			client := server.Client()
			for attempt := 0; attempt < 10; attempt++ {
				request, err := http.NewRequestWithContext(context.Background(), http.MethodPost, server.URL+tc.path, strings.NewReader("{}"))
				if err != nil {
					t.Fatalf("new request: %v", err)
				}
				request.Header.Set("Content-Type", "application/json")
				if tc.token != "" {
					request.Header.Set("Authorization", "Bearer "+tc.token)
				}
				response, err := client.Do(request)
				if err != nil {
					t.Fatalf("attempt %d: error response was not delivered cleanly (reset?): %v", attempt, err)
				}
				payload, readErr := io.ReadAll(response.Body)
				if closeErr := response.Body.Close(); closeErr != nil {
					t.Errorf("attempt %d: close body: %v", attempt, closeErr)
				}
				if readErr != nil {
					t.Fatalf("attempt %d: read body: %v", attempt, readErr)
				}
				if response.StatusCode != tc.wantStatus {
					t.Fatalf("attempt %d: status = %d, want %d", attempt, response.StatusCode, tc.wantStatus)
				}
				if !strings.Contains(string(payload), `"error"`) {
					t.Errorf("attempt %d: body = %q, want error envelope", attempt, payload)
				}
				if response.Close {
					t.Errorf("attempt %d: connection was marked non-reusable for a drained body", attempt)
				}

				// The connection (and therefore the server) stays healthy.
				health, err := client.Get(server.URL + "/api/v1/health")
				if err != nil {
					t.Fatalf("attempt %d: follow-up health request failed: %v", attempt, err)
				}
				if _, readErr := io.ReadAll(health.Body); readErr != nil {
					t.Errorf("attempt %d: read health: %v", attempt, readErr)
				}
				if closeErr := health.Body.Close(); closeErr != nil {
					t.Errorf("attempt %d: close health: %v", attempt, closeErr)
				}
				if health.StatusCode != http.StatusOK {
					t.Fatalf("attempt %d: health = %d", attempt, health.StatusCode)
				}
			}
		})
	}
}
