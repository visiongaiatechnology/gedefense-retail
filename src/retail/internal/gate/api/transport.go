package api

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Security headers of every response.
const contentSecurityPolicy = "default-src 'self'; img-src 'self' data:; " +
	"style-src 'self'; script-src 'self'; connect-src 'self'; " +
	"frame-ancestors 'none'; base-uri 'none'; form-action 'self'"

// maxErrorBodyDrain bounds the drained remainder of an early error response.
const maxErrorBodyDrain = 64 << 10

var requestIDPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{8,64}$`)

type contextKey int

const ctxKeyRequestID contextKey = iota

// statusRecorder records the written status and whether a response started.
type statusRecorder struct {
	http.ResponseWriter
	status int
	wrote  bool
}

func (s *statusRecorder) WriteHeader(code int) {
	if s.wrote {
		return
	}
	s.status = code
	s.wrote = true
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusRecorder) Write(payload []byte) (int, error) {
	if !s.wrote {
		s.WriteHeader(http.StatusOK)
	}
	return s.ResponseWriter.Write(payload)
}

func (s *statusRecorder) Flush() {
	if flusher, ok := s.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}

func (s *statusRecorder) Unwrap() http.ResponseWriter { return s.ResponseWriter }

// captureWriter tees the response body for the idempotency cache.
type captureWriter struct {
	*statusRecorder
	body *bytes.Buffer
}

func (c *captureWriter) Write(payload []byte) (int, error) {
	if c.body != nil && c.body.Len() < maxBodyBytes*2 {
		c.body.Write(payload)
	}
	return c.statusRecorder.Write(payload)
}

// buildHandler composes recovery, base headers and dispatch.
func (s *Server) buildHandler() http.Handler {
	return s.recoverMW(s.baseMW(http.HandlerFunc(s.serve)))
}

// recoverMW is the single panic boundary of the API.
func (s *Server) recoverMW(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		recorder, ok := w.(*statusRecorder)
		if !ok {
			recorder = &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		}
		defer func() {
			if recovered := recover(); recovered != nil {
				s.logger.Error("panic while serving gate request",
					"request_id", requestID(r), "method", r.Method, "path", r.URL.Path,
					"panic", fmt.Sprint(recovered))
				if !recorder.wrote {
					s.fail(recorder, r, http.StatusInternalServerError, "internal", "internal server error")
				}
			}
		}()
		next.ServeHTTP(recorder, r)
	})
}

// baseMW assigns the request id and the security headers.
func (s *Server) baseMW(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := requestIDFromRequest(r)
		header := w.Header()
		header.Set("X-Request-Id", id)
		header.Set("X-Content-Type-Options", "nosniff")
		header.Set("X-Frame-Options", "DENY")
		header.Set("Referrer-Policy", "no-referrer")
		header.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		header.Set("Content-Security-Policy", contentSecurityPolicy)
		if r.TLS != nil {
			header.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}
		header.Set("Cache-Control", "no-store")
		ctx := context.WithValue(r.Context(), ctxKeyRequestID, id)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// requestIDFromRequest honours a well-formed inbound request id.
func requestIDFromRequest(r *http.Request) string {
	if candidate := r.Header.Get("X-Request-Id"); requestIDPattern.MatchString(candidate) {
		return candidate
	}
	return newRequestID()
}

// newRequestID creates an unpredictable request id.
func newRequestID() string {
	raw := make([]byte, 12)
	if _, err := rand.Read(raw); err != nil {
		return fmt.Sprintf("%x", time.Now().UTC().UnixNano())
	}
	return hex.EncodeToString(raw)
}

// requestID returns the request id from the context.
func requestID(r *http.Request) string {
	if id, ok := r.Context().Value(ctxKeyRequestID).(string); ok {
		return id
	}
	return ""
}

// errorBody is the contract error object.
type errorBody struct {
	Code      string `json:"code"`
	Message   string `json:"message"`
	RequestID string `json:"request_id"`
}

type errorEnvelope struct {
	Error errorBody `json:"error"`
}

// listEnvelope is the paginated list response.
type listEnvelope[T any] struct {
	Items  []T `json:"items"`
	Total  int `json:"total"`
	Limit  int `json:"limit,omitempty"`
	Offset int `json:"offset,omitempty"`
}

// respondJSON writes a JSON response.
func (s *Server) respondJSON(w http.ResponseWriter, r *http.Request, status int, payload any) {
	raw, err := json.Marshal(payload)
	if err != nil {
		s.logger.Error("encode gate response failed", "request_id", requestID(r), "error", err)
		s.fail(w, r, http.StatusInternalServerError, "internal", "internal server error")
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	if _, werr := w.Write(raw); werr != nil {
		s.logger.Warn("write gate response failed", "request_id", requestID(r), "error", werr)
	}
}

// respondNoContent writes an empty 204 response.
func (s *Server) respondNoContent(w http.ResponseWriter) {
	w.WriteHeader(http.StatusNoContent)
}

// fail drains a bounded body remainder and writes the error envelope.
func (s *Server) fail(w http.ResponseWriter, r *http.Request, status int, code, message string) {
	drainRequestBody(w, r)
	env := errorEnvelope{Error: errorBody{Code: code, Message: message, RequestID: requestID(r)}}
	raw, err := json.Marshal(env)
	if err != nil {
		http.Error(w, `{"error":{"code":"internal","message":"internal server error"}}`, http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	if _, werr := w.Write(raw); werr != nil {
		s.logger.Warn("write gate error response failed", "request_id", requestID(r), "error", werr)
	}
}

// drainRequestBody discards a small unread body so error responses are framed
// cleanly (no TCP reset from unread inbound data).
func drainRequestBody(w http.ResponseWriter, r *http.Request) {
	body := r.Body
	if body == nil || body == http.NoBody {
		return
	}
	switch {
	case r.ContentLength < 0:
		w.Header().Set("Connection", "close")
		return
	case r.ContentLength == 0:
		return
	case r.ContentLength > maxErrorBodyDrain:
		w.Header().Set("Connection", "close")
		return
	}
	copied, err := io.CopyN(io.Discard, body, r.ContentLength)
	if err != nil && copied > 0 {
		w.Header().Set("Connection", "close")
	}
}

// decodeJSON strictly decodes one JSON object (unknown fields rejected).
func (s *Server) decodeJSON(w http.ResponseWriter, r *http.Request, dst any) bool {
	if r.Body == nil {
		s.fail(w, r, http.StatusBadRequest, "invalid_request", "request body is required")
		return false
	}
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBodyBytes))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(dst); err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			s.fail(w, r, http.StatusBadRequest, "invalid_request", "request body exceeds 128 KiB")
			return false
		}
		s.fail(w, r, http.StatusBadRequest, "invalid_request", "malformed JSON body or unknown field")
		return false
	}
	var extra json.RawMessage
	if err := decoder.Decode(&extra); err != io.EOF {
		s.fail(w, r, http.StatusBadRequest, "invalid_request", "trailing content after the JSON body")
		return false
	}
	return true
}

// query validates and reads the query parameters of a request.
type query struct {
	values url.Values
	err    error
}

func parseQuery(r *http.Request, allowed ...string) *query {
	values := r.URL.Query()
	allowedSet := make(map[string]struct{}, len(allowed))
	for _, name := range allowed {
		allowedSet[name] = struct{}{}
	}
	for name := range values {
		if _, ok := allowedSet[name]; !ok {
			return &query{values: values, err: fmt.Errorf("unknown query parameter %q", name)}
		}
	}
	return &query{values: values}
}

func (q *query) str(name string) string { return strings.TrimSpace(q.values.Get(name)) }

func (q *query) setError(err error) {
	if q.err == nil {
		q.err = err
	}
}

func (q *query) intValue(name string, def, minimum, maximum int) int {
	if q.err != nil {
		return def
	}
	raw := q.str(name)
	if raw == "" {
		return def
	}
	value, err := strconv.Atoi(raw)
	if err != nil || value < minimum || value > maximum {
		q.setError(fmt.Errorf("%s must be an integer between %d and %d", name, minimum, maximum))
		return def
	}
	return value
}

func (q *query) limit() int  { return q.intValue("limit", defaultList, 1, maxListLimit) }
func (q *query) offset() int { return q.intValue("offset", 0, 0, 1_000_000) }

func (q *query) enumValue(name string, allowed []string) string {
	if q.err != nil {
		return ""
	}
	raw := q.str(name)
	if raw == "" {
		return ""
	}
	for _, candidate := range allowed {
		if candidate == raw {
			return raw
		}
	}
	q.setError(fmt.Errorf("%s has an invalid value", name))
	return ""
}

func (q *query) boolValue(name string) bool {
	if q.err != nil {
		return false
	}
	raw := q.str(name)
	switch raw {
	case "":
		return false
	case "true", "1":
		return true
	case "false", "0":
		return false
	}
	q.setError(fmt.Errorf("%s must be a boolean", name))
	return false
}

func (q *query) targetID(name string) string {
	raw := q.str(name)
	if raw != "" && len(raw) > 96 {
		q.setError(fmt.Errorf("%s is too long", name))
		return ""
	}
	return raw
}

// checkQuery writes a 400 when parameter validation failed.
func (s *Server) checkQuery(w http.ResponseWriter, r *http.Request, q *query) bool {
	if q.err == nil {
		return true
	}
	s.fail(w, r, http.StatusBadRequest, "invalid_request", q.err.Error())
	return false
}
