package api

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/visiongaiatechnology/gedefense/retail/internal/i18n"
)

// Security headers are applied to every response, including the static UI.
const contentSecurityPolicy = "default-src 'self'; img-src 'self' data:; " +
	"style-src 'self'; script-src 'self'; connect-src 'self'; " +
	"frame-ancestors 'none'; base-uri 'none'; form-action 'self'"

// requestIDPattern is the only accepted inbound request id shape.
var requestIDPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{8,64}$`)

type contextKey int

const (
	ctxKeyRequestID contextKey = iota
	ctxKeyIdentity
)

// statusRecorder tracks whether a response was already written so that the
// panic boundary never writes a second status line.
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

func (s *statusRecorder) Write(body []byte) (int, error) {
	if !s.wrote {
		s.WriteHeader(http.StatusOK)
	}
	return s.ResponseWriter.Write(body)
}

// Flush forwards to the underlying flusher (required for SSE).
func (s *statusRecorder) Flush() {
	if flusher, ok := s.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}

// Unwrap exposes the original writer to http.ResponseController.
func (s *statusRecorder) Unwrap() http.ResponseWriter { return s.ResponseWriter }

// buildHandler composes the middleware chain.
func (s *Server) buildHandler() http.Handler {
	mux := http.HandlerFunc(s.serve)
	return s.whitelistMW(s.recoverMW(s.baseMW(mux)))
}

// recoverMW is the single panic boundary of the HTTP layer: a handler bug becomes
// a logged 500 instead of a crashed process.
func (s *Server) recoverMW(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		recorder, ok := w.(*statusRecorder)
		if !ok {
			recorder = &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		}
		defer func() {
			if recovered := recover(); recovered != nil {
				s.logger.Error("panic while serving request",
					"request_id", requestID(r),
					"method", r.Method,
					"path", r.URL.Path,
					"panic", fmt.Sprint(recovered),
				)
				if !recorder.wrote {
					s.fail(recorder, r, http.StatusInternalServerError, "internal", "internal server error")
				}
			}
		}()
		next.ServeHTTP(recorder, r)
	})
}

// baseMW assigns the request id, applies the security headers and the cache
// policy, and installs the request context.
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
		if strings.HasPrefix(r.URL.Path, apiPrefix) {
			header.Set("Cache-Control", "no-store")
		} else {
			header.Set("Cache-Control", "no-cache")
		}
		ctx := context.WithValue(r.Context(), ctxKeyRequestID, id)
		// Resolve the response language once per request so every error path
		// (including the setup API) localizes consistently. The language never
		// changes a status code or the machine-stable error code.
		ctx = i18n.WithLanguage(ctx, s.requestLanguage(r))
		header.Set("Vary", "Accept-Language")
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// requestIDFromRequest honours a well-formed inbound request id and otherwise
// generates a new one.
func requestIDFromRequest(r *http.Request) string {
	if candidate := r.Header.Get("X-Request-Id"); requestIDPattern.MatchString(candidate) {
		return candidate
	}
	return newRequestID()
}

// newRequestID creates an unpredictable request identifier.
func newRequestID() string {
	raw := make([]byte, 12)
	if _, err := rand.Read(raw); err != nil {
		// A request id must never panic the request path; the timestamp is only a
		// fallback for a broken entropy source.
		return fmt.Sprintf("%x", time.Now().UTC().UnixNano())
	}
	return hex.EncodeToString(raw)
}

// requestID returns the request id stored in the context.
func requestID(r *http.Request) string {
	if id, ok := r.Context().Value(ctxKeyRequestID).(string); ok {
		return id
	}
	return ""
}

// withIdentity stores the authenticated caller in the context.
func withIdentity(ctx context.Context, ident identity) context.Context {
	return context.WithValue(ctx, ctxKeyIdentity, ident)
}

// identityFrom returns the authenticated caller of the request.
func identityFrom(r *http.Request) (identity, bool) {
	ident, ok := r.Context().Value(ctxKeyIdentity).(identity)
	return ident, ok
}
