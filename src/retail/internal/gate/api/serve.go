package api

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"strconv"
	"strings"
)

const idempotencyHeader = "Idempotency-Key"

// serve dispatches one gate API request.
func (s *Server) serve(w http.ResponseWriter, r *http.Request) {
	recorder, ok := w.(*statusRecorder)
	if !ok {
		recorder = &statusRecorder{ResponseWriter: w, status: http.StatusOK}
	}
	if !strings.HasPrefix(r.URL.Path, apiPrefix) {
		s.fail(recorder, r, http.StatusNotFound, "not_found", "resource not found")
		return
	}
	matched, routeParams, allowed := matchRoute(s.routes(), r.Method, r.URL.Path)
	if matched == nil {
		if len(allowed) > 0 {
			recorder.Header().Set("Allow", strings.Join(allowed, ", "))
			s.fail(recorder, r, http.StatusMethodNotAllowed, "invalid_request", "method not allowed")
			return
		}
		s.fail(recorder, r, http.StatusNotFound, "not_found", "resource not found")
		return
	}

	session, authenticated := s.authenticate(r)
	if !matched.public {
		if !authenticated {
			recorder.Header().Set("WWW-Authenticate", `Bearer realm="gedefense-gate"`)
			s.fail(recorder, r, http.StatusUnauthorized, "unauthorized", "authentication required")
			return
		}
	}
	if len(matched.roles) > 0 && !hasAnyRole(session.User, matched.roles) {
		s.fail(recorder, r, http.StatusForbidden, "role_required", "insufficient permissions")
		return
	}

	limitKey := "ip:" + clientIP(r)
	if authenticated {
		limitKey = "token:" + session.TokenHash
	}
	limiter := s.limiter
	if matched.login {
		limiter = s.loginLimiter
		limitKey = "login:" + clientIP(r)
	}
	if allowedNow, retryAfter := limiter.allow(limitKey); !allowedNow {
		recorder.Header().Set("Retry-After", strconv.Itoa(retryAfter))
		s.fail(recorder, r, http.StatusTooManyRequests, "rate_limited", "too many requests")
		return
	}

	if matched.idempotent {
		if s.serveIdempotent(recorder, r, matched, routeParams, session) {
			return
		}
		if recorder.wrote {
			return
		}
	}

	matched.handler(recorder, r, routeParams, session)
}

// serveIdempotent replays a completed POST response or captures a new one.
// It returns true when the request was fully handled.
func (s *Server) serveIdempotent(w *statusRecorder, r *http.Request, matched *route, routeParams params, session apiSession) bool {
	key := strings.TrimSpace(r.Header.Get(idempotencyHeader))
	if key == "" {
		return false
	}
	if len(key) < 8 || len(key) > 128 || strings.ContainsAny(key, " \t\r\n") {
		s.fail(w, r, http.StatusBadRequest, "invalid_request", "Idempotency-Key must be 8..128 visible characters")
		return true
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, maxBodyBytes+1))
	if err != nil {
		s.fail(w, r, http.StatusBadRequest, "invalid_request", "could not read request body")
		return true
	}
	if len(raw) > maxBodyBytes {
		s.fail(w, r, http.StatusBadRequest, "invalid_request", "request body exceeds 128 KiB")
		return true
	}
	sum := sha256.Sum256(raw)
	requestHash := hex.EncodeToString(sum[:])
	if entry, found, keyOK := s.idem.lookup(key, requestHash); found {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(entry.status)
		_, _ = w.Write(entry.body)
		return true
	} else if !keyOK {
		s.fail(w, r, http.StatusConflict, "conflict", "Idempotency-Key was already used with a different request")
		return true
	}
	r.Body = io.NopCloser(bytes.NewReader(raw))
	capture := &captureWriter{statusRecorder: w, body: &bytes.Buffer{}}
	matched.handler(capture, r, routeParams, session)
	if !w.wrote || w.status < 200 || w.status > 299 {
		return true
	}
	s.idem.store(key, requestHash, w.status, capture.body.Bytes())
	return true
}
