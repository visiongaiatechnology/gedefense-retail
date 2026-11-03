package api

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/visiongaiatechnology/gedefense/retail/internal/i18n"
)

// apiErrorBody is the machine readable error payload of the contract.
type apiErrorBody struct {
	Code      string `json:"code"`
	Message   string `json:"message"`
	RequestID string `json:"request_id"`
}

type apiErrorEnvelope struct {
	Error apiErrorBody `json:"error"`
}

// listEnvelope is the paginated list response of the contract.
type listEnvelope[T any] struct {
	Items  []T `json:"items"`
	Total  int `json:"total"`
	Limit  int `json:"limit,omitempty"`
	Offset int `json:"offset,omitempty"`
}

// respondJSON writes a JSON response with the contract headers.
func (s *Server) respondJSON(w http.ResponseWriter, r *http.Request, status int, payload any) {
	raw, err := json.Marshal(payload)
	if err != nil {
		s.logger.Error("encode response failed",
			"request_id", requestID(r), "path", r.URL.Path, "error", err)
		s.fail(w, r, http.StatusInternalServerError, "internal", "internal server error")
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	if _, werr := w.Write(raw); werr != nil {
		s.logger.Warn("write response failed", "request_id", requestID(r), "error", werr)
	}
}

// maxErrorBodyDrain bounds how much of an unread request body is discarded
// before an early error response. Larger or unknown-length bodies are not drained
// at all; the connection is then marked non-reusable instead of blocking.
const maxErrorBodyDrain = 64 << 10

// drainRequestBody discards the bounded remainder of a request body before an
// early error response is written.
//
// Why: all error paths (unknown route, 405, 401, 403, 429, malformed body) answer
// before the handler necessarily read the body. Leaving inbound bytes unread makes
// the HTTP layer close the connection with pending data; Windows turns that into a
// TCP RST and the client observes a connection reset instead of the documented
// error response. Draining a small body makes the exchange cleanly framed, and an
// oversized or unknown-length body is answered with Connection: close so the client
// knows not to reuse the socket. The read is bounded, so a slow sender cannot pin
// the request goroutine.
func drainRequestBody(w http.ResponseWriter, r *http.Request) {
	body := r.Body
	if body == nil || body == http.NoBody {
		return
	}
	switch {
	case r.ContentLength < 0:
		// Chunked/unknown length: never block on an unbounded stream.
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
		// The sender aborted mid-body; the connection cannot be reused.
		w.Header().Set("Connection", "close")
	}
}

// fail writes the contract error envelope. The code and HTTP status are always
// machine-stable; the human message is localized when the request language is not
// English (English keeps the caller's precise detail for backward compatibility).
//
// The language normally comes from baseMW. Requests rejected earlier in the chain
// (whitelist deny) have no request context yet, so fail resolves the language from
// the request itself in that case.
func (s *Server) fail(w http.ResponseWriter, r *http.Request, status int, code, message string) {
	drainRequestBody(w, r)
	lang, ok := i18n.LanguageFromContext(r.Context())
	if !ok {
		lang = s.requestLanguage(r)
	}
	localized := localizedError(lang, code, message)
	if localized != message {
		// The English detail stays in the diagnostic log, never in the localized
		// response body.
		s.logger.Debug("localized error response",
			"request_id", requestID(r), "code", code, "language", lang.String(), "detail", message)
	}
	w.Header().Set("Vary", "Accept-Language")
	envelope := apiErrorEnvelope{Error: apiErrorBody{
		Code:      code,
		Message:   localized,
		RequestID: requestID(r),
	}}
	raw, err := json.Marshal(envelope)
	if err != nil {
		// The envelope only contains strings; this cannot fail in practice, but a
		// fixed fallback keeps the response valid instead of panicking.
		http.Error(w, `{"error":{"code":"internal","message":"internal server error"}}`, http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	if _, werr := w.Write(raw); werr != nil {
		s.logger.Warn("write error response failed", "request_id", requestID(r), "error", werr)
	}
}

// decodeJSON strictly decodes exactly one JSON object from the request body.
// It returns false after having written the error response.
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
			s.fail(w, r, http.StatusBadRequest, "invalid_request", "request body exceeds 256 KiB")
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

// newList builds the paginated list envelope, ensuring a non-nil items slice.
func newList[T any](items []T, total, limit, offset int) listEnvelope[T] {
	if items == nil {
		items = []T{}
	}
	return listEnvelope[T]{Items: items, Total: total, Limit: limit, Offset: offset}
}
