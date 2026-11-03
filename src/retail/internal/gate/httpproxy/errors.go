package httpproxy

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/visiongaiatechnology/gedefense/retail/internal/domain"
)

// writeError emits the contract error envelope (code + request id, no details).
func (p *Proxy) writeError(w http.ResponseWriter, r *http.Request, status int, code string) {
	requestID := newRequestID()
	w.Header().Set("X-Request-Id", requestID)
	if wantsJSON(r) {
		writeJSON(w, status, map[string]any{
			"error": map[string]any{"code": code, "message": codeMessage(code), "request_id": requestID},
		})
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(status)
	_, _ = io.WriteString(w, codeMessage(code)+"\n")
}

func codeMessage(code string) string {
	switch code {
	case "unauthorized":
		return "authentication required"
	case "forbidden":
		return "request denied"
	case "rate_limited":
		return "too many requests"
	case "unavailable":
		return "upstream unavailable"
	case "invalid_request":
		return "invalid request"
	default:
		return "request failed"
	}
}

// denyWrite reports a refused write to the gate core (fail-closed regardless of
// reporting errors).
func (p *Proxy) denyWrite(ctx context.Context, sourceIP, function, address, reason, valueHint string) {
	attempt := domain.DeniedWriteAttempt{
		DenyID:    newDenyID(),
		At:        p.now(),
		SourceIP:  sourceIP,
		TargetID:  p.cfg.TargetID,
		Protocol:  Protocol,
		Function:  function,
		Address:   address,
		ValueHint: valueHint,
		Reason:    reason,
		Severity:  httpDenySeverity(reason),
	}
	if err := attempt.Validate(); err != nil {
		p.recordError("deny evidence: " + err.Error())
		return
	}
	if p.sessions == nil {
		return
	}
	if err := p.sessions.Deny(ctx, attempt); err != nil {
		p.recordError("deny report: " + err.Error())
	}
}

func httpDenySeverity(reason string) domain.Severity {
	switch reason {
	case ReasonOperationNotApproved, ReasonValueMismatch, ReasonAddressMismatch,
		ReasonOutsideWindow, ReasonNotApproved, ReasonSessionRevoked, ReasonFailsafeStore:
		return domain.SeverityCritical
	default:
		return domain.SeverityHigh
	}
}

func newDenyID() domain.DenyID {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err == nil {
		return domain.DenyID("dny_" + hex.EncodeToString(raw[:]))
	}
	return domain.DenyID("dny_fallback_" + strconv.FormatInt(time.Now().UnixNano(), 10))
}

func newRequestID() string {
	var raw [8]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "req_unavailable"
	}
	return "req_" + hex.EncodeToString(raw[:])
}

// bodySHA256 is the plan value binding for HTTP writes (Alpha).
func bodySHA256(body []byte) string {
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

// readBoundedBody reads at most limit bytes and rejects larger bodies.
func readBoundedBody(r *http.Request, limit int64) ([]byte, error) {
	if r.Body == nil {
		return nil, nil
	}
	data, err := io.ReadAll(io.LimitReader(r.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, ErrTooLarge
	}
	return data, nil
}
