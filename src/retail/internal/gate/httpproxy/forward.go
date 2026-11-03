// Request policy, write authorization and reverse-proxy forwarding.
package httpproxy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"path"
	"strings"
	"time"

	"github.com/visiongaiatechnology/gedefense/retail/internal/domain"
)

// Stable deny reasons (gate engineering contract §5) plus the Alpha extensions.
const (
	ReasonNoSession            = "no_session"
	ReasonSessionExpired       = "session_expired"
	ReasonSessionRevoked       = "session_revoked"
	ReasonWrongSource          = "wrong_source"
	ReasonWrongTarget          = "wrong_target"
	ReasonNotApproved          = "not_approved"
	ReasonOperationNotApproved = "operation_not_approved"
	ReasonValueMismatch        = "value_mismatch"
	ReasonAddressMismatch      = "address_mismatch"
	ReasonOutsideWindow        = "outside_window"
	ReasonFailsafeStore        = "failsafe_store"
	ReasonURLNotAllowed        = "operation_not_approved"
	ReasonHardDenied           = "operation_not_approved"
)

// deviceCookiePrefix scopes device cookies per target (no cross-device bleed).
const deviceCookiePrefix = "gd_dev_"

// hop-by-hop headers that must never be forwarded (RFC 7230 §6.1).
var hopByHopHeaders = map[string]struct{}{
	"connection": {}, "keep-alive": {}, "proxy-authenticate": {}, "proxy-authorization": {},
	"te": {}, "trailer": {}, "transfer-encoding": {}, "upgrade": {}, "proxy-connection": {},
	"x-forwarded-for": {}, "x-forwarded-host": {}, "x-forwarded-proto": {}, "forwarded": {},
	"x-real-ip": {}, "authorization": {}, "cookie": {}, "set-cookie": {},
}

// chained checkError carries the HTTP status of a refused request.
type checkError struct {
	status int
	code   string
	reason string
	deny   bool
}

func (e *checkError) Error() string { return e.code }

// ErrTooLarge is returned for bodies above the configured limit.
var ErrTooLarge = errors.New("httpproxy: body too large")

// serve is the single handler entry point.
func (p *Proxy) serve(w http.ResponseWriter, r *http.Request) {
	p.requests.Add(1)
	secure := p.secureRequest(r)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Cache-Control", "no-store")
	if !p.sourceAllowed(r) {
		p.sourceDenied.Add(1)
		p.writeError(w, r, http.StatusForbidden, "forbidden")
		return
	}
	switch r.URL.Path {
	case gateLoginPath:
		p.serveLogin(w, r, secure)
		return
	case gateLogoutPath:
		p.serveLogout(w, r, secure)
		return
	}
	if _, ok := p.authenticate(r); !ok {
		p.authFailures.Add(1)
		p.writeError(w, r, http.StatusUnauthorized, "unauthorized")
		return
	}
	// WebSocket/Upgrade tunnels have no method or plan context in the MVP.
	if r.Header.Get("Upgrade") != "" {
		p.writeError(w, r, http.StatusNotImplemented, "unavailable")
		return
	}
	switch r.Method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		p.reads.Add(1)
		if p.isForbiddenUpdatePath(r.URL.Path) {
			p.writeError(w, r, http.StatusForbidden, "forbidden")
			return
		}
		p.forward(w, r, nil)
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		p.handleWrite(w, r)
	default:
		w.Header().Set("Allow", "GET, HEAD, OPTIONS, POST, PUT, PATCH, DELETE")
		p.writeError(w, r, http.StatusMethodNotAllowed, "invalid_request")
	}
}

// handleWrite enforces the write policy: hard deny -> URL allowlist -> body
// limit -> parameter allowlist -> session + plan match -> audit -> forward.
func (p *Proxy) handleWrite(w http.ResponseWriter, r *http.Request) {
	writePath, err := canonicalWritePath(r.URL.Path)
	if err != nil {
		p.writeError(w, r, http.StatusBadRequest, "invalid_request")
		return
	}
	clientIP := requestClientIP(r)
	function := "http_" + strings.ToLower(r.Method)
	deny := func(reason string) {
		p.writesDenied.Add(1)
		p.denyWrite(r.Context(), clientIP, function, writePath, reason, "body")
	}
	if p.isForbiddenUpdatePath(writePath) {
		deny(ReasonHardDenied)
		p.writeError(w, r, http.StatusForbidden, "forbidden")
		return
	}
	if !p.allowed.Match(writePath) {
		deny(ReasonURLNotAllowed)
		p.writeError(w, r, http.StatusForbidden, "forbidden")
		return
	}
	body, err := readBoundedBody(r, p.cfg.BodyLimit)
	if err != nil {
		p.writeError(w, r, http.StatusRequestEntityTooLarge, "invalid_request")
		return
	}
	if err := p.checkParameterAllowlist(r, body); err != nil {
		deny(ReasonOperationNotApproved)
		p.writeError(w, r, http.StatusForbidden, "forbidden")
		return
	}
	now := p.now()
	if p.sessions == nil {
		deny(ReasonNoSession)
		p.writeError(w, r, http.StatusForbidden, "forbidden")
		return
	}
	session, ok := p.sessions.Lookup(p.cfg.TargetID, clientIP, now)
	if !ok {
		deny(ReasonNoSession)
		p.writeError(w, r, http.StatusForbidden, "forbidden")
		return
	}
	reason, status := p.writeDecision(session, clientIP, function, writePath, body, now)
	if reason != "" {
		deny(reason)
		p.writeError(w, r, status, reason)
		return
	}
	p.writesAllowed.Add(1)
	p.forward(w, r, body)
}

// writeDecision evaluates session, plan, window and exact body match. It returns
// an empty reason on success.
func (p *Proxy) writeDecision(session domain.WriteSession, clientIP, function, writePath string, body []byte, now time.Time) (reason string, status int) {
	if session.Revoked {
		return ReasonSessionRevoked, http.StatusForbidden
	}
	if !now.Before(session.ExpiresAt) || session.Uses >= session.MaxUses {
		return ReasonSessionExpired, http.StatusForbidden
	}
	if session.TargetID != p.cfg.TargetID {
		return ReasonWrongTarget, http.StatusForbidden
	}
	if session.SourceIP != clientIP {
		return ReasonWrongSource, http.StatusForbidden
	}
	plan, ok := p.sessions.PlanFor(session.SessionID)
	if !ok {
		return ReasonNotApproved, http.StatusForbidden
	}
	if plan.TargetID != p.cfg.TargetID {
		return ReasonWrongTarget, http.StatusForbidden
	}
	if plan.State != domain.PlanApproved && plan.State != domain.PlanExecuted {
		return ReasonNotApproved, http.StatusForbidden
	}
	if !plan.InWindow(now) {
		return ReasonOutsideWindow, http.StatusForbidden
	}
	value := bodySHA256(body)
	op, matched := plan.MatchOperation(Protocol, function, writePath, value)
	if !matched {
		addressKnown := false
		for _, planned := range plan.Operations {
			if planned.Protocol == Protocol && planned.Function == function && planned.Address == writePath {
				addressKnown = true
				break
			}
		}
		if addressKnown {
			return ReasonValueMismatch, http.StatusForbidden
		}
		return ReasonAddressMismatch, http.StatusForbidden
	}
	if !p.sessions.ConsumeUse(session.SessionID, now) {
		return ReasonSessionExpired, http.StatusForbidden
	}
	if err := p.sessions.Allowed(context.Background(), session.SessionID, op); err != nil {
		p.recordError("allowed audit: " + err.Error())
		return ReasonFailsafeStore, http.StatusServiceUnavailable
	}
	return "", 0
}

// checkParameterAllowlist enforces the Alpha parameter allowlist (form or JSON
// body keys). An empty allowlist documents the Alpha limit: path+body-hash only.
func (p *Proxy) checkParameterAllowlist(r *http.Request, body []byte) error {
	if len(p.cfg.ParameterAllowlist) == 0 {
		return nil
	}
	allowed := make(map[string]struct{}, len(p.cfg.ParameterAllowlist))
	for _, name := range p.cfg.ParameterAllowlist {
		allowed[name] = struct{}{}
	}
	keys, err := bodyKeys(r.Header.Get("Content-Type"), body)
	if err != nil {
		return err
	}
	if len(keys) == 0 {
		return errors.New("httpproxy: write body has no parameters for the allowlist")
	}
	for _, key := range keys {
		if _, ok := allowed[key]; !ok {
			return fmt.Errorf("httpproxy: parameter %q is not allowlisted", key)
		}
	}
	return nil
}

// bodyKeys extracts the parameter names of a form or JSON body.
func bodyKeys(contentType string, body []byte) ([]string, error) {
	lower := strings.ToLower(contentType)
	if strings.Contains(lower, "application/json") {
		var decoded map[string]json.RawMessage
		if err := json.Unmarshal(body, &decoded); err != nil {
			return nil, err
		}
		keys := make([]string, 0, len(decoded))
		for key := range decoded {
			keys = append(keys, key)
		}
		return keys, nil
	}
	values, err := url.ParseQuery(string(body))
	if err != nil {
		return nil, err
	}
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	return keys, nil
}

// isForbiddenUpdatePath hard-denies firmware/update paths (and CGI writes by
// default, see Config.AllowCGIWrites).
func (p *Proxy) isForbiddenUpdatePath(rawPath string) bool {
	lower := strings.ToLower(rawPath)
	for _, marker := range []string{"/update", "/firmware", "/upgrade", "/flash"} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	for _, suffix := range []string{".spk", ".bin", ".fw", ".img", ".hex", ".zip", ".tar", ".gz"} {
		if strings.HasSuffix(lower, suffix) {
			return true
		}
	}
	if strings.Contains(lower, ".cgi") && !p.cfg.AllowCGIWrites {
		return true
	}
	return false
}

// sourceAllowed applies the mandatory source CIDRs to the direct peer.
func (p *Proxy) sourceAllowed(r *http.Request) bool {
	ip := requestClientIP(r)
	if ip == "" {
		return false
	}
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	for _, prefix := range p.cfg.SourceCIDRs {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

// forward proxies one read or an already authorized write.
func (p *Proxy) forward(w http.ResponseWriter, r *http.Request, writeBody []byte) {
	upstreamURL, err := p.buildUpstreamURL(r)
	if err != nil {
		p.recordError("upstream url: " + err.Error())
		p.writeError(w, r, http.StatusBadRequest, "invalid_request")
		return
	}
	var body io.Reader
	if writeBody != nil {
		body = bytes.NewReader(writeBody)
	}
	request, err := http.NewRequestWithContext(r.Context(), r.Method, upstreamURL, body)
	if err != nil {
		p.writeError(w, r, http.StatusInternalServerError, "internal")
		return
	}
	// Embedded UIs often check Host; SNI is derived from the upstream URL host.
	request.Host = p.target.Host
	request.Header = p.filterRequestHeaders(r)
	if deviceCookies := p.deviceCookieHeader(r); deviceCookies != "" {
		request.Header.Set("Cookie", deviceCookies)
	}
	if writeBody != nil {
		request.ContentLength = int64(len(writeBody))
	}
	response, err := p.transport.RoundTrip(request)
	if err != nil {
		p.upstreamErrors.Add(1)
		p.recordError("upstream: " + err.Error())
		p.writeError(w, r, http.StatusBadGateway, "unavailable")
		return
	}
	defer func() { _ = response.Body.Close() }()
	p.copyResponse(w, r, response)
}

// copyResponse rewrites headers/cookies/redirects and streams the body with a
// hard size limit. Firmware paths are denied earlier, so large legitimate
// responses are bounded instead of buffered.
func (p *Proxy) copyResponse(w http.ResponseWriter, r *http.Request, response *http.Response) {
	secure := p.secureRequest(r)
	w.Header().Set("Content-Type", "application/json")
	for key, values := range response.Header {
		lower := strings.ToLower(key)
		if _, hop := hopByHopHeaders[lower]; hop {
			continue
		}
		if lower == "cache-control" {
			continue
		}
		if lower == "location" {
			continue
		}
		w.Header()[key] = append([]string{}, values...)
	}
	if location := response.Header.Get("Location"); location != "" {
		w.Header().Set("Location", p.rewriteLocation(location))
	}
	w.Header().Del("Set-Cookie")
	for _, cookie := range response.Cookies() {
		if cookie.Name == "" || len(cookie.Name) > 48 {
			continue
		}
		rewritten := &http.Cookie{
			Name:     deviceCookiePrefix + cookie.Name,
			Value:    cookie.Value,
			Path:     "/",
			HttpOnly: true,
			Secure:   secure,
			SameSite: http.SameSiteStrictMode,
			MaxAge:   cookie.MaxAge,
		}
		http.SetCookie(w, rewritten)
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.WriteHeader(response.StatusCode)
	if r.Method == http.MethodHead {
		return
	}
	written, err := io.Copy(w, io.LimitReader(response.Body, p.cfg.MaxResponseBytes+1))
	if err != nil {
		p.recordError("response copy: " + err.Error())
		return
	}
	if written > p.cfg.MaxResponseBytes {
		p.recordError("response exceeded the configured limit")
		panic(http.ErrAbortHandler)
	}
}

// filterRequestHeaders copies only the allowlisted, non-sensitive headers.
func (p *Proxy) filterRequestHeaders(r *http.Request) http.Header {
	header := make(http.Header, len(p.headerAllow))
	for key, values := range r.Header {
		lower := strings.ToLower(key)
		if _, ok := p.headerAllow[lower]; !ok {
			continue
		}
		if _, hop := hopByHopHeaders[lower]; hop {
			continue
		}
		header[key] = append([]string{}, values...)
	}
	return header
}

// deviceCookieHeader reconstructs the device cookie header from prefixed client
// cookies. The gate session cookie is never forwarded to the device.
func (p *Proxy) deviceCookieHeader(r *http.Request) string {
	parts := make([]string, 0, 4)
	for _, cookie := range r.Cookies() {
		if !strings.HasPrefix(cookie.Name, deviceCookiePrefix) {
			continue
		}
		name := strings.TrimPrefix(cookie.Name, deviceCookiePrefix)
		if name == "" || strings.ContainsAny(name, ";, \t\r\n") {
			continue
		}
		parts = append(parts, name+"="+cookie.Value)
	}
	return strings.Join(parts, "; ")
}

// rewriteLocation turns device-absolute redirects into gate-relative ones so a
// browser can never be sent directly to the controller (bypass).
func (p *Proxy) rewriteLocation(location string) string {
	parsed, err := url.Parse(location)
	if err != nil || !parsed.IsAbs() {
		return location
	}
	if !strings.EqualFold(parsed.Host, p.target.Host) {
		return location
	}
	out := parsed.Path
	if out == "" {
		out = "/"
	}
	if parsed.RawQuery != "" {
		out += "?" + parsed.RawQuery
	}
	return out
}

// buildUpstreamURL joins the upstream base URL with the request path safely.
func (p *Proxy) buildUpstreamURL(r *http.Request) (string, error) {
	cleanPath, err := canonicalWritePath(r.URL.Path)
	if err != nil {
		return "", err
	}
	base := p.target
	basePath := strings.TrimSuffix(base.Path, "/")
	full := path.Clean(basePath + "/" + strings.TrimPrefix(cleanPath, "/"))
	if !strings.HasPrefix(full, "/") {
		full = "/" + full
	}
	if basePath != "" && !strings.HasPrefix(full, basePath) {
		return "", errors.New("httpproxy: path escaped the upstream base path")
	}
	u := &url.URL{Scheme: base.Scheme, Host: base.Host, Path: full, RawQuery: r.URL.RawQuery}
	return u.String(), nil
}
