// Gate login/logout over the reverse-proxy listener (API contract §7).
package httpproxy

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"html"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	gateLoginPath       = "/gate/login"
	gateLogoutPath      = "/gate/logout"
	sessionCookie       = "gate_session"
	secureSessionCookie = "__Host-gate_session"
	csrfCookie          = "gate_csrf"
	csrfField           = "csrf"
	loginBodyLimit      = 16 << 10
	loginRatePerMin     = 10
	loginWindow         = time.Minute
	maxLoginBuckets     = 4096
)

// loginLimiter is a bounded per-IP sliding window (10 login attempts/minute).
type loginLimiter struct {
	mu      sync.Mutex
	entries map[string]*loginBucket
}

type loginBucket struct {
	windowStart time.Time
	count       int
}

func newLoginLimiter() *loginLimiter {
	return &loginLimiter{entries: make(map[string]*loginBucket, 64)}
}

func (l *loginLimiter) allow(ip string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.entries) > maxLoginBuckets {
		l.entries = make(map[string]*loginBucket, 64)
	}
	bucket, ok := l.entries[ip]
	if !ok || now.Sub(bucket.windowStart) >= loginWindow {
		l.entries[ip] = &loginBucket{windowStart: now, count: 1}
		return true
	}
	if bucket.count >= loginRatePerMin {
		return false
	}
	bucket.count++
	return true
}

// secureRequest reports whether cookies must be Secure (TLS at the gate or an
// explicit TLS-terminating deployment flag).
func (p *Proxy) secureRequest(r *http.Request) bool {
	return r.TLS != nil || p.cfg.SecureCookies
}

func cookieName(secure bool) string {
	if secure {
		return secureSessionCookie
	}
	return sessionCookie
}

// readSessionToken returns the gate session token from the request cookies.
func (p *Proxy) readSessionToken(r *http.Request) string {
	for _, cookie := range r.Cookies() {
		if cookie.Name == sessionCookie || cookie.Name == secureSessionCookie {
			return cookie.Value
		}
	}
	return ""
}

// authenticate resolves the gate session cookie to an active gate user.
func (p *Proxy) authenticate(r *http.Request) (userID string, ok bool) {
	token := p.readSessionToken(r)
	if token == "" {
		return "", false
	}
	user, valid := p.auth.Authenticate(r.Context(), token)
	if !valid {
		return "", false
	}
	return string(user), true
}

func (p *Proxy) setSessionCookie(w http.ResponseWriter, r *http.Request, token string) {
	secure := p.secureRequest(r)
	http.SetCookie(w, &http.Cookie{
		Name: cookieName(secure), Value: token, Path: "/", HttpOnly: true,
		Secure: secure, SameSite: http.SameSiteStrictMode,
		MaxAge: int(p.cfg.SessionTTL.Seconds()),
	})
}

func (p *Proxy) clearSessionCookie(w http.ResponseWriter, r *http.Request) {
	secure := p.secureRequest(r)
	http.SetCookie(w, &http.Cookie{
		Name: cookieName(secure), Value: "", Path: "/", HttpOnly: true,
		Secure: secure, SameSite: http.SameSiteStrictMode, MaxAge: -1,
	})
}

// serveLogin handles GET (form with CSRF token) and POST (credential check).
func (p *Proxy) serveLogin(w http.ResponseWriter, r *http.Request, secure bool) {
	switch r.Method {
	case http.MethodGet, http.MethodHead:
		token, err := randomToken(24)
		if err != nil {
			p.recordError("csrf token: " + err.Error())
			p.writeError(w, r, http.StatusInternalServerError, "internal")
			return
		}
		http.SetCookie(w, &http.Cookie{
			Name: csrfCookie, Value: token, Path: "/", HttpOnly: true, Secure: secure,
			SameSite: http.SameSiteStrictMode, MaxAge: 600,
		})
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`<!doctype html><html><head><title>GeDefense Gate</title></head><body>
<h1>GeDefense Access Gate</h1>
<form method="post" action="/gate/login">
<input type="hidden" name="csrf" value="` + html.EscapeString(token) + `">
<label>User <input name="user_id" autocomplete="username" required></label>
<label>Password <input name="password" type="password" autocomplete="current-password" required></label>
<label>TOTP <input name="totp" inputmode="numeric" autocomplete="one-time-code"></label>
<button type="submit">Sign in</button>
</form></body></html>`))
	case http.MethodPost:
		p.handleLoginPost(w, r)
	default:
		w.Header().Set("Allow", "GET, POST")
		p.writeError(w, r, http.StatusMethodNotAllowed, "invalid_request")
	}
}

func (p *Proxy) handleLoginPost(w http.ResponseWriter, r *http.Request) {
	clientIP := requestClientIP(r)
	if !p.limiter.allow(clientIP, p.now()) {
		p.loginFailures.Add(1)
		p.writeError(w, r, http.StatusTooManyRequests, "rate_limited")
		return
	}
	// CSRF: the form token must equal the cookie token (constant time).
	cookieToken := ""
	for _, cookie := range r.Cookies() {
		if cookie.Name == csrfCookie {
			cookieToken = cookie.Value
			break
		}
	}
	r.Body = http.MaxBytesReader(w, r.Body, loginBodyLimit)
	if err := r.ParseForm(); err != nil {
		p.loginFailures.Add(1)
		p.writeError(w, r, http.StatusBadRequest, "invalid_request")
		return
	}
	formToken := r.PostForm.Get(csrfField)
	if cookieToken == "" || formToken == "" || subtle.ConstantTimeCompare([]byte(cookieToken), []byte(formToken)) != 1 {
		p.loginFailures.Add(1)
		p.writeError(w, r, http.StatusForbidden, "forbidden")
		return
	}
	userID := strings.TrimSpace(r.PostForm.Get("user_id"))
	password := r.PostForm.Get("password")
	totp := strings.TrimSpace(r.PostForm.Get("totp"))
	if userID == "" || password == "" {
		p.loginFailures.Add(1)
		p.writeError(w, r, http.StatusUnauthorized, "unauthorized")
		return
	}
	user, token, err := p.auth.Login(r.Context(), userID, password, totp)
	if err != nil || token == "" {
		p.loginFailures.Add(1)
		p.recordError("login rejected")
		p.writeError(w, r, http.StatusUnauthorized, "unauthorized")
		return
	}
	p.loginOK.Add(1)
	p.setSessionCookie(w, r, token)
	http.SetCookie(w, &http.Cookie{
		Name: csrfCookie, Value: "", Path: "/", HttpOnly: true, Secure: p.secureRequest(r),
		SameSite: http.SameSiteStrictMode, MaxAge: -1,
	})
	if wantsJSON(r) {
		writeJSON(w, http.StatusOK, map[string]any{"user_id": string(user)})
		return
	}
	// Constant, non-user-controlled redirect target (no open redirect).
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// serveLogout revokes the gate session and clears the cookie.
func (p *Proxy) serveLogout(w http.ResponseWriter, r *http.Request, _ bool) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		p.writeError(w, r, http.StatusMethodNotAllowed, "invalid_request")
		return
	}
	if token := p.readSessionToken(r); token != "" {
		if err := p.auth.Logout(r.Context(), token); err != nil {
			p.recordError("logout: " + err.Error())
		}
	}
	p.clearSessionCookie(w, r)
	if wantsJSON(r) {
		writeJSON(w, http.StatusOK, map[string]any{"logged_out": true})
		return
	}
	http.Redirect(w, r, gateLoginPath, http.StatusSeeOther)
}

// randomToken returns a hex token with the requested number of random bytes.
func randomToken(bytesCount int) (string, error) {
	if bytesCount < 16 || bytesCount > 64 {
		return "", errors.New("httpproxy: invalid token size")
	}
	raw := make([]byte, bytesCount)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw), nil
}

func wantsJSON(r *http.Request) bool {
	return strings.Contains(strings.ToLower(r.Header.Get("Accept")), "application/json")
}

// requestClientIP extracts the source IP of the direct peer (never a header).
func requestClientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return ""
	}
	return host
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}
