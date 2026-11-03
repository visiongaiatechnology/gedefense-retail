package api

import (
	"crypto/x509"
	"errors"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/visiongaiatechnology/gedefense/retail/internal/domain"
	"github.com/visiongaiatechnology/gedefense/retail/internal/gate/identity"
)

const bearerPrefix = "Bearer "

// sessionStore holds the management API sessions (token hash only). Sessions are
// deliberately in-memory: a gate restart logs operators out (fail-closed).
type sessionStore struct {
	mu     sync.Mutex
	byHash map[string]apiSession
	max    int
	now    func() time.Time
}

func newSessionStore(max int) *sessionStore {
	return &sessionStore{byHash: make(map[string]apiSession, 32), max: max, now: time.Now}
}

// create registers a new session and returns the plaintext bearer token once.
func (s *sessionStore) create(user domain.GateUser, mfaOK bool, ttl time.Duration, now time.Time) (string, apiSession, error) {
	token, err := newAPIToken()
	if err != nil {
		return "", apiSession{}, err
	}
	session := apiSession{
		TokenHash: tokenHash(token),
		User:      user,
		MFAOK:     mfaOK,
		ExpiresAt: now.Add(ttl),
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.byHash) >= s.max {
		s.pruneLocked(now)
		if len(s.byHash) >= s.max {
			return "", apiSession{}, errors.New("gate api: too many active sessions")
		}
	}
	s.byHash[session.TokenHash] = session
	return token, session, nil
}

// get returns an unexpired session.
func (s *sessionStore) get(token string, now time.Time) (apiSession, bool) {
	if token == "" {
		return apiSession{}, false
	}
	hash := tokenHash(token)
	s.mu.Lock()
	defer s.mu.Unlock()
	session, ok := s.byHash[hash]
	if !ok {
		return apiSession{}, false
	}
	if !now.Before(session.ExpiresAt) {
		delete(s.byHash, hash)
		return apiSession{}, false
	}
	return session, true
}

// revoke invalidates one session.
func (s *sessionStore) revoke(token string) {
	if token == "" {
		return
	}
	hash := tokenHash(token)
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.byHash, hash)
}

// count returns the number of active sessions.
func (s *sessionStore) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.byHash)
}

func (s *sessionStore) pruneLocked(now time.Time) {
	for hash, session := range s.byHash {
		if !now.Before(session.ExpiresAt) {
			delete(s.byHash, hash)
		}
	}
}

// bearerToken extracts the bearer token from the Authorization header.
func bearerToken(r *http.Request) string {
	header := r.Header.Get("Authorization")
	if len(header) <= len(bearerPrefix) {
		return ""
	}
	if !strings.EqualFold(header[:len(bearerPrefix)], bearerPrefix) {
		return ""
	}
	token := strings.TrimSpace(header[len(bearerPrefix):])
	if token == "" || len(token) > 256 || strings.ContainsAny(token, " \t\r\n,") {
		return ""
	}
	return token
}

// authenticate resolves the bearer session of a request.
func (s *Server) authenticate(r *http.Request) (apiSession, bool) {
	return s.sessions.get(bearerToken(r), s.now())
}

// deviceFingerprint returns the SHA-256 of the presented client certificate.
func deviceFingerprint(r *http.Request) string {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return ""
	}
	return identity.CertificateFingerprint(r.TLS.PeerCertificates[0])
}

// verifyMFAHeader validates the X-Gate-MFA code for a step-up action.
func (s *Server) verifyMFAHeader(r *http.Request, session apiSession) error {
	code := strings.TrimSpace(r.Header.Get("X-Gate-MFA"))
	if code == "" {
		return identity.ErrMFARequired
	}
	return s.deps.Identity.VerifyMFA(r.Context(), session.User.UserID, code)
}

// ensure x509 stays referenced by the mTLS helper documentation above.
var _ = x509.Certificate{}
