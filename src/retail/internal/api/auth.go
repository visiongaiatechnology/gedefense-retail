package api

import (
	"crypto/sha256"
	"crypto/subtle"
	"net"
	"net/http"
	"strings"

	"github.com/visiongaiatechnology/gedefense/retail/internal/config"
	"github.com/visiongaiatechnology/gedefense/retail/internal/domain"
)

const bearerPrefix = "Bearer "

// identity is the authenticated caller of a request.
type identity struct {
	UserID    domain.UserID
	Name      string
	Role      config.Role
	tokenHash string
}

// authenticate extracts and verifies the bearer token. The comparison of the
// SHA-256 digest is constant time and iterates over every configured user, so the
// response time does not depend on which user matched.
func (s *Server) authenticate(r *http.Request) (identity, bool) {
	header := r.Header.Get("Authorization")
	if header == "" || len(header) <= len(bearerPrefix) {
		return identity{}, false
	}
	if !strings.EqualFold(header[:len(bearerPrefix)], bearerPrefix) {
		return identity{}, false
	}
	token := strings.TrimSpace(header[len(bearerPrefix):])
	if token == "" || len(token) > maxTokenLength || strings.ContainsAny(token, " \t\r\n,") {
		return identity{}, false
	}
	digest := sha256.Sum256([]byte(token))

	matched := -1
	for i := range s.users {
		if subtle.ConstantTimeCompare(digest[:], s.users[i].hash[:]) == 1 && matched < 0 {
			matched = i
		}
	}
	if matched < 0 {
		return identity{}, false
	}
	user := s.users[matched].user
	return identity{
		UserID:    user.UserID,
		Name:      user.Name,
		Role:      user.Role,
		tokenHash: strings.ToLower(user.TokenSHA256),
	}, true
}

// userExists reports whether the identifier belongs to a configured user. It is
// used to validate alert assignees.
func (s *Server) userExists(id domain.UserID) bool {
	for _, record := range s.users {
		if record.user.UserID == id {
			return true
		}
	}
	return false
}

// clientIP returns the address of the direct peer. Forwarding headers are
// deliberately ignored: the gateway is deployed behind a local reverse proxy that
// rewrites the peer address, and trusting untrusted headers would break the
// loopback guard of the simulator ingest.
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// isLoopbackClient reports whether the request originates from this host.
func isLoopbackClient(r *http.Request) bool {
	return config.IsLoopbackHost(clientIP(r))
}
