// Package httpproxy implements the HTTP(S) reverse proxy of the Access Gate.
//
// Every request must carry a valid gate login session. Read methods are
// forwarded after login; write methods additionally require an approved
// WriteSession whose plan matches the URL path AND the SHA-256 of the request
// body. Denied writes never reach the device: the proxy answers 403 and reports
// domain.DeniedWriteAttempt to the gate core.
package httpproxy

import (
	"fmt"
	"strings"
)

// maxPatternLen bounds one URL allowlist pattern.
const maxPatternLen = 256

// allowlist enforces the target's write path allowlist. Only exact paths and
// trailing-prefix entries are supported; there are no regular expressions.
type allowlist struct {
	patterns []string
}

// newAllowlist validates and compiles the patterns.
func newAllowlist(patterns []string) (*allowlist, error) {
	compiled := make([]string, 0, len(patterns))
	for _, raw := range patterns {
		pattern := strings.TrimSpace(raw)
		if err := validatePattern(pattern); err != nil {
			return nil, err
		}
		compiled = append(compiled, pattern)
	}
	return &allowlist{patterns: compiled}, nil
}

func validatePattern(pattern string) error {
	if pattern == "" || len(pattern) > maxPatternLen {
		return fmt.Errorf("httpproxy: url_allowlist pattern length must be 1..%d", maxPatternLen)
	}
	if !strings.HasPrefix(pattern, "/") {
		return fmt.Errorf("httpproxy: url_allowlist pattern %q must start with '/'", pattern)
	}
	for i := 0; i < len(pattern); i++ {
		c := pattern[i]
		if c < 0x20 || c == 0x7f || c == '\\' || c == '?' || c == '#' {
			return fmt.Errorf("httpproxy: url_allowlist pattern %q contains a forbidden character", pattern)
		}
	}
	if strings.Contains(pattern, "*") {
		if !strings.HasSuffix(pattern, "*") || strings.Count(pattern, "*") != 1 {
			return fmt.Errorf("httpproxy: url_allowlist pattern %q may only use a single trailing '*'", pattern)
		}
	}
	for _, segment := range strings.Split(pattern, "/") {
		if segment == ".." {
			return fmt.Errorf("httpproxy: url_allowlist pattern %q must not contain '..'", pattern)
		}
	}
	return nil
}

// Match reports whether the request path is allowed by the write allowlist.
// The path must already be validated by canonicalWritePath.
func (a *allowlist) Match(path string) bool {
	if a == nil {
		return false
	}
	for _, pattern := range a.patterns {
		if strings.HasSuffix(pattern, "*") {
			if strings.HasPrefix(path, strings.TrimSuffix(pattern, "*")) {
				return true
			}
			continue
		}
		if path == pattern {
			return true
		}
	}
	return false
}

// Len returns the number of patterns (tests/diagnostics).
func (a *allowlist) Len() int {
	if a == nil {
		return 0
	}
	return len(a.patterns)
}

// canonicalWritePath validates a request path used as plan address. Query
// strings are deliberately excluded from the plan address (Alpha limitation,
// documented in the engineering contract): plans authorise a path, the values
// are bound through the body hash.
func canonicalWritePath(path string) (string, error) {
	if path == "" || len(path) > maxPatternLen {
		return "", fmt.Errorf("httpproxy: path length must be 1..%d", maxPatternLen)
	}
	if !strings.HasPrefix(path, "/") {
		return "", fmt.Errorf("httpproxy: path must start with '/'")
	}
	for i := 0; i < len(path); i++ {
		c := path[i]
		if c < 0x20 || c == 0x7f || c == '\\' {
			return "", fmt.Errorf("httpproxy: path contains a forbidden character")
		}
	}
	for _, segment := range strings.Split(path, "/") {
		if segment == ".." {
			return "", fmt.Errorf("httpproxy: path contains a traversal segment")
		}
	}
	if path != "/" && strings.HasSuffix(path, "/") {
		path = strings.TrimRight(path, "/")
		if path == "" {
			path = "/"
		}
	}
	return path, nil
}
