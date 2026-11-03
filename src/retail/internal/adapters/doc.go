// Package adapters is the home of the passive protocol collectors.
//
// The package itself contains no production code on purpose: every adapter is
// a separate subpackage. The safety test suite lives here because it checks all
// adapter packages at once (no write capability, no active scan, read-only
// Info contract). See internal/adapters/safety_test.go.
package adapters
