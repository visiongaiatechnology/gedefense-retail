package domain

import (
	"errors"
	"fmt"
	"strings"
)

// Identifier types. Distinct named types prevent accidental mixing of, for
// example, an AssetID with a SensorID. All identifiers are opaque, printable
// tokens created by GeDefense itself (or by the operator during onboarding);
// they are never derived from untrusted network input without validation.
type (
	EventID             string
	SiteID              string
	ZoneID              string
	AssetID             string
	SensorID            string
	AlertID             string
	IncidentID          string
	PolicyID            string
	MaintenanceWindowID string
	UserID              string
	RuleID              string
)

// ErrInvalidID is returned by every Validate method in this package family.
var ErrInvalidID = errors.New("invalid identifier")

const (
	maxIDLen     = 96
	idSeparators = "._:-/_"
)

// validID enforces a conservative allowlist: ASCII letters, digits and a small
// set of separators. This keeps identifiers safe for log lines, JSONL files,
// audit records and (future) SQL parameters without escaping rules.
func validID(kind, value string, allowSlash bool) error {
	if value == "" {
		return fmt.Errorf("%w: empty %s", ErrInvalidID, kind)
	}
	if len(value) > maxIDLen {
		return fmt.Errorf("%w: %s longer than %d bytes", ErrInvalidID, kind, maxIDLen)
	}
	for i := 0; i < len(value); i++ {
		c := value[i]
		switch {
		case c >= 'a' && c <= 'z':
		case c >= 'A' && c <= 'Z':
		case c >= '0' && c <= '9':
		case strings.ContainsRune(idSeparators, rune(c)):
			if c == '/' && !allowSlash {
				return fmt.Errorf("%w: %s contains '/'", ErrInvalidID, kind)
			}
		default:
			return fmt.Errorf("%w: %s contains forbidden byte %q", ErrInvalidID, kind, c)
		}
	}
	return nil
}

func (id EventID) Validate() error    { return validID("event_id", string(id), false) }
func (id SiteID) Validate() error     { return validID("site_id", string(id), false) }
func (id ZoneID) Validate() error     { return validID("zone_id", string(id), false) }
func (id AssetID) Validate() error    { return validID("asset_id", string(id), false) }
func (id SensorID) Validate() error   { return validID("sensor_id", string(id), false) }
func (id AlertID) Validate() error    { return validID("alert_id", string(id), false) }
func (id IncidentID) Validate() error { return validID("incident_id", string(id), false) }
func (id PolicyID) Validate() error   { return validID("policy_id", string(id), false) }
func (id MaintenanceWindowID) Validate() error {
	return validID("maintenance_window_id", string(id), false)
}
func (id UserID) Validate() error { return validID("user_id", string(id), false) }
func (id RuleID) Validate() error { return validID("rule_id", string(id), false) }

func (s SiteID) String() string     { return string(s) }
func (s AssetID) String() string    { return string(s) }
func (s SensorID) String() string   { return string(s) }
func (s AlertID) String() string    { return string(s) }
func (s ZoneID) String() string     { return string(s) }
func (s EventID) String() string    { return string(s) }
func (s PolicyID) String() string   { return string(s) }
func (s RuleID) String() string     { return string(s) }
func (s UserID) String() string     { return string(s) }
func (s IncidentID) String() string { return string(s) }
