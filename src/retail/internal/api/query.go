package api

import (
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/visiongaiatechnology/gedefense/retail/internal/domain"
)

// query collects and validates the parameters of one GET request. Unknown
// parameters are rejected: silently ignoring a filter would show the operator
// more data than requested.
type query struct {
	values url.Values
	err    error
}

// parseQuery validates the parameter names of the request.
func parseQuery(r *http.Request, allowed ...string) *query {
	values := r.URL.Query()
	allowedSet := make(map[string]struct{}, len(allowed))
	for _, name := range allowed {
		allowedSet[name] = struct{}{}
	}
	for name := range values {
		if _, ok := allowedSet[name]; !ok {
			return &query{values: values, err: fmt.Errorf("unknown query parameter %q", name)}
		}
	}
	return &query{values: values}
}

// str returns a trimmed parameter value.
func (q *query) str(name string) string { return strings.TrimSpace(q.values.Get(name)) }

// setError records the first validation error.
func (q *query) setError(err error) {
	if q.err == nil {
		q.err = err
	}
}

// intValue parses a bounded integer parameter.
func (q *query) intValue(name string, defaultValue, minimum, maximum int) int {
	if q.err != nil {
		return defaultValue
	}
	raw := q.str(name)
	if raw == "" {
		return defaultValue
	}
	value, err := strconv.Atoi(raw)
	if err != nil {
		q.setError(fmt.Errorf("%s must be an integer", name))
		return defaultValue
	}
	if value < minimum || value > maximum {
		q.setError(fmt.Errorf("%s must be between %d and %d", name, minimum, maximum))
		return defaultValue
	}
	return value
}

// limit returns the validated page size.
func (q *query) limit() int { return q.intValue("limit", defaultListLimit, 1, maxListLimit) }

// offset returns the validated page offset.
func (q *query) offset() int { return q.intValue("offset", 0, 0, 1_000_000) }

// timeValue parses an optional RFC 3339 timestamp.
func (q *query) timeValue(name string) time.Time {
	if q.err != nil {
		return time.Time{}
	}
	raw := q.str(name)
	if raw == "" {
		return time.Time{}
	}
	parsed, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		q.setError(fmt.Errorf("%s must be an RFC 3339 timestamp", name))
		return time.Time{}
	}
	return parsed.UTC()
}

// textValue returns a bounded free-text parameter.
func (q *query) textValue(name string, maxLen int) string {
	if q.err != nil {
		return ""
	}
	raw := q.str(name)
	if len(raw) > maxLen {
		q.setError(fmt.Errorf("%s must be at most %d characters", name, maxLen))
		return ""
	}
	return raw
}

// idValue returns a parameter that must be a valid identifier of kind.
func (q *query) idValue(name string, validate func(string) error) string {
	if q.err != nil {
		return ""
	}
	raw := q.str(name)
	if raw == "" {
		return ""
	}
	if err := validate(raw); err != nil {
		q.setError(fmt.Errorf("%s is not a valid identifier", name))
		return ""
	}
	return raw
}

// checkQuery writes a 400 response when validation failed.
func (s *Server) checkQuery(w http.ResponseWriter, r *http.Request, q *query) bool {
	if q.err == nil {
		return true
	}
	s.fail(w, r, http.StatusBadRequest, "invalid_request", q.err.Error())
	return false
}

// enumValue validates a string against an allowlist.
func (q *query) enumValue(name string, allowed []string) string {
	if q.err != nil {
		return ""
	}
	raw := q.str(name)
	if raw == "" {
		return ""
	}
	for _, candidate := range allowed {
		if candidate == raw {
			return raw
		}
	}
	q.setError(fmt.Errorf("%s must be one of %s", name, strings.Join(allowed, ", ")))
	return ""
}

// parseSeverityParameter parses and validates a severity parameter.
func (q *query) parseSeverity(name string) domain.Severity {
	raw := q.enumValue(name, []string{
		string(domain.SeverityInfo), string(domain.SeverityLow), string(domain.SeverityMedium),
		string(domain.SeverityHigh), string(domain.SeverityCritical),
	})
	return domain.Severity(raw)
}

// parseStatusParameter parses and validates an alert status parameter.
func (q *query) parseStatus(name string) domain.AlertStatus {
	raw := q.enumValue(name, []string{
		string(domain.AlertOpen), string(domain.AlertAcknowledged), string(domain.AlertInvestigating),
		string(domain.AlertResolved), string(domain.AlertClosed), string(domain.AlertFalsePositive),
	})
	return domain.AlertStatus(raw)
}

// parseCategoryParameter parses and validates an alert category parameter.
func (q *query) parseCategory(name string) domain.Category {
	raw := q.enumValue(name, []string{
		string(domain.CategoryAccess), string(domain.CategoryNetwork), string(domain.CategoryThermal),
		string(domain.CategoryIntegrity), string(domain.CategoryDeviceHealth), string(domain.CategoryDataQuality),
	})
	return domain.Category(raw)
}

// parseAssetTypeParameter parses and validates an asset type parameter.
func (q *query) parseAssetType(name string) domain.AssetType {
	raw := q.enumValue(name, []string{
		string(domain.AssetRefrigerationController), string(domain.AssetPL), string(domain.AssetHMI),
		string(domain.AssetSensorGateway), string(domain.AssetBMS), string(domain.AssetNetworkDevice),
		string(domain.AssetEdgeGateway), string(domain.AssetCoolingRack), string(domain.AssetColdRoom),
		string(domain.AssetUnknown),
	})
	return domain.AssetType(raw)
}

// validateSiteID validates a site identifier parameter.
func validateSiteID(id string) error { return domain.SiteID(id).Validate() }

// validateZoneID validates a zone identifier parameter.
func validateZoneID(id string) error { return domain.ZoneID(id).Validate() }

// validateSensorID validates a sensor identifier parameter.
func validateSensorID(id string) error { return domain.SensorID(id).Validate() }
