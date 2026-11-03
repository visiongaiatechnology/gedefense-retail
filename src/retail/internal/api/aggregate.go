package api

import (
	"net/http"
	"sort"

	"github.com/visiongaiatechnology/gedefense/retail/internal/domain"
	"github.com/visiongaiatechnology/gedefense/retail/internal/ports"
)

// snapshotAlerts loads every stored alert. On failure it writes the 500 response
// and returns ok=false.
func (s *Server) snapshotAlerts(w http.ResponseWriter, r *http.Request) ([]domain.Alert, bool) {
	alerts, err := s.deps.Alerts.Snapshot(r.Context())
	if err != nil {
		s.logger.Error("snapshot alerts failed", "request_id", requestID(r), "error", err)
		s.fail(w, r, http.StatusInternalServerError, "internal", "internal server error")
		return nil, false
	}
	return alerts, true
}

// isActiveAlert reports whether an alert still needs operator attention.
func isActiveAlert(alert domain.Alert) bool {
	switch alert.Status {
	case domain.AlertOpen, domain.AlertAcknowledged, domain.AlertInvestigating:
		return true
	}
	return false
}

// siteAlertCounts aggregates the open alert load of one site.
type siteAlertCounts struct {
	Open     int
	Critical int
	High     int
}

// alertCountsBySite aggregates the active alerts per site.
func alertCountsBySite(alerts []domain.Alert) map[domain.SiteID]siteAlertCounts {
	out := make(map[domain.SiteID]siteAlertCounts)
	for _, alert := range alerts {
		if !isActiveAlert(alert) {
			continue
		}
		counts := out[alert.SiteID]
		counts.Open++
		switch alert.Severity {
		case domain.SeverityCritical:
			counts.Critical++
		case domain.SeverityHigh:
			counts.High++
		}
		out[alert.SiteID] = counts
	}
	return out
}

// alertCountsByCategory aggregates active alerts per site and category.
func alertCountsByCategory(alerts []domain.Alert) map[domain.SiteID]map[domain.Category]int {
	out := make(map[domain.SiteID]map[domain.Category]int)
	for _, alert := range alerts {
		if !isActiveAlert(alert) {
			continue
		}
		byCategory, ok := out[alert.SiteID]
		if !ok {
			byCategory = make(map[domain.Category]int, 4)
			out[alert.SiteID] = byCategory
		}
		byCategory[alert.Category]++
	}
	return out
}

// sortAlertsBySeverity orders alerts the way the operator contract requires:
// severity first, then most recent activity.
func sortAlertsBySeverity(alerts []domain.Alert) {
	sort.SliceStable(alerts, func(i, j int) bool {
		ri, rj := alerts[i].Severity.Rank(), alerts[j].Severity.Rank()
		if ri != rj {
			return ri > rj
		}
		if !alerts[i].LastSeenAt.Equal(alerts[j].LastSeenAt) {
			return alerts[i].LastSeenAt.After(alerts[j].LastSeenAt)
		}
		return alerts[i].AlertID < alerts[j].AlertID
	})
}

// filterAlerts applies the documented alert list filters.
func filterAlerts(alerts []domain.Alert, site domain.SiteID, status domain.AlertStatus, severity domain.Severity, category domain.Category) []domain.Alert {
	out := make([]domain.Alert, 0, len(alerts))
	for _, alert := range alerts {
		if site != "" && alert.SiteID != site {
			continue
		}
		if status != "" && alert.Status != status {
			continue
		}
		if severity != "" && alert.Severity != severity {
			continue
		}
		if category != "" && alert.Category != category {
			continue
		}
		out = append(out, alert)
	}
	return out
}

// paginate slices a page out of items and reports the total.
func paginate[T any](items []T, limit, offset int) ([]T, int) {
	total := len(items)
	if offset >= total {
		return []T{}, total
	}
	end := offset + limit
	if end > total {
		end = total
	}
	return items[offset:end], total
}

// collectorStateCounts counts running and failed collectors.
func collectorStateCounts(health []ports.CollectorHealth) (running, failed int) {
	for _, collector := range health {
		switch collector.State {
		case "running":
			running++
		case "failed":
			failed++
		}
	}
	return running, failed
}
