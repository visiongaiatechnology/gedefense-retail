package api

import (
	"net/http"
	"time"

	"github.com/visiongaiatechnology/gedefense/retail/internal/domain"
	"github.com/visiongaiatechnology/gedefense/retail/internal/ports"
)

// storageHealth is the storage block of the health response.
type storageHealth struct {
	Events       int64 `json:"events"`
	Alerts       int   `json:"alerts"`
	AuditChainOK bool  `json:"audit_chain_ok"`
	// AuditCheckedAt is the time of the verification the flag is based on. The
	// verification is cached for a bounded TTL so an unauthenticated probe cannot
	// force an O(audit-log) scan per request.
	AuditCheckedAt time.Time `json:"audit_checked_at,omitempty"`
}

// healthResponse is the public health payload.
type healthResponse struct {
	Status     string                  `json:"status"`
	Product    string                  `json:"product"`
	Version    string                  `json:"version"`
	Commit     string                  `json:"commit"`
	BuildDate  string                  `json:"build_date"`
	Now        time.Time               `json:"now"`
	UptimeS    int64                   `json:"uptime_s"`
	ReadOnly   bool                    `json:"read_only"`
	Storage    storageHealth           `json:"storage"`
	Collectors []ports.CollectorHealth `json:"collectors"`
}

// handleHealth serves GET /api/v1/health. It is the only unauthenticated
// endpoint: an orchestrator must be able to probe liveness without a token.
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request, _ params, _ identity) {
	ctx := r.Context()
	alertCount, err := s.deps.Alerts.Count(ctx)
	if err != nil {
		s.logger.Error("health: count alerts failed", "request_id", requestID(r), "error", err)
		s.fail(w, r, http.StatusInternalServerError, "internal", "internal server error")
		return
	}
	auditOK := true
	chain := s.auditChain.Status(ctx)
	if chain.Err != nil {
		s.logger.Error("health: audit verify failed", "request_id", requestID(r), "error", chain.Err)
		auditOK = false
	} else {
		auditOK = chain.OK
	}

	status := "ok"
	if !auditOK {
		status = "degraded"
	}
	s.respondJSON(w, r, http.StatusOK, healthResponse{
		Status:    status,
		Product:   s.deps.Version.Product,
		Version:   s.deps.Version.Version,
		Commit:    s.deps.Version.Commit,
		BuildDate: s.deps.Version.BuildDate,
		Now:       time.Now().UTC(),
		UptimeS:   int64(time.Since(s.started).Seconds()),
		ReadOnly:  true,
		Storage: storageHealth{
			Events:         s.deps.Events.Count(),
			Alerts:         alertCount,
			AuditChainOK:   auditOK,
			AuditCheckedAt: chain.CheckedAt,
		},
		Collectors: s.collectorHealth(),
	})
}

// metaCapabilities is the capability block of the meta response.
type metaCapabilities struct {
	ReadOnly   bool     `json:"read_only"`
	Simulation bool     `json:"simulation"`
	Protocols  []string `json:"protocols"`
	NotInMVP   []string `json:"not_in_mvp"`
}

// metaResponse describes the product and its deliberate limits.
type metaResponse struct {
	Product      string           `json:"product"`
	Edition      string           `json:"edition"`
	Version      string           `json:"version"`
	HTTPAPI      string           `json:"http_api"`
	Capabilities metaCapabilities `json:"capabilities"`
	Roles        []string         `json:"roles"`
}

// handleMeta serves GET /api/v1/meta.
func (s *Server) handleMeta(w http.ResponseWriter, r *http.Request, _ params, _ identity) {
	s.respondJSON(w, r, http.StatusOK, metaResponse{
		Product: s.deps.Version.Product,
		Edition: s.deps.Version.Edition,
		Version: s.deps.Version.Version,
		HTTPAPI: s.deps.Version.HTTPAPI,
		Capabilities: metaCapabilities{
			ReadOnly:   true,
			Simulation: s.deps.SimulationEnabled,
			Protocols:  []string{"modbus_tcp", "mqtt", "bacnet_ip", "snmp", "pcap"},
			NotInMVP:   []string{"opc_ua", "snmp_v3", "lonworks", "active_discovery", "plc_write"},
		},
		Roles: []string{"viewer", "operator", "admin"},
	})
}

// overviewTotals is the fleet summary of the overview response.
type overviewTotals struct {
	Sites             int `json:"sites"`
	Assets            int `json:"assets"`
	Sensors           int `json:"sensors"`
	OpenAlerts        int `json:"open_alerts"`
	Critical          int `json:"critical"`
	High              int `json:"high"`
	CollectorsRunning int `json:"collectors_running"`
	CollectorsFailed  int `json:"collectors_failed"`
	Peers             int `json:"peers"`
}

// overviewColdchain is the cold-chain block of one site.
type overviewColdchain struct {
	Sensors           int `json:"sensors"`
	LimitViolations   int `json:"limit_violations"`
	DataQualityIssues int `json:"data_quality_issues"`
}

// overviewGateway is the gateway block of one site.
type overviewGateway struct {
	LastEventAt time.Time `json:"last_event_at,omitempty"`
	Status      string    `json:"status"`
}

// overviewSite is one site row of the overview response.
type overviewSite struct {
	Site        domain.Site       `json:"site"`
	SiteStatus  domain.SiteStatus `json:"site_status"`
	Assets      int               `json:"assets"`
	OpenAlerts  int               `json:"open_alerts"`
	Critical    int               `json:"critical"`
	High        int               `json:"high"`
	LastEventAt time.Time         `json:"last_event_at,omitempty"`
	Coldchain   overviewColdchain `json:"coldchain"`
	Gateway     overviewGateway   `json:"gateway"`
}

// overviewResponse is the dashboard landing payload.
type overviewResponse struct {
	GeneratedAt  time.Time               `json:"generated_at"`
	Totals       overviewTotals          `json:"totals"`
	Sites        []overviewSite          `json:"sites"`
	RecentAlerts []domain.Alert          `json:"recent_alerts"`
	Collectors   []ports.CollectorHealth `json:"collectors"`
}

// handleOverview serves GET /api/v1/overview.
func (s *Server) handleOverview(w http.ResponseWriter, r *http.Request, _ params, _ identity) {
	ctx := r.Context()
	alerts, err := s.deps.Alerts.Snapshot(ctx)
	if err != nil {
		s.logger.Error("overview: snapshot alerts failed", "request_id", requestID(r), "error", err)
		s.fail(w, r, http.StatusInternalServerError, "internal", "internal server error")
		return
	}
	sites := s.deps.Sites.Sites()
	health := s.deps.Sites.Health()
	assetCounts := s.deps.Sites.AssetCountsBySite()
	sensorCounts := s.deps.Sites.SensorCountsBySite()
	alertCounts := alertCountsBySite(alerts)
	categoryCounts := alertCountsByCategory(alerts)
	collectors := s.collectorHealth()
	running, failed := collectorStateCounts(collectors)

	rows := make([]overviewSite, 0, len(sites))
	totals := overviewTotals{
		Sites:             len(sites),
		Assets:            health.Assets,
		Sensors:           health.Sensors,
		Peers:             health.Peers,
		CollectorsRunning: running,
		CollectorsFailed:  failed,
	}
	for _, site := range sites {
		counts := alertCounts[site.SiteID]
		byCategory := categoryCounts[site.SiteID]
		rows = append(rows, overviewSite{
			Site:        site,
			SiteStatus:  site.Status,
			Assets:      assetCounts[site.SiteID],
			OpenAlerts:  counts.Open,
			Critical:    counts.Critical,
			High:        counts.High,
			LastEventAt: site.LastSeenAt,
			Coldchain: overviewColdchain{
				Sensors:           sensorCounts[site.SiteID],
				LimitViolations:   byCategory[domain.CategoryThermal],
				DataQualityIssues: byCategory[domain.CategoryDataQuality],
			},
			Gateway: overviewGateway{
				LastEventAt: site.LastSeenAt,
				Status:      string(site.Status),
			},
		})
		totals.OpenAlerts += counts.Open
		totals.Critical += counts.Critical
		totals.High += counts.High
	}

	sorted := append([]domain.Alert(nil), alerts...)
	sortAlertsBySeverity(sorted)
	recent := sorted
	if len(recent) > 10 {
		recent = recent[:10]
	}

	s.respondJSON(w, r, http.StatusOK, overviewResponse{
		GeneratedAt:  time.Now().UTC(),
		Totals:       totals,
		Sites:        rows,
		RecentAlerts: recent,
		Collectors:   collectors,
	})
}

// collectorsResponse is the collector list payload.
type collectorsResponse struct {
	Items []ports.CollectorHealth `json:"items"`
}

// handleCollectors serves GET /api/v1/collectors.
func (s *Server) handleCollectors(w http.ResponseWriter, r *http.Request, _ params, _ identity) {
	s.respondJSON(w, r, http.StatusOK, collectorsResponse{Items: s.collectorHealth()})
}
