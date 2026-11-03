package api

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/visiongaiatechnology/gedefense/retail/internal/domain"
)

func TestPolicyEndpoints(t *testing.T) {
	h := newAPIHarness(t, apiTestOptions{})

	recorder := h.do(t, http.MethodGet, "/api/v1/policies", nil, viewerToken, nil)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
	policies := decode[policiesResponse](t, recorder)
	if policies.Current.Version != 1 || policies.Current.Hash == "" {
		t.Errorf("current = %+v", policies.Current)
	}
	if len(policies.Versions) != 1 || policies.Versions[0].Version != 1 {
		t.Errorf("versions = %+v", policies.Versions)
	}

	reload := h.do(t, http.MethodPost, "/api/v1/policies/reload", nil, adminToken, nil)
	if reload.Code != http.StatusOK {
		t.Fatalf("reload = %d, body = %s", reload.Code, reload.Body.String())
	}
	reloaded := decode[policyVersionResponse](t, reload)
	if reloaded.Version.Policy.Version != 2 {
		t.Errorf("reloaded version = %d, want 2", reloaded.Version.Policy.Version)
	}

	versionPath := "/api/v1/policies/filiale-001/versions/1"
	if recorder = h.do(t, http.MethodGet, versionPath, nil, viewerToken, nil); recorder.Code != http.StatusOK {
		t.Errorf("version 1 = %d, want 200", recorder.Code)
	}
	if recorder = h.do(t, http.MethodGet, "/api/v1/policies/filiale-001/versions/99", nil, viewerToken, nil); recorder.Code != http.StatusNotFound {
		t.Errorf("missing version = %d, want 404", recorder.Code)
	}
	if recorder = h.do(t, http.MethodGet, "/api/v1/policies/filiale-999/versions/1", nil, viewerToken, nil); recorder.Code != http.StatusNotFound {
		t.Errorf("wrong site = %d, want 404", recorder.Code)
	}
	if recorder = h.do(t, http.MethodGet, "/api/v1/policies?site_id=filiale-999", nil, viewerToken, nil); recorder.Code != http.StatusNotFound {
		t.Errorf("site mismatch = %d, want 404", recorder.Code)
	}
	if recorder = h.do(t, http.MethodGet, "/api/v1/policies/filiale-001/versions/abc", nil, viewerToken, nil); recorder.Code != http.StatusBadRequest {
		t.Errorf("invalid version = %d, want 400", recorder.Code)
	}
}

func TestAuditEndpointAndChain(t *testing.T) {
	h := newAPIHarness(t, apiTestOptions{})
	body := map[string]any{
		"vendor": "ServiceCo", "starts_at": baseTime.Format(time.RFC3339), "ends_at": baseTime.Add(2 * time.Hour).Format(time.RFC3339),
	}
	recorder := h.do(t, http.MethodPost, "/api/v1/windows", body, adminToken, nil)
	if recorder.Code != http.StatusOK {
		t.Fatalf("window create = %d, body = %s", recorder.Code, recorder.Body.String())
	}
	created := decode[windowResponse](t, recorder)
	if created.Window.WindowID == "" || !strings.HasPrefix(string(created.Window.WindowID), "win_") {
		t.Errorf("window = %+v", created.Window)
	}
	if created.Window.Status != domain.WindowPlanned || created.Window.CreatedBy != "admin" {
		t.Errorf("window defaults = %+v", created.Window)
	}
	closeRecorder := h.do(t, http.MethodPost, "/api/v1/windows/"+string(created.Window.WindowID)+"/close", map[string]string{"note": "done"}, adminToken, nil)
	if closeRecorder.Code != http.StatusOK {
		t.Fatalf("window close = %d, body = %s", closeRecorder.Code, closeRecorder.Body.String())
	}
	closed := decode[windowResponse](t, closeRecorder)
	if closed.Window.Status != domain.WindowClosed {
		t.Errorf("closed window = %+v", closed.Window)
	}
	if again := h.do(t, http.MethodPost, "/api/v1/windows/"+string(created.Window.WindowID)+"/close", map[string]string{}, adminToken, nil); again.Code != http.StatusConflict {
		t.Errorf("second close = %d, want 409", again.Code)
	}
	if missing := h.do(t, http.MethodPost, "/api/v1/windows/win-missing/close", map[string]string{}, adminToken, nil); missing.Code != http.StatusNotFound {
		t.Errorf("missing window = %d, want 404", missing.Code)
	}

	audit := decode[auditResponse](t, h.do(t, http.MethodGet, "/api/v1/audit", nil, viewerToken, nil))
	if !audit.ChainOK {
		t.Error("audit chain is not ok")
	}
	if len(audit.Items) != 2 {
		t.Fatalf("audit entries = %d, want 2", len(audit.Items))
	}
	if audit.Items[0].Action != "window.create" || audit.Items[1].Action != "window.close" {
		t.Errorf("audit actions = %+v", audit.Items)
	}
	if audit.FirstVerifiedSeq != 1 {
		t.Errorf("first verified seq = %d, want 1", audit.FirstVerifiedSeq)
	}
	limited := decode[auditResponse](t, h.do(t, http.MethodGet, "/api/v1/audit?limit=1", nil, viewerToken, nil))
	if len(limited.Items) != 1 || limited.Items[0].Action != "window.close" {
		t.Errorf("limited audit = %+v", limited.Items)
	}
}

func TestIncidentEndpoints(t *testing.T) {
	h := newAPIHarness(t, apiTestOptions{})
	h.seedAlert(t, "alr-1", "dedup-1", "high", "Temperature above limit")
	incident := domain.Incident{
		IncidentID:  "inc-1",
		SiteID:      "filiale-001",
		Title:       "Possible thermal manipulation",
		Severity:    domain.SeverityCritical,
		Status:      domain.IncidentOpen,
		AlertIDs:    []domain.AlertID{"alr-1"},
		ZoneIDs:     []domain.ZoneID{"zone-ot"},
		AssetIDs:    []domain.AssetID{"asset-1"},
		FirstSeenAt: baseTime,
		LastSeenAt:  baseTime,
		Summary:     "Three independent indicators matched within 30 minutes.",
		CreatedAt:   baseTime,
		UpdatedAt:   baseTime,
	}
	if err := h.registry.UpsertIncident(incident); err != nil {
		t.Fatalf("upsert incident: %v", err)
	}

	list := decode[incidentsResponse](t, h.do(t, http.MethodGet, "/api/v1/incidents", nil, viewerToken, nil))
	if list.Total != 1 || list.Items[0].IncidentID != "inc-1" {
		t.Fatalf("incidents = %+v", list)
	}
	open := decode[incidentsResponse](t, h.do(t, http.MethodGet, "/api/v1/incidents?status=open", nil, viewerToken, nil))
	if open.Total != 1 {
		t.Errorf("status filter = %+v", open)
	}
	other := decode[incidentsResponse](t, h.do(t, http.MethodGet, "/api/v1/incidents?site_id=filiale-999", nil, viewerToken, nil))
	if other.Total != 0 {
		t.Errorf("site filter = %+v", other)
	}

	detail := decode[incidentDetailResponse](t, h.do(t, http.MethodGet, "/api/v1/incidents/inc-1", nil, viewerToken, nil))
	if detail.Incident.IncidentID != "inc-1" || len(detail.Alerts) != 1 {
		t.Errorf("detail = %+v", detail)
	}

	note := h.do(t, http.MethodPost, "/api/v1/incidents/inc-1/note", map[string]string{"note": "Betreiber kontaktiert"}, operatorToken, nil)
	if note.Code != http.StatusOK {
		t.Fatalf("note = %d, body = %s", note.Code, note.Body.String())
	}
	after := decode[incidentDetailResponse](t, h.do(t, http.MethodGet, "/api/v1/incidents/inc-1", nil, viewerToken, nil))
	if len(after.Incident.Notes) != 1 {
		t.Errorf("notes = %+v", after.Incident.Notes)
	}
	if forbidden := h.do(t, http.MethodPost, "/api/v1/incidents/inc-1/note", map[string]string{"note": "x"}, viewerToken, nil); forbidden.Code != http.StatusForbidden {
		t.Errorf("viewer note = %d, want 403", forbidden.Code)
	}
	if invalid := h.do(t, http.MethodPost, "/api/v1/incidents/inc-1/note", map[string]string{"note": ""}, operatorToken, nil); invalid.Code != http.StatusBadRequest {
		t.Errorf("empty note = %d, want 400", invalid.Code)
	}

	export := h.do(t, http.MethodGet, "/api/v1/incidents/inc-1/export", nil, viewerToken, nil)
	if export.Code != http.StatusOK {
		t.Fatalf("export = %d, body = %s", export.Code, export.Body.String())
	}
	if disposition := export.Header().Get("Content-Disposition"); !strings.Contains(disposition, "attachment") || !strings.Contains(disposition, "inc-1") {
		t.Errorf("Content-Disposition = %q", disposition)
	}
	bundle := decode[domain.IncidentExport](t, export)
	if bundle.Incident.IncidentID != "inc-1" || len(bundle.Constraints) != 2 {
		t.Errorf("export = %+v", bundle)
	}
	if recorder := h.do(t, http.MethodGet, "/api/v1/incidents/inc-missing", nil, viewerToken, nil); recorder.Code != http.StatusNotFound {
		t.Errorf("missing incident = %d, want 404", recorder.Code)
	}
}

func TestTimelineEndpoint(t *testing.T) {
	h := newAPIHarness(t, apiTestOptions{})
	h.seedEvent(t, telemetryEvent("evt-1", baseTime, "sensor-1", 4.2))
	h.seedAlert(t, "alr-1", "dedup-1", "high", "Temperature above limit")

	query := url.Values{}
	query.Set("since", baseTime.Add(-time.Hour).Format(time.RFC3339))
	recorder := h.do(t, http.MethodGet, "/api/v1/timeline?"+query.Encode(), nil, viewerToken, nil)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
	timeline := decode[timelineResponse](t, recorder)
	if timeline.Total < 2 || len(timeline.Items) < 2 {
		t.Fatalf("timeline = %+v", timeline)
	}
	kinds := make(map[string]bool, 2)
	for _, item := range timeline.Items {
		kinds[item.Kind] = true
	}
	if !kinds["alert"] || !kinds["event"] {
		t.Errorf("timeline kinds = %+v", kinds)
	}
	if !timeline.Items[0].At.After(timeline.Items[len(timeline.Items)-1].At) && timeline.Items[0].At != timeline.Items[len(timeline.Items)-1].At {
		t.Errorf("timeline not sorted newest first: %+v", timeline.Items)
	}
}

func TestIntegrityEndpoint(t *testing.T) {
	h := newAPIHarness(t, apiTestOptions{})
	integrityEvent := domain.Event{
		EventID:    "evt-integrity",
		Kind:       domain.EventIntegrity,
		SiteID:     "filiale-001",
		ZoneID:     "zone-ot",
		AssetID:    "asset-1",
		ObservedAt: baseTime,
		ReceivedAt: baseTime,
		Source:     "operator-export",
		Collection: "operator_export",
		Confidence: 1,
		Integrity: &domain.IntegrityMeta{
			Subject: "controller_parameters", Version: "2.4", SHA256: "abcdef",
			Changed: true, Approved: false,
		},
	}
	h.seedEvent(t, integrityEvent)

	recorder := h.do(t, http.MethodGet, "/api/v1/integrity?site_id=filiale-001", nil, viewerToken, nil)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
	integrity := decode[integrityResponse](t, recorder)
	if len(integrity.Items) != 1 {
		t.Fatalf("items = %+v", integrity.Items)
	}
	item := integrity.Items[0]
	if item.Subject != "controller_parameters" || item.Version != "2.4" || !item.Changed || item.Approved {
		t.Errorf("integrity item = %+v", item)
	}
	if len(integrity.Changes) != 1 || integrity.Changes[0].Subject != "controller_parameters" {
		t.Errorf("changes = %+v", integrity.Changes)
	}
}

func TestAccessEndpoint(t *testing.T) {
	h := newAPIHarness(t, apiTestOptions{})
	h.seedEvent(t, accessEvent("evt-access", baseTime, "ses-1"))
	body := map[string]any{
		"vendor": "ServiceCo", "starts_at": baseTime.Add(time.Hour).Format(time.RFC3339),
		"ends_at": baseTime.Add(2 * time.Hour).Format(time.RFC3339),
	}
	if recorder := h.do(t, http.MethodPost, "/api/v1/windows", body, adminToken, nil); recorder.Code != http.StatusOK {
		t.Fatalf("window create = %d", recorder.Code)
	}

	query := url.Values{}
	query.Set("site_id", "filiale-001")
	query.Set("since", baseTime.Add(-time.Hour).Format(time.RFC3339))
	recorder := h.do(t, http.MethodGet, "/api/v1/access?"+query.Encode(), nil, viewerToken, nil)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
	access := decode[accessResponse](t, recorder)
	if len(access.Windows) != 1 || len(access.Sessions) != 1 {
		t.Fatalf("access = %+v", access)
	}
	if access.Sessions[0].SessionID != "ses-1" || access.Sessions[0].Vendor != "ServiceCo" {
		t.Errorf("session = %+v", access.Sessions[0])
	}
	if len(access.Anomalies) != 0 {
		t.Errorf("anomalies = %+v", access.Anomalies)
	}
}

// accessEvent builds a passive maintenance access event.
func accessEvent(id string, at time.Time, session string) domain.Event {
	return domain.Event{
		EventID:    domain.EventID(id),
		Kind:       domain.EventAccess,
		SiteID:     "filiale-001",
		ObservedAt: at,
		ReceivedAt: at,
		Source:     "pcap.tap",
		Collection: "passive_tap",
		Confidence: 0.8,
		Access: &domain.AccessMeta{
			Vendor: "ServiceCo", User: "tech-1", Method: "vpn",
			TargetAsset: "asset-1", SessionID: session, InWindow: false,
		},
	}
}
