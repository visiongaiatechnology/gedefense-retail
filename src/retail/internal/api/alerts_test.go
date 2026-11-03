package api

import (
	"context"
	"net/http"
	"testing"

	"github.com/visiongaiatechnology/gedefense/retail/internal/domain"
)

func TestAlertListFiltersAndOrdering(t *testing.T) {
	h := newAPIHarness(t, apiTestOptions{})
	h.seedAlert(t, "alr-medium", "dedup-medium", "medium", "Medium alert")
	h.seedAlert(t, "alr-critical", "dedup-critical", "critical", "Critical alert")

	recorder := h.do(t, http.MethodGet, "/api/v1/alerts", nil, viewerToken, nil)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
	list := decode[listEnvelope[domain.Alert]](t, recorder)
	if list.Total != 2 || len(list.Items) != 2 {
		t.Fatalf("alerts = %+v", list)
	}
	if list.Items[0].AlertID != "alr-critical" {
		t.Errorf("severity ordering = %+v", list.Items)
	}

	critical := decode[listEnvelope[domain.Alert]](t, h.do(t, http.MethodGet, "/api/v1/alerts?severity=critical", nil, viewerToken, nil))
	if critical.Total != 1 {
		t.Errorf("severity filter = %+v", critical)
	}
	open := decode[listEnvelope[domain.Alert]](t, h.do(t, http.MethodGet, "/api/v1/alerts?status=open", nil, viewerToken, nil))
	if open.Total != 2 {
		t.Errorf("status filter = %+v", open)
	}
	none := decode[listEnvelope[domain.Alert]](t, h.do(t, http.MethodGet, "/api/v1/alerts?site_id=filiale-999", nil, viewerToken, nil))
	if none.Total != 0 || len(none.Items) != 0 {
		t.Errorf("site filter = %+v", none)
	}
	paged := decode[listEnvelope[domain.Alert]](t, h.do(t, http.MethodGet, "/api/v1/alerts?limit=1", nil, viewerToken, nil))
	if paged.Total != 2 || len(paged.Items) != 1 {
		t.Errorf("limit = %+v", paged)
	}
}

func TestAlertDetailWithEvidenceEvents(t *testing.T) {
	h := newAPIHarness(t, apiTestOptions{})
	h.seedEvent(t, telemetryEvent("evt-1", baseTime, "sensor-1", 9.1))
	h.seedAlert(t, "alr-1", "dedup-1", "high", "Temperature above limit")

	recorder := h.do(t, http.MethodGet, "/api/v1/alerts/alr-1", nil, viewerToken, nil)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
	detail := decode[alertDetailResponse](t, recorder)
	if detail.Alert.AlertID != "alr-1" {
		t.Errorf("alert = %+v", detail.Alert)
	}
	if len(detail.EvidenceEvents) != 1 || detail.EvidenceEvents[0].EventID != "evt-1" {
		t.Errorf("evidence events = %+v", detail.EvidenceEvents)
	}

	if recorder = h.do(t, http.MethodGet, "/api/v1/alerts/alr-missing", nil, viewerToken, nil); recorder.Code != http.StatusNotFound {
		t.Errorf("missing alert = %d, want 404", recorder.Code)
	}
}

func TestAlertWorkflowThroughAPI(t *testing.T) {
	h := newAPIHarness(t, apiTestOptions{})
	h.seedAlert(t, "alr-1", "dedup-1", "high", "Temperature above limit")

	ack := h.do(t, http.MethodPost, "/api/v1/alerts/alr-1/ack", map[string]string{"note": "Betreiber informiert"}, operatorToken, nil)
	if ack.Code != http.StatusOK {
		t.Fatalf("ack = %d, body = %s", ack.Code, ack.Body.String())
	}
	acked := decode[alertResponse](t, ack)
	if acked.Alert.Status != domain.AlertAcknowledged {
		t.Errorf("ack status = %q", acked.Alert.Status)
	}

	assign := h.do(t, http.MethodPost, "/api/v1/alerts/alr-1/assign", map[string]string{"assignee": "operator-1", "note": "Kälte Nord"}, operatorToken, nil)
	if assign.Code != http.StatusOK {
		t.Fatalf("assign = %d, body = %s", assign.Code, assign.Body.String())
	}
	assigned := decode[alertResponse](t, assign)
	if assigned.Alert.Assignee != "operator-1" {
		t.Errorf("assignee = %q", assigned.Alert.Assignee)
	}

	closeResp := h.do(t, http.MethodPost, "/api/v1/alerts/alr-1/close", map[string]string{"status": "false_positive", "note": "Türöffnung 12 min"}, operatorToken, nil)
	if closeResp.Code != http.StatusOK {
		t.Fatalf("close = %d, body = %s", closeResp.Code, closeResp.Body.String())
	}
	closed := decode[alertResponse](t, closeResp)
	if closed.Alert.Status != domain.AlertFalsePositive {
		t.Errorf("close status = %q", closed.Alert.Status)
	}

	// The three operator actions are hash-chain audited.
	entries, err := h.audit.List(context.Background(), 10)
	if err != nil {
		t.Fatalf("audit list: %v", err)
	}
	if len(entries) != 3 {
		t.Fatalf("audit entries = %d, want 3", len(entries))
	}
	ok, _, err := h.audit.Verify(context.Background())
	if err != nil || !ok {
		t.Fatalf("audit chain = %v, %v", ok, err)
	}
}

func TestAlertWorkflowErrors(t *testing.T) {
	h := newAPIHarness(t, apiTestOptions{})
	h.seedAlert(t, "alr-1", "dedup-1", "high", "Temperature above limit")

	unknownAssignee := h.do(t, http.MethodPost, "/api/v1/alerts/alr-1/assign", map[string]string{"assignee": "ghost-user"}, operatorToken, nil)
	if unknownAssignee.Code != http.StatusBadRequest {
		t.Errorf("unknown assignee = %d, want 400", unknownAssignee.Code)
	}
	invalidStatus := h.do(t, http.MethodPost, "/api/v1/alerts/alr-1/close", map[string]string{"status": "open"}, operatorToken, nil)
	if invalidStatus.Code != http.StatusBadRequest {
		t.Errorf("invalid close status = %d, want 400", invalidStatus.Code)
	}
	missing := h.do(t, http.MethodPost, "/api/v1/alerts/alr-missing/ack", map[string]string{"note": ""}, operatorToken, nil)
	if missing.Code != http.StatusNotFound {
		t.Errorf("missing alert = %d, want 404", missing.Code)
	}
	if recorder := h.do(t, http.MethodPost, "/api/v1/alerts/alr-1/close", map[string]string{"status": "resolved"}, operatorToken, nil); recorder.Code != http.StatusOK {
		t.Fatalf("first close = %d", recorder.Code)
	}
	conflict := h.do(t, http.MethodPost, "/api/v1/alerts/alr-1/ack", map[string]string{"note": "late"}, operatorToken, nil)
	if conflict.Code != http.StatusConflict {
		t.Errorf("ack after close = %d, want 409", conflict.Code)
	}
}
