package api

import (
	"net/http"
	"strconv"
	"testing"

	"github.com/visiongaiatechnology/gedefense/retail/internal/domain"
	"github.com/visiongaiatechnology/gedefense/retail/internal/ports"
)

// testDevEvent builds a valid telemetry event for the simulator ingest path.
func testDevEvent(id string) domain.Event {
	return domain.Event{
		EventID:    domain.EventID(id),
		Kind:       domain.EventTelemetry,
		SiteID:     "filiale-001",
		ZoneID:     "zone-ot",
		AssetID:    "asset-1",
		SensorID:   "sensor-1",
		ObservedAt: baseTime,
		ReceivedAt: baseTime,
		Source:     "retail-sim",
		Collection: "passive_tap",
		Protocol:   "modbus_tcp",
		Confidence: 0.9,
		Measurement: &domain.Measurement{
			Value: 4.2, Unit: domain.UnitCelsius, Quality: domain.QualityGood,
			Metric: "air_temperature", ObservedAt: baseTime,
		},
	}
}

func simHeaders() map[string]string { return map[string]string{"X-GeDefense-Sim": "1"} }

func TestDevIngestGuardsReturn404(t *testing.T) {
	body := map[string]any{"events": []domain.Event{testDevEvent("evt-1")}}

	// Simulation disabled: 404 even for a fully privileged loopback client.
	disabled := newAPIHarness(t, apiTestOptions{simulation: false})
	if recorder := disabled.do(t, http.MethodPost, "/api/v1/dev/events", body, adminToken, simHeaders()); recorder.Code != http.StatusNotFound {
		t.Errorf("simulation disabled = %d, want 404", recorder.Code)
	}

	// Missing simulator header: 404.
	enabled := newAPIHarness(t, apiTestOptions{simulation: true})
	if recorder := enabled.do(t, http.MethodPost, "/api/v1/dev/events", body, adminToken, nil); recorder.Code != http.StatusNotFound {
		t.Errorf("missing sim header = %d, want 404", recorder.Code)
	}
	// Wrong header value: 404.
	if recorder := enabled.do(t, http.MethodPost, "/api/v1/dev/events", body, adminToken, map[string]string{"X-GeDefense-Sim": "0"}); recorder.Code != http.StatusNotFound {
		t.Errorf("wrong sim header = %d, want 404", recorder.Code)
	}
	// Non-loopback peer: 404.
	if recorder := enabled.doRemote(t, http.MethodPost, "/api/v1/dev/events", body, adminToken, "10.0.0.9:52344", simHeaders()); recorder.Code != http.StatusNotFound {
		t.Errorf("remote peer = %d, want 404", recorder.Code)
	}
	// No token: 401 only after every simulation guard passed.
	if recorder := enabled.do(t, http.MethodPost, "/api/v1/dev/events", body, "", simHeaders()); recorder.Code != http.StatusUnauthorized {
		t.Errorf("missing token = %d, want 401", recorder.Code)
	}
	// Operator token: 403.
	if recorder := enabled.do(t, http.MethodPost, "/api/v1/dev/events", body, operatorToken, simHeaders()); recorder.Code != http.StatusForbidden {
		t.Errorf("operator token = %d, want 403", recorder.Code)
	}
}

func TestDevIngestAcceptsValidBatch(t *testing.T) {
	h := newAPIHarness(t, apiTestOptions{simulation: true})
	body := map[string]any{"events": []domain.Event{testDevEvent("evt-1"), testDevEvent("evt-2")}}
	recorder := h.do(t, http.MethodPost, "/api/v1/dev/events", body, adminToken, simHeaders())
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
	result := decode[devIngestResponse](t, recorder)
	if result.Accepted != 2 || result.Rejected != 0 || len(result.Errors) != 0 {
		t.Fatalf("result = %+v", result)
	}
	if h.registry.Health().EventsIngested != 2 {
		t.Errorf("registry events = %d, want 2", h.registry.Health().EventsIngested)
	}
	if h.events.Count() != 2 {
		t.Errorf("stored events = %d, want 2", h.events.Count())
	}
	recent := h.registry.Events(ports.EventQuery{Limit: 2})
	if len(recent) != 2 {
		t.Errorf("registry recent = %d, want 2", len(recent))
	}
}

func TestDevIngestRejectsInvalidEvents(t *testing.T) {
	h := newAPIHarness(t, apiTestOptions{simulation: true})
	broken := testDevEvent("evt-broken")
	broken.Measurement = nil
	body := map[string]any{"events": []domain.Event{testDevEvent("evt-ok"), broken}}
	recorder := h.do(t, http.MethodPost, "/api/v1/dev/events", body, adminToken, simHeaders())
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
	result := decode[devIngestResponse](t, recorder)
	if result.Accepted != 1 || result.Rejected != 1 {
		t.Fatalf("result = %+v", result)
	}
	if len(result.Errors) != 1 || result.Errors[0].Index != 1 || result.Errors[0].Reason == "" {
		t.Errorf("errors = %+v", result.Errors)
	}
	if h.events.Count() != 1 {
		t.Errorf("stored events = %d, want 1", h.events.Count())
	}
}

func TestDevIngestBatchBounds(t *testing.T) {
	h := newAPIHarness(t, apiTestOptions{simulation: true})
	if recorder := h.do(t, http.MethodPost, "/api/v1/dev/events", map[string]any{"events": []domain.Event{}}, adminToken, simHeaders()); recorder.Code != http.StatusBadRequest {
		t.Errorf("empty batch = %d, want 400", recorder.Code)
	}
	oversized := make([]domain.Event, maxDevEvents+1)
	for i := range oversized {
		oversized[i] = testDevEvent("evt-" + strconv.Itoa(i))
	}
	if recorder := h.do(t, http.MethodPost, "/api/v1/dev/events", map[string]any{"events": oversized}, adminToken, simHeaders()); recorder.Code != http.StatusBadRequest {
		t.Errorf("oversized batch = %d, want 400", recorder.Code)
	}
}

func TestDevIngestStrictJSON(t *testing.T) {
	h := newAPIHarness(t, apiTestOptions{simulation: true})
	req := newJSONRequest(t, http.MethodPost, "/api/v1/dev/events", `{"events":[],"extra":true}`, adminToken)
	req.Header.Set("X-GeDefense-Sim", "1")
	recorder := h.serve(req)
	if recorder.Code != http.StatusBadRequest {
		t.Errorf("unknown field = %d, want 400", recorder.Code)
	}
}
