package api

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/visiongaiatechnology/gedefense/retail/internal/i18n"
)

// errorBody decodes the contract error envelope of a test response.
func errorBody(t *testing.T, recorder *httptest.ResponseRecorder) apiErrorEnvelope {
	t.Helper()
	var envelope apiErrorEnvelope
	if err := json.Unmarshal(recorder.Body.Bytes(), &envelope); err != nil {
		t.Fatalf("decode error envelope: %v (body %q)", err, recorder.Body.String())
	}
	return envelope
}

func TestErrorResponseLocalization(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		lang    i18n.Language
		headers map[string]string
	}{
		{"german", i18n.German, map[string]string{"Accept-Language": "de-DE,de;q=0.9,en;q=0.5"}},
		{"french", i18n.French, map[string]string{"Accept-Language": "fr"}},
		{"italian", i18n.Italian, map[string]string{"Accept-Language": "it-IT"}},
		{"spanish", i18n.Spanish, map[string]string{"Accept-Language": "es"}},
		{"japanese", i18n.Japanese, map[string]string{"Accept-Language": "ja-JP"}},
		{"chinese", i18n.Chinese, map[string]string{"Accept-Language": "zh-Hans-CN"}},
		{"russian", i18n.Russian, map[string]string{"Accept-Language": "ru"}},
	}
	harness := newAPIHarness(t, apiTestOptions{})
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			recorder := harness.do(t, http.MethodGet, "/api/v1/does-not-exist", nil, "", tc.headers)
			if recorder.Code != http.StatusNotFound {
				t.Fatalf("status = %d, want 404 (status must be locale independent)", recorder.Code)
			}
			envelope := errorBody(t, recorder)
			if envelope.Error.Code != "not_found" {
				t.Fatalf("code = %q, want machine-stable not_found", envelope.Error.Code)
			}
			want := i18n.Code(tc.lang, "not_found")
			if envelope.Error.Message != want {
				t.Fatalf("message = %q, want %q", envelope.Error.Message, want)
			}
			if envelope.Error.RequestID == "" {
				t.Fatal("request id missing")
			}
			if got := recorder.Header().Get("Vary"); !strings.Contains(got, "Accept-Language") {
				t.Fatalf("Vary = %q, want Accept-Language", got)
			}
		})
	}
}

func TestErrorLocalizationPrecedence(t *testing.T) {
	t.Parallel()
	harness := newAPIHarness(t, apiTestOptions{})
	cases := []struct {
		name     string
		target   string
		headers  map[string]string
		want     i18n.Language
		wantCode string
		wantHTTP int
	}{
		{
			name:    "query beats header",
			target:  "/api/v1/nope?lang=ja",
			headers: map[string]string{"Accept-Language": "de", "X-Lang": "ru"},
			want:    i18n.Japanese, wantCode: "not_found", wantHTTP: http.StatusNotFound,
		},
		{
			name:    "x-lang beats accept-language",
			target:  "/api/v1/nope",
			headers: map[string]string{"Accept-Language": "de", "X-Lang": "ru"},
			want:    i18n.Russian, wantCode: "not_found", wantHTTP: http.StatusNotFound,
		},
		{
			name:    "invalid query falls back to accept-language",
			target:  "/api/v1/nope?lang=xx",
			headers: map[string]string{"Accept-Language": "fr"},
			want:    i18n.French, wantCode: "not_found", wantHTTP: http.StatusNotFound,
		},
		{
			name:    "invalid x-lang and accept-language fall back to default",
			target:  "/api/v1/nope",
			headers: map[string]string{"Accept-Language": "pt-BR,xx", "X-Lang": "bogus"},
			want:    i18n.English, wantCode: "not_found", wantHTTP: http.StatusNotFound,
		},
		{
			name:    "wildcard falls back to default",
			target:  "/api/v1/nope",
			headers: map[string]string{"Accept-Language": "*"},
			want:    i18n.English, wantCode: "not_found", wantHTTP: http.StatusNotFound,
		},
		{
			name:    "q values order languages",
			target:  "/api/v1/nope",
			headers: map[string]string{"Accept-Language": "de;q=0.2, fr;q=0.9"},
			want:    i18n.French, wantCode: "not_found", wantHTTP: http.StatusNotFound,
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			recorder := harness.do(t, http.MethodGet, tc.target, nil, "", tc.headers)
			if recorder.Code != tc.wantHTTP {
				t.Fatalf("status = %d, want %d", recorder.Code, tc.wantHTTP)
			}
			envelope := errorBody(t, recorder)
			if envelope.Error.Code != tc.wantCode {
				t.Fatalf("code = %q, want %q", envelope.Error.Code, tc.wantCode)
			}
			if tc.want == i18n.English {
				// English keeps the precise contract detail (backward compatible).
				if envelope.Error.Message != "resource not found" {
					t.Fatalf("english message = %q", envelope.Error.Message)
				}
				return
			}
			if want := i18n.Code(tc.want, tc.wantCode); envelope.Error.Message != want {
				t.Fatalf("message = %q, want %q", envelope.Error.Message, want)
			}
		})
	}
}

func TestUnauthorizedAndForbiddenLocalized(t *testing.T) {
	t.Parallel()
	harness := newAPIHarness(t, apiTestOptions{})
	deHeaders := map[string]string{"Accept-Language": "de"}

	unauthorized := harness.do(t, http.MethodGet, "/api/v1/sites", nil, "", deHeaders)
	if unauthorized.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", unauthorized.Code)
	}
	envelope := errorBody(t, unauthorized)
	if envelope.Error.Code != "unauthorized" || envelope.Error.Message != i18n.Code(i18n.German, "unauthorized") {
		t.Fatalf("unauthorized envelope = %+v", envelope.Error)
	}

	forbidden := harness.do(t, http.MethodPost, "/api/v1/policies/reload", map[string]any{}, viewerToken, deHeaders)
	if forbidden.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", forbidden.Code)
	}
	envelope = errorBody(t, forbidden)
	if envelope.Error.Code != "forbidden" || envelope.Error.Message != i18n.Code(i18n.German, "forbidden") {
		t.Fatalf("forbidden envelope = %+v", envelope.Error)
	}
}

func TestInvalidRequestLocalized(t *testing.T) {
	t.Parallel()
	harness := newAPIHarness(t, apiTestOptions{})
	recorder := newJSONRequest(t, http.MethodPost, "/api/v1/windows", `{"not":`, adminToken)
	recorder.Header.Set("Accept-Language", "fr")
	response := harness.serve(recorder)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", response.Code)
	}
	envelope := errorBody(t, response)
	if envelope.Error.Code != "invalid_request" {
		t.Fatalf("code = %q", envelope.Error.Code)
	}
	if envelope.Error.Message != i18n.Code(i18n.French, "invalid_request") {
		t.Fatalf("message = %q", envelope.Error.Message)
	}
	// English keeps the precise detail for clients that depend on it.
	englishRequest := newJSONRequest(t, http.MethodPost, "/api/v1/windows", `{"not":`, adminToken)
	english := harness.serve(englishRequest)
	englishEnvelope := errorBody(t, english)
	if englishEnvelope.Error.Code != "invalid_request" || !strings.Contains(englishEnvelope.Error.Message, "malformed JSON") {
		t.Fatalf("english invalid_request = %+v", englishEnvelope.Error)
	}
}

func TestDefaultLanguageHook(t *testing.T) {
	t.Parallel()
	harness := newAPIHarness(t, apiTestOptions{})
	harness.server.SetDefaultLanguage("de")
	recorder := harness.do(t, http.MethodGet, "/api/v1/does-not-exist", nil, "", nil)
	envelope := errorBody(t, recorder)
	if envelope.Error.Message != i18n.Code(i18n.German, "not_found") {
		t.Fatalf("default-language message = %q", envelope.Error.Message)
	}
	harness.server.SetDefaultLanguage("unsupported")
	recorder = harness.do(t, http.MethodGet, "/api/v1/does-not-exist", nil, "", nil)
	envelope = errorBody(t, recorder)
	if envelope.Error.Message != "resource not found" {
		t.Fatalf("invalid default language must fall back to English, got %q", envelope.Error.Message)
	}
}

func TestHealthAndMetaStayMachineReadable(t *testing.T) {
	t.Parallel()
	harness := newAPIHarness(t, apiTestOptions{simulation: true})
	deHeaders := map[string]string{"Accept-Language": "de"}
	health := harness.do(t, http.MethodGet, "/api/v1/health", nil, "", deHeaders)
	if health.Code != http.StatusOK {
		t.Fatalf("health status = %d", health.Code)
	}
	var healthPayload map[string]any
	if err := json.Unmarshal(health.Body.Bytes(), &healthPayload); err != nil {
		t.Fatalf("health JSON: %v", err)
	}
	if healthPayload["status"] != "ok" || healthPayload["product"] != "GeDefense Retail" || healthPayload["read_only"] != true {
		t.Fatalf("health payload changed for non-English request: %+v", healthPayload)
	}
	meta := harness.do(t, http.MethodGet, "/api/v1/meta", nil, viewerToken, deHeaders)
	if meta.Code != http.StatusOK {
		t.Fatalf("meta status = %d", meta.Code)
	}
	var metaPayload map[string]any
	if err := json.Unmarshal(meta.Body.Bytes(), &metaPayload); err != nil {
		t.Fatalf("meta JSON: %v", err)
	}
	if metaPayload["product"] != "GeDefense Retail" || metaPayload["http_api"] != "v1" {
		t.Fatalf("meta payload changed for non-English request: %+v", metaPayload)
	}
}

func TestWhitelistDenyLocalizedWithoutContext(t *testing.T) {
	t.Parallel()
	server := &Server{defaultLanguage: i18n.German, logger: slog.Default()}
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.RemoteAddr = "10.99.0.5:4321"
	recorder := httptest.NewRecorder()
	// The whitelist middleware rejects before baseMW installs the language in the
	// context; fail must still localize from the request headers.
	server.fail(recorder, request, http.StatusForbidden, "ip_not_allowed", "access denied")
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("status = %d", recorder.Code)
	}
	envelope := errorBody(t, recorder)
	if envelope.Error.Code != "ip_not_allowed" {
		t.Fatalf("code = %q", envelope.Error.Code)
	}
	if envelope.Error.Message != i18n.Code(i18n.German, "ip_not_allowed") {
		t.Fatalf("message = %q", envelope.Error.Message)
	}
	if got := recorder.Header().Get("Vary"); !strings.Contains(got, "Accept-Language") {
		t.Fatalf("Vary = %q", got)
	}
}

func TestSetupCodesLocalized(t *testing.T) {
	t.Parallel()
	codes := []string{"ip_not_allowed", "setup_required", "setup_conflict", "unauthorized", "unknown_code"}
	for _, code := range codes {
		for _, lang := range i18n.SupportedLanguages() {
			message := localizedError(lang, code, "fallback detail")
			if strings.TrimSpace(message) == "" {
				t.Fatalf("%q/%q: empty message", lang, code)
			}
			if lang == i18n.English {
				if message != "fallback detail" {
					t.Fatalf("english/%q must keep caller detail, got %q", code, message)
				}
				continue
			}
			want := i18n.Code(lang, code)
			if message != want {
				t.Fatalf("%q/%q message = %q, want %q", lang, code, message, want)
			}
		}
	}
}

func TestErrorBodiesContainNoSecrets(t *testing.T) {
	t.Parallel()
	harness := newAPIHarness(t, apiTestOptions{})
	for _, lang := range i18n.SupportedLanguages() {
		recorder := harness.do(t, http.MethodGet, "/api/v1/does-not-exist", nil, "",
			map[string]string{"Accept-Language": string(lang)})
		body := strings.ToLower(recorder.Body.String())
		for _, forbidden := range []string{"bearer ", "token=", "password", "-----begin", "hmac"} {
			if strings.Contains(body, forbidden) {
				t.Fatalf("%q error body contains %q: %s", lang, forbidden, recorder.Body.String())
			}
		}
	}
}
