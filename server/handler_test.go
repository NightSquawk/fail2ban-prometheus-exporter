package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestScrapeTimeout(t *testing.T) {
	tests := []struct {
		name   string
		header string
		want   time.Duration
		wantOK bool
	}{
		{"absent", "", 0, false},
		{"whole seconds", "10", 10 * time.Second, true},
		{"fractional", "2.5", 2500 * time.Millisecond, true},
		{"unparseable", "soon", 0, false},
		{"zero", "0", 0, false},
		{"negative", "-1", 0, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/metrics", nil)
			if tt.header != "" {
				r.Header.Set(scrapeTimeoutHeader, tt.header)
			}
			got, ok := scrapeTimeout(r)
			if ok != tt.wantOK || got != tt.want {
				t.Errorf("scrapeTimeout() = (%v, %v), want (%v, %v)", got, ok, tt.want, tt.wantOK)
			}
		})
	}
}

// TestMetricsHandlerServesWithAndWithoutTimeoutHeader checks both branches of
// the handler produce a normal exposition response.
func TestMetricsHandlerServesWithAndWithoutTimeoutHeader(t *testing.T) {
	handler := metricsHandler()

	for _, header := range []string{"", "10"} {
		r := httptest.NewRequest(http.MethodGet, "/metrics", nil)
		if header != "" {
			r.Header.Set(scrapeTimeoutHeader, header)
		}
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, r)

		if rec.Code != http.StatusOK {
			t.Errorf("%s header %q: status = %d, want 200", scrapeTimeoutHeader, header, rec.Code)
		}
	}
}

// doHealth exercises healthHandler directly against a down-socket collector
// (newDownSocketCollector, defined in metrics_json_test.go), so IsHealthy()
// deterministically returns false without a fake fail2ban server. That is
// enough to pin down both response shapes and the status/Content-Type
// contract; IsHealthy()'s own true/false behaviour is covered in
// collector/f2b/health_test.go.
func doHealth(t *testing.T, minimal bool) *httptest.ResponseRecorder {
	t.Helper()
	collector := newDownSocketCollector(t)
	r := httptest.NewRequest(http.MethodGet, "/health", nil)
	rec := httptest.NewRecorder()
	healthHandler(rec, r, collector, minimal)
	return rec
}

// TestHealthHandlerReportsIdentityByDefault is the M3 default: /health's body
// grows exporter name and version, matching newDownSocketCollector's
// BuildInfo{Version: "test", ...} verbatim, alongside the unchanged 500-on-
// unhealthy status.
func TestHealthHandlerReportsIdentityByDefault(t *testing.T) {
	rec := doHealth(t, false)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d (down socket)", rec.Code, http.StatusInternalServerError)
	}
	if got := rec.Header().Get("Content-Type"); got != healthContentType {
		t.Errorf("Content-Type = %q, want %q", got, healthContentType)
	}
	want := `{"healthy":false,"exporter":"fail2ban-prometheus-exporter","version":"test"}`
	if got := rec.Body.String(); got != want {
		t.Errorf("body = %q, want %q", got, want)
	}
}

// TestHealthHandlerMinimalOmitsIdentity is --web.health.minimal: the body
// must be exactly the old bare shape, byte for byte, with only the
// Content-Type header changed.
func TestHealthHandlerMinimalOmitsIdentity(t *testing.T) {
	rec := doHealth(t, true)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d (down socket)", rec.Code, http.StatusInternalServerError)
	}
	if got := rec.Header().Get("Content-Type"); got != healthContentType {
		t.Errorf("Content-Type = %q, want %q", got, healthContentType)
	}
	want := `{"healthy":false}`
	if got := rec.Body.String(); got != want {
		t.Errorf("body = %q, want %q", got, want)
	}
}
