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
