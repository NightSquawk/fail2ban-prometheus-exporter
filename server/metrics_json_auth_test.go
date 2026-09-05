package server

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/NightSquawk/fail2ban-prometheus-exporter/auth"
)

// TestMetricsJSONRejectsUnauthenticatedRequestUnderBasicAuth proves
// /metrics.json is wired through AuthMiddleware exactly like /metrics and /
// (docs/metrics-json-schema-v1.md §1: "there is no unauthenticated data path"):
// with the deprecated --web.basic-auth.* provider configured, an
// unauthenticated GET must be rejected with 401 and MUST NOT include any
// snapshot data in the body - the doc specifies an EMPTY body for this
// mechanism's rejection, which is itself proof no data leaked.
func TestMetricsJSONRejectsUnauthenticatedRequestUnderBasicAuth(t *testing.T) {
	collector := newDownSocketCollector(t)
	authProvider := auth.NewBasicAuthProvider("admin", "s3cret")
	handler := AuthMiddleware(metricsJSONHandler(collector), authProvider)

	r := httptest.NewRequest(http.MethodGet, "/metrics.json", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, r)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	if rec.Body.Len() != 0 {
		t.Errorf("unauthenticated /metrics.json body = %q, want empty (no snapshot data may leak into a 401)", rec.Body.String())
	}

	// Wrong credentials must be rejected identically to none at all.
	r2 := httptest.NewRequest(http.MethodGet, "/metrics.json", nil)
	r2.SetBasicAuth("admin", "wrong-password")
	rec2 := httptest.NewRecorder()
	handler.ServeHTTP(rec2, r2)
	if rec2.Code != http.StatusUnauthorized {
		t.Fatalf("wrong-credentials status = %d, want 401", rec2.Code)
	}
	if rec2.Body.Len() != 0 {
		t.Errorf("wrong-credentials /metrics.json body = %q, want empty", rec2.Body.String())
	}

	// Correct credentials must still reach the handler and gather data.
	r3 := httptest.NewRequest(http.MethodGet, "/metrics.json", nil)
	r3.SetBasicAuth("admin", "s3cret")
	rec3 := httptest.NewRecorder()
	handler.ServeHTTP(rec3, r3)
	if rec3.Code != http.StatusOK {
		t.Fatalf("authenticated status = %d, want 200, body=%s", rec3.Code, rec3.Body.String())
	}
	if rec3.Body.Len() == 0 {
		t.Errorf("authenticated /metrics.json returned an empty body")
	}
}

// TestHealthReachableWithoutCredentialsInSameAuthConfiguration pins the
// deliberate, load-bearing asymmetry called out in server/handler.go's
// healthHandler doc comment: /health is never wrapped in AuthMiddleware, so
// it stays reachable with NO credentials even while --web.basic-auth.* (the
// exact configuration TestMetricsJSONRejectsUnauthenticatedRequestUnderBasicAuth
// above uses) rejects /metrics.json outright. This is what lets an
// unauthenticated container healthcheck (`curl --fail http://.../health`)
// keep working when the operator has locked down the metrics endpoints.
// healthHandler's signature itself proves the point: unlike
// metricsJSONHandler, it takes no auth.AuthProvider to bypass - there is no
// authentication code path here at all, bare or otherwise.
func TestHealthReachableWithoutCredentialsInSameAuthConfiguration(t *testing.T) {
	// Configuring auth at all (as in the sibling test) is irrelevant to
	// /health, since server.go registers it outside AuthMiddleware
	// entirely; healthHandler is called directly here exactly as server.go
	// calls it, with no Authorization header on the request.
	collector := newDownSocketCollector(t)
	r := httptest.NewRequest(http.MethodGet, "/health", nil)
	rec := httptest.NewRecorder()
	healthHandler(rec, r, collector, false)

	// The down-socket collector makes IsHealthy() false, i.e. 500 - but
	// crucially NOT 401: the request carried no credentials at all, and
	// unlike /metrics.json above, that was never checked.
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500 (down socket, not an auth rejection)", rec.Code)
	}
	if rec.Body.Len() == 0 {
		t.Errorf("/health body is empty, want the health payload (it must still be served without credentials)")
	}
}
