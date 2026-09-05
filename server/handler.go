package server

import (
	"encoding/json"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/NightSquawk/fail2ban-prometheus-exporter/collector/f2b"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

const (
	metricsPath = "/metrics"
	// scrapeTimeoutHeader is set by Prometheus on every scrape and carries the
	// job's scrape_timeout.
	scrapeTimeoutHeader = "X-Prometheus-Scrape-Timeout-Seconds"
)

func rootHtmlHandler(w http.ResponseWriter, r *http.Request) {
	_, err := w.Write([]byte(
		`<html>
			<head><title>Fail2Ban Exporter</title></head>
			<body>
			<h1>Fail2Ban Exporter</h1>
			<p><a href="` + metricsPath + `">Metrics</a></p>
			</body>
		</html>`))
	if err != nil {
		log.Printf("error handling root url: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
	}
}

func handlerOpts() promhttp.HandlerOpts {
	return promhttp.HandlerOpts{
		ErrorLog: log.Default(),
		// A single malformed textfile metric family should cost that family, not
		// the whole scrape.
		ErrorHandling: promhttp.ContinueOnError,
	}
}

// metricsHandler serves /metrics, bounding the gather by the scrape timeout
// Prometheus advertises so a slow collector returns 503 instead of holding the
// scrape connection open indefinitely.
func metricsHandler() http.HandlerFunc {
	base := promhttp.HandlerFor(prometheus.DefaultGatherer, handlerOpts())
	return func(w http.ResponseWriter, r *http.Request) {
		timeout, ok := scrapeTimeout(r)
		if !ok {
			base.ServeHTTP(w, r)
			return
		}
		opts := handlerOpts()
		opts.Timeout = timeout
		promhttp.HandlerFor(prometheus.DefaultGatherer, opts).ServeHTTP(w, r)
	}
}

func scrapeTimeout(r *http.Request) (time.Duration, bool) {
	raw := r.Header.Get(scrapeTimeoutHeader)
	if raw == "" {
		return 0, false
	}
	seconds, err := strconv.ParseFloat(raw, 64)
	if err != nil || seconds <= 0 {
		log.Printf("ignoring invalid %s header value %q", scrapeTimeoutHeader, raw)
		return 0, false
	}
	return time.Duration(seconds * float64(time.Second)), true
}

// healthContentType is set on every /health response, in both modes below.
const healthContentType = "application/json; charset=utf-8"

// healthResponse is the bare {"healthy":bool} body served when
// --web.health.minimal is set.
type healthResponse struct {
	Healthy bool `json:"healthy"`
}

// healthResponseWithIdentity is the default /health body: bare health plus
// exporter identity, so an operator hitting the endpoint learns what is
// actually running there. A distinct type from healthResponse - rather than
// one struct with `omitempty` identity fields - so the minimal shape stays
// exactly {"healthy":bool} regardless of what Exporter/Version happen to
// hold at runtime (an omitempty field would also vanish on a genuinely empty
// version string, silently reproducing the minimal shape when identity
// reporting was actually requested).
type healthResponseWithIdentity struct {
	Healthy  bool   `json:"healthy"`
	Exporter string `json:"exporter"`
	Version  string `json:"version"`
}

// healthHandler serves /health. It is registered bare in server.go, never
// wrapped in AuthMiddleware: the container healthcheck shim (./health, baked
// into both Dockerfile and Dockerfile.goreleaser) is an unauthenticated
// `curl --fail` that keys entirely on the HTTP status, so this endpoint must
// stay reachable with no credentials and must keep returning exactly 200
// (healthy) or 500 (unhealthy) - never anything else on the unhealthy path.
//
// By default the body also reports exporter identity (name + version);
// minimal restores the old bare {"healthy":bool} shape for operators who
// consider the version string a disclosure on an unauthenticated endpoint
// (--web.health.minimal).
func healthHandler(w http.ResponseWriter, r *http.Request, collector *f2b.Collector, minimal bool) {
	healthy := collector.IsHealthy()

	// Marshal into a buffer before writing the status, the same discipline
	// /metrics.json uses (server/metrics_json.go): a serialisation failure
	// must never leave a 200/500 half-written on the wire.
	var body []byte
	var err error
	if minimal {
		body, err = json.Marshal(healthResponse{Healthy: healthy})
	} else {
		name, version := collector.Identity()
		body, err = json.Marshal(healthResponseWithIdentity{
			Healthy:  healthy,
			Exporter: name,
			Version:  version,
		})
	}
	if err != nil {
		// Both shapes above are fixed, simple values (a bool and up to two
		// plain strings) that cannot fail to marshal in practice; fall back
		// to the bare shape rather than send nothing.
		log.Printf("health: failed to marshal response: %v", err)
		body, _ = json.Marshal(healthResponse{Healthy: healthy})
	}

	w.Header().Set("Content-Type", healthContentType)
	if healthy {
		w.WriteHeader(http.StatusOK)
	} else {
		w.WriteHeader(http.StatusInternalServerError)
	}
	_, _ = w.Write(body)
}
