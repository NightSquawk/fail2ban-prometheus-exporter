package server

import (
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

func healthHandler(w http.ResponseWriter, r *http.Request, collector *f2b.Collector) {
	if collector.IsHealthy() {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("{\"healthy\":true}"))
	} else {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("{\"healthy\":false}"))
	}
}
