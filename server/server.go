package server

import (
	"log"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/NightSquawk/fail2ban-prometheus-exporter/cfg"
	"github.com/NightSquawk/fail2ban-prometheus-exporter/collector/f2b"
	"github.com/prometheus/exporter-toolkit/web"
)

func StartServer(
	appSettings *cfg.AppSettings,
	f2bCollector *f2b.Collector,
) chan error {
	mux := http.NewServeMux()
	mux.HandleFunc("/", AuthMiddleware(
		http.HandlerFunc(rootHtmlHandler),
		appSettings.AuthProvider,
	))
	mux.Handle(metricsPath, AuthMiddleware(
		metricsHandler(),
		appSettings.AuthProvider,
	))
	// /metrics.json goes through the SAME AuthMiddleware wrapper as / and
	// /metrics - never registered bare like /health - so both the
	// --web.config-file layer (exporter-toolkit, wrapping the whole server)
	// and the deprecated --web.basic-auth.* flags (enforced by AuthMiddleware
	// itself) cover it. There is no unauthenticated path to the fail2ban
	// domain snapshot. See docs/metrics-json-schema-v1.md §1.
	mux.Handle(metricsJSONPath, AuthMiddleware(
		metricsJSONHandler(f2bCollector),
		appSettings.AuthProvider,
	))
	mux.HandleFunc("/health",
		func(w http.ResponseWriter, r *http.Request) {
			healthHandler(w, r, f2bCollector)
		},
	)
	log.Printf("metrics available at '%s'", metricsPath)
	log.Printf("json metrics available at '%s'", metricsJSONPath)

	svrErr := make(chan error)
	go func() {
		httpServer := &http.Server{
			Handler:           mux,
			ReadHeaderTimeout: 10 * time.Second,
			ReadTimeout:       10 * time.Second,
			WriteTimeout:      10 * time.Second,
			IdleTimeout:       30 * time.Second,
		}
		// exporter-toolkit owns the listener so that --web.config-file can add
		// TLS, mTLS client-certificate verification and multi-user basic auth
		// without this package having to implement any of it.
		listenAddresses := []string{appSettings.MetricsAddress}
		systemdSocket := false
		flags := &web.FlagConfig{
			WebListenAddresses: &listenAddresses,
			WebSystemdSocket:   &systemdSocket,
			WebConfigFile:      &appSettings.WebConfigFile,
		}
		svrErr <- web.ListenAndServe(httpServer, flags, toolkitLogger())
	}()
	log.Print("ready")
	return svrErr
}

// toolkitLogger adapts exporter-toolkit's slog requirement onto the same stderr
// stream the rest of the exporter logs to.
func toolkitLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
}
