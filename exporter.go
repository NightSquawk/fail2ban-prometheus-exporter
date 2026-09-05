package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/NightSquawk/fail2ban-prometheus-exporter/cfg"
	"github.com/NightSquawk/fail2ban-prometheus-exporter/collector/f2b"
	"github.com/NightSquawk/fail2ban-prometheus-exporter/collector/textfile"
	"github.com/NightSquawk/fail2ban-prometheus-exporter/server"
	"github.com/prometheus/client_golang/prometheus"
)

var (
	version = "1.0.0"
	commit  = "none"
	date    = "unknown"
	builtBy = "unknown"
)

func printAppVersion() {
	fmt.Println(version)
	fmt.Printf("    build date:  %s\r\n    commit hash: %s\r\n    built by:    %s\r\n", date, commit, builtBy)
}

func main() {
	appSettings := cfg.Parse()
	if appSettings.VersionMode {
		printAppVersion()
		return
	}

	handleGracefulShutdown()
	log.Printf("fail2ban exporter version %s", version)
	log.Printf("starting server at %s", appSettings.MetricsAddress)

	f2bCollector := f2b.NewExporter(appSettings, f2b.BuildInfo{Version: version, Commit: commit})
	prometheus.MustRegister(f2bCollector)

	textFileCollector := textfile.NewCollector(appSettings)
	prometheus.MustRegister(textFileCollector)

	if !appSettings.DryRunMode {
		svrErr := server.StartServer(appSettings, f2bCollector)
		err := <-svrErr
		log.Fatal(err)
	} else {
		log.Print("running in dry-run mode - exiting")
	}
}

func handleGracefulShutdown() {
	var signals = make(chan os.Signal, 1)

	signal.Notify(signals, syscall.SIGTERM)
	signal.Notify(signals, syscall.SIGINT)

	go func() {
		sig := <-signals
		log.Printf("caught signal: %+v", sig)
		os.Exit(0)
	}()
}
