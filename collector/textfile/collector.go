package textfile

import (
	"log"

	"github.com/NightSquawk/fail2ban-prometheus-exporter/cfg"
	"github.com/prometheus/client_golang/prometheus"
)

type Collector struct {
	enabled    bool
	folderPath string
}

func NewCollector(appSettings *cfg.AppSettings) *Collector {
	collector := &Collector{
		enabled:    appSettings.FileCollectorPath != "",
		folderPath: appSettings.FileCollectorPath,
	}
	if collector.enabled {
		log.Printf("reading textfile metrics from: %s", collector.folderPath)
	}
	return collector
}

// Describe deliberately emits no descriptors, registering this as an unchecked
// collector: the metric families come from user-supplied .prom files and are
// only known at scrape time, so they cannot be declared up front.
func (c *Collector) Describe(chan<- *prometheus.Desc) {}

// Collect parses each .prom file in the configured directory and emits its
// samples as real Prometheus metrics. Earlier versions appended the raw file
// bytes to the HTTP response after promhttp had already written (and possibly
// gzipped) its own output, which corrupted the payload for any scraper sending
// Accept-Encoding: gzip - which Prometheus always does.
func (c *Collector) Collect(ch chan<- prometheus.Metric) {
	if !c.enabled {
		return
	}
	c.collectFiles(ch)
}
