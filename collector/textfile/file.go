package textfile

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/prometheus/common/expfmt"
	"github.com/prometheus/common/model"
)

const namespace = "textfile"

var (
	metricReadError = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "error"),
		"Checks for errors while reading text files",
		[]string{"path"}, nil,
	)
)

// collectFiles parses every .prom file in the collector's directory and emits
// the metrics it finds, plus one textfile_error gauge per file: 1 if that file
// could not be read, parsed, or was skipped, 0 otherwise.
func (c *Collector) collectFiles(ch chan<- prometheus.Metric) {
	files, err := os.ReadDir(c.folderPath)
	if err != nil {
		log.Printf("error reading directory '%s': %v", c.folderPath, err)
		return
	}

	// A metric family may only be emitted once per scrape, so the first file to
	// define a name wins and any later file redefining it is reported as an error
	// rather than being allowed to fail the whole gather.
	seenFamilies := make(map[string]string)

	for _, file := range files {
		fileName := file.Name()
		if !strings.HasSuffix(strings.ToLower(fileName), ".prom") {
			continue
		}

		readError := 0.0
		if err := c.collectFile(ch, fileName, seenFamilies); err != nil {
			log.Printf("error collecting textfile metrics from '%s': %v", fileName, err)
			readError = 1.0
		}
		ch <- prometheus.MustNewConstMetric(
			metricReadError, prometheus.GaugeValue, readError, fileName,
		)
	}
}

func (c *Collector) collectFile(ch chan<- prometheus.Metric, fileName string, seenFamilies map[string]string) error {
	f, err := os.Open(filepath.Join(c.folderPath, fileName))
	if err != nil {
		return err
	}
	defer f.Close()

	// The zero-value TextParser has an unset name validation scheme and panics
	// on first use, so the scheme has to be chosen explicitly. UTF8Validation
	// matches the library default; names it accepts but prometheus.NewDesc
	// rejects surface as a textfile_error rather than a crash.
	parser := expfmt.NewTextParser(model.UTF8Validation)
	families, err := parser.TextToMetricFamilies(f)
	if err != nil {
		return err
	}

	// Parsing yields a map, so emit in a stable order to keep repeated scrapes
	// and the duplicate-name check deterministic.
	names := make([]string, 0, len(families))
	for name := range families {
		names = append(names, name)
	}
	sort.Strings(names)

	for _, name := range names {
		if owner, ok := seenFamilies[name]; ok {
			return fmt.Errorf("metric family %q already defined by %s", name, owner)
		}
		seenFamilies[name] = fileName
		if err := emitFamily(ch, families[name]); err != nil {
			return err
		}
	}
	return nil
}

// emitFamily converts one parsed metric family into const metrics.
func emitFamily(ch chan<- prometheus.Metric, mf *dto.MetricFamily) error {
	for _, m := range mf.Metric {
		labelNames := make([]string, 0, len(m.Label))
		labelValues := make([]string, 0, len(m.Label))
		for _, pair := range m.Label {
			labelNames = append(labelNames, pair.GetName())
			labelValues = append(labelValues, pair.GetValue())
		}
		desc := prometheus.NewDesc(mf.GetName(), helpOrDefault(mf), labelNames, nil)

		var (
			metric prometheus.Metric
			err    error
		)
		switch mf.GetType() {
		case dto.MetricType_COUNTER:
			metric, err = prometheus.NewConstMetric(desc, prometheus.CounterValue, m.GetCounter().GetValue(), labelValues...)
		case dto.MetricType_GAUGE:
			metric, err = prometheus.NewConstMetric(desc, prometheus.GaugeValue, m.GetGauge().GetValue(), labelValues...)
		case dto.MetricType_UNTYPED:
			metric, err = prometheus.NewConstMetric(desc, prometheus.UntypedValue, m.GetUntyped().GetValue(), labelValues...)
		case dto.MetricType_SUMMARY:
			quantiles := make(map[float64]float64, len(m.GetSummary().Quantile))
			for _, q := range m.GetSummary().Quantile {
				quantiles[q.GetQuantile()] = q.GetValue()
			}
			metric, err = prometheus.NewConstSummary(desc, m.GetSummary().GetSampleCount(), m.GetSummary().GetSampleSum(), quantiles, labelValues...)
		case dto.MetricType_HISTOGRAM:
			buckets := make(map[float64]uint64, len(m.GetHistogram().Bucket))
			for _, b := range m.GetHistogram().Bucket {
				buckets[b.GetUpperBound()] = b.GetCumulativeCount()
			}
			metric, err = prometheus.NewConstHistogram(desc, m.GetHistogram().GetSampleCount(), m.GetHistogram().GetSampleSum(), buckets, labelValues...)
		default:
			return fmt.Errorf("metric %q has unsupported type %s", mf.GetName(), mf.GetType())
		}
		if err != nil {
			return fmt.Errorf("metric %q: %w", mf.GetName(), err)
		}

		if m.TimestampMs != nil {
			metric = prometheus.NewMetricWithTimestamp(time.Unix(0, m.GetTimestampMs()*int64(time.Millisecond)), metric)
		}
		ch <- metric
	}
	return nil
}

// helpOrDefault supplies a placeholder for files that omit a HELP line, since
// prometheus.NewDesc requires one.
func helpOrDefault(mf *dto.MetricFamily) string {
	if help := mf.GetHelp(); help != "" {
		return help
	}
	return "Metric read from a textfile collector file"
}
