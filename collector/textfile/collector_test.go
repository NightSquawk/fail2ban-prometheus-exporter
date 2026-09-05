package textfile

import (
	"compress/gzip"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/NightSquawk/fail2ban-prometheus-exporter/cfg"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/prometheus/common/expfmt"
)

// newTestCollector writes files into a temp directory and returns a Collector
// reading from it. Keys are file names, values are file contents.
func newTestCollector(t *testing.T, files map[string]string) *Collector {
	t.Helper()

	dir := t.TempDir()
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	return NewCollector(&cfg.AppSettings{FileCollectorPath: dir})
}

// gather registers c into a fresh registry and renders the text exposition
// format, the same path promhttp serves.
func gather(t *testing.T, c *Collector) string {
	t.Helper()

	reg := prometheus.NewRegistry()
	if err := reg.Register(c); err != nil {
		t.Fatalf("register collector: %v", err)
	}
	families, err := reg.Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}

	var sb strings.Builder
	enc := expfmt.NewEncoder(&sb, expfmt.NewFormat(expfmt.TypeTextPlain))
	for _, mf := range families {
		if err := enc.Encode(mf); err != nil {
			t.Fatalf("encode %s: %v", mf.GetName(), err)
		}
	}
	return sb.String()
}

func TestCollectParsesEveryMetricType(t *testing.T) {
	c := newTestCollector(t, map[string]string{
		"types.prom": `# HELP demo_counter A counter.
# TYPE demo_counter counter
demo_counter{label="a"} 7
# HELP demo_gauge A gauge.
# TYPE demo_gauge gauge
demo_gauge 1.5
# HELP demo_summary A summary.
# TYPE demo_summary summary
demo_summary{quantile="0.5"} 0.2
demo_summary_sum 12
demo_summary_count 3
# HELP demo_histogram A histogram.
# TYPE demo_histogram histogram
demo_histogram_bucket{le="1"} 1
demo_histogram_bucket{le="+Inf"} 2
demo_histogram_sum 3
demo_histogram_count 2
demo_untyped 42
`,
		"ignored.txt": "this file must not be read",
	})

	out := gather(t, c)
	for _, want := range []string{
		`demo_counter{label="a"} 7`,
		"demo_gauge 1.5",
		`demo_summary{quantile="0.5"} 0.2`,
		"demo_summary_count 3",
		`demo_histogram_bucket{le="1"} 1`,
		"demo_untyped 42",
		"# TYPE demo_counter counter",
		"# TYPE demo_histogram histogram",
		`textfile_error{path="types.prom"} 0`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output is missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "this file must not be read") {
		t.Error("a non-.prom file was collected")
	}
	if strings.Contains(out, `textfile_error{path="ignored.txt"}`) {
		t.Error("a non-.prom file produced a textfile_error series")
	}
}

func TestCollectReportsUnparseableFile(t *testing.T) {
	c := newTestCollector(t, map[string]string{
		"good.prom": "# TYPE good_metric gauge\ngood_metric 1\n",
		"bad.prom":  "this is not exposition format {{{\n",
	})

	out := gather(t, c)
	if !strings.Contains(out, `textfile_error{path="bad.prom"} 1`) {
		t.Errorf("expected textfile_error 1 for the malformed file:\n%s", out)
	}
	// One bad file must not take the good one down with it.
	if !strings.Contains(out, "good_metric 1") {
		t.Errorf("a malformed file suppressed a valid one:\n%s", out)
	}
	if !strings.Contains(out, `textfile_error{path="good.prom"} 0`) {
		t.Errorf("expected textfile_error 0 for the valid file:\n%s", out)
	}
}

// TestCollectRejectsDuplicateFamily covers two files defining the same metric:
// the second is reported as an error rather than being emitted and failing the
// whole gather with a duplicate-series error.
func TestCollectRejectsDuplicateFamily(t *testing.T) {
	c := newTestCollector(t, map[string]string{
		"a.prom": "# TYPE dup gauge\ndup 1\n",
		"b.prom": "# TYPE dup gauge\ndup 2\n",
	})

	out := gather(t, c)
	if !strings.Contains(out, `textfile_error{path="b.prom"} 1`) {
		t.Errorf("expected the second file defining 'dup' to be reported as an error:\n%s", out)
	}
	if got := strings.Count(out, "\ndup "); got != 1 {
		t.Errorf("expected exactly one 'dup' sample, got %d:\n%s", got, out)
	}
}

func TestCollectDisabledWithoutDirectory(t *testing.T) {
	c := NewCollector(&cfg.AppSettings{})
	if out := gather(t, c); out != "" {
		t.Errorf("expected no metrics when no directory is configured, got:\n%s", out)
	}
}

// TestMetricsSurviveGzipScrape is the regression test for the bug this
// collector replaced: textfile contents used to be appended to the HTTP
// response after promhttp had written its own (gzipped) body, so a scraper
// sending Accept-Encoding: gzip - which Prometheus always does - received a
// gzip stream with plaintext stuck on the end.
func TestMetricsSurviveGzipScrape(t *testing.T) {
	c := newTestCollector(t, map[string]string{
		"custom.prom": "# TYPE custom_metric gauge\ncustom_metric 99\n",
	})
	reg := prometheus.NewRegistry()
	if err := reg.Register(c); err != nil {
		t.Fatalf("register collector: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	req.Header.Set("Accept-Encoding", "gzip")
	rec := httptest.NewRecorder()
	promhttp.HandlerFor(reg, promhttp.HandlerOpts{}).ServeHTTP(rec, req)

	res := rec.Result()
	defer res.Body.Close()
	if res.Header.Get("Content-Encoding") != "gzip" {
		t.Fatalf("expected a gzipped response, got Content-Encoding %q", res.Header.Get("Content-Encoding"))
	}

	zr, err := gzip.NewReader(res.Body)
	if err != nil {
		t.Fatalf("open gzip reader: %v", err)
	}
	body, err := io.ReadAll(zr)
	if err != nil {
		t.Fatalf("read gzipped body (trailing plaintext would surface here): %v", err)
	}
	if err := zr.Close(); err != nil {
		t.Fatalf("close gzip reader: %v", err)
	}
	if !strings.Contains(string(body), "custom_metric 99") {
		t.Errorf("textfile metric missing from the gzipped scrape:\n%s", body)
	}
}
