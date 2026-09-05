package f2b

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil/promlint"
)

// knownLintProblems are promlint findings this project accepts, keyed by
// "<metric>: <problem text>". Every entry needs a reason: the point of the
// allowlist is that adding to it is a deliberate decision, not the default.
var knownLintProblems = map[string]string{
	// f2b_jail_count predates this fork, mirrors fail2ban's own "Number of jail"
	// line and is referenced by every published dashboard. promlint objects to
	// the _count suffix because it collides with histogram/summary conventions,
	// which this gauge is in no danger of being confused with. Renaming it would
	// break every existing dashboard for no operational gain.
	"f2b_jail_count: non-histogram and non-summary metrics should not have \"_count\" suffix": "legacy name, kept for dashboard compatibility",
}

// TestGoldenMetricsPassPromlint runs the Prometheus naming and typing linter
// over the exact exposition output the golden test pins, so a new metric
// cannot land with a name or type that Prometheus conventions reject.
func TestGoldenMetricsPassPromlint(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "metrics.golden"))
	if err != nil {
		t.Fatalf("read golden file (run the golden test with -update to create it): %v", err)
	}

	problems, err := promlint.New(bytes.NewReader(data)).Lint()
	if err != nil {
		t.Fatalf("lint golden metrics: %v", err)
	}

	var unexpected []string
	for _, p := range problems {
		key := fmt.Sprintf("%s: %s", p.Metric, p.Text)
		if _, ok := knownLintProblems[key]; ok {
			continue
		}
		unexpected = append(unexpected, key)
	}
	sort.Strings(unexpected)

	for _, p := range unexpected {
		t.Errorf("promlint: %s", p)
	}
}
