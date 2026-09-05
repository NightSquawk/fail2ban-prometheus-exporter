package f2b

import (
	"bytes"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/NightSquawk/fail2ban-prometheus-exporter/cfg"
	"github.com/NightSquawk/fail2ban-prometheus-exporter/collector/database"
	dto "github.com/prometheus/client_model/go"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/expfmt"
)

var update = flag.Bool("update", false, "update golden files")

// TestMain pins the local timezone so f2b_attacks_by_hour and
// f2b_attacks_by_day_of_week (which bucket via time.Unix(...).Hour()/
// .Weekday() in local time) are reproducible on any machine and in CI.
func TestMain(m *testing.M) {
	time.Local = time.UTC
	os.Exit(m.Run())
}

// fixedNow is the frozen clock every golden-test Collector uses. It is
// deliberately anchored well in the past: fixture rows compute their
// "currently active" real-world expiry (used by the SQL predicate in
// collector/database, which is NOT wired to this clock) as offsets from
// fixedNow, and picking fixedNow safely before "today" means a short
// bantime is expired forever while a long bantime stays active far into
// the future - both hold regardless of what day the suite actually runs.
var fixedNow = time.Date(2025, 1, 15, 8, 0, 0, 0, time.UTC)

const secondsPerYear = 365 * 24 * 3600

// newTickingClock returns a clock seam anchored at base that advances by one
// microsecond on every call. Every business-logic use of nowFn (ban age,
// remaining/expiry, the 48h pattern cutoff, attack velocity, the alert
// timeDelta) reads it via .Unix(), i.e. second resolution, and a whole
// Collect() call only makes a few dozen nowFn calls - microseconds of
// cumulative drift, so those values still floor to base's exact second
// every run regardless of exactly how many times a future refactor calls
// nowFn. Collect()'s duration metrics take Sub() between two calls to this
// same seam, which is exactly why they come out non-zero instead of being
// suppressed by their `if duration > 0` guards under a perfectly static
// clock - and exactly why the golden test normalizes their values rather
// than comparing them.
func newTickingClock(base time.Time) func() time.Time {
	var calls int64
	return func() time.Time {
		n := atomic.AddInt64(&calls, 1) - 1
		return base.Add(time.Duration(n) * time.Microsecond)
	}
}

// goldenSocketFixture is fail2ban's live in-memory state, as reported over
// the socket: currently banned IPs and jail configuration.
func goldenSocketFixture() fakeF2BFixture {
	return fakeF2BFixture{
		Version: "1.0.2",
		Jails: []fakeJailFixture{
			{
				Name:          "sshd",
				FailedCurrent: 3,
				FailedTotal:   42,
				BannedCurrent: 3,
				BannedTotal:   10,
				BannedIPs:     "203.0.113.10,203.0.113.14,203.0.113.12",
				BanTime:       3600,
				FindTime:      600,
				MaxRetry:      5,
			},
			{
				Name:          "apache-auth",
				FailedCurrent: 0,
				FailedTotal:   5,
				BannedCurrent: 1,
				BannedTotal:   2,
				BannedIPs:     "198.51.100.20",
				BanTime:       7200,
				FindTime:      300,
				MaxRetry:      3,
			},
			{
				Name:          "recidive",
				FailedCurrent: 0,
				FailedTotal:   0,
				BannedCurrent: 0,
				BannedTotal:   0,
				BannedIPs:     "",
				BanTime:       86400,
				FindTime:      600,
				MaxRetry:      3,
			},
		},
	}
}

// goldenBanRows is fail2ban's persisted ban history, as read from SQLite.
// Timestamps are offsets from fixedNow so ages/expiries computed against
// the injected clock are exact literals, not derived at test time.
//
//   - sshd/.99: bantime of 100 years keeps it "active" per the database's
//     own strftime('now') predicate indefinitely; used to exercise
//     collectTimeBasedMetrics's non-skip path.
//   - sshd/.10 appears 3 times within the 48h pattern window (brute force)
//     plus once 72h out (outside the window, only affects all-time
//     ip_ban_count_total/repeat_offender).
//   - sshd/.10..14 span 4 distinct countries (US, CN, RU, FR) and 6 distinct
//     IPs, tripping DetectDistributed and DetectPortScan.
//   - apache-auth has two bans, below every pattern threshold: a control
//     jail where nothing fires.
//   - recidive/.200 has timeofban=0 with a deliberately huge bantime so it
//     still passes the database's real-clock "active" filter, exercising
//     collectTimeBasedMetrics's timeofban==0 skip path.
func goldenBanRows() []database.BannedIP {
	at := func(offsetSeconds int64) int64 { return fixedNow.Unix() + offsetSeconds }
	return []database.BannedIP{
		{Jail: "sshd", IP: "203.0.113.99", TimeOfBan: at(-3600), BanTime: 100 * secondsPerYear},
		{Jail: "sshd", IP: "203.0.113.10", TimeOfBan: at(-2 * 3600), BanTime: 3600},
		{Jail: "sshd", IP: "203.0.113.10", TimeOfBan: at(-5 * 3600), BanTime: 3600},
		{Jail: "sshd", IP: "203.0.113.10", TimeOfBan: at(-10 * 3600), BanTime: 3600},
		{Jail: "sshd", IP: "203.0.113.10", TimeOfBan: at(-72 * 3600), BanTime: 3600},
		{Jail: "sshd", IP: "203.0.113.11", TimeOfBan: at(-3 * 3600), BanTime: 3600},
		{Jail: "sshd", IP: "203.0.113.12", TimeOfBan: at(-4 * 3600), BanTime: 3600},
		{Jail: "sshd", IP: "203.0.113.13", TimeOfBan: at(-6 * 3600), BanTime: 3600},
		{Jail: "sshd", IP: "203.0.113.14", TimeOfBan: at(-7 * 3600), BanTime: 3600},
		{Jail: "apache-auth", IP: "198.51.100.20", TimeOfBan: at(-3600), BanTime: 3600},
		{Jail: "apache-auth", IP: "198.51.100.21", TimeOfBan: at(-2 * 3600), BanTime: 3600},
		{Jail: "recidive", IP: "203.0.113.200", TimeOfBan: 0, BanTime: 4_000_000_000},
	}
}

// newFixtureDatabase builds a temp fail2ban-shaped SQLite database, mirroring
// collector/database/database_test.go's newTestDB.
func newFixtureDatabase(t *testing.T, rows []database.BannedIP) *database.Database {
	t.Helper()

	dbPath := filepath.Join(t.TempDir(), "fail2ban.sqlite3")
	db, err := database.NewDatabase(dbPath)
	if err != nil {
		t.Fatalf("create fixture database: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	if _, err := db.GetDB().Exec(`CREATE TABLE bans (jail TEXT, ip TEXT, timeofban INTEGER, bantime INTEGER)`); err != nil {
		t.Fatalf("create bans table: %v", err)
	}
	for _, row := range rows {
		if _, err := db.GetDB().Exec(
			`INSERT INTO bans (jail, ip, timeofban, bantime) VALUES (?, ?, ?, ?)`,
			row.Jail, row.IP, row.TimeOfBan, row.BanTime,
		); err != nil {
			t.Fatalf("insert fixture ban: %v", err)
		}
	}
	return db
}

// geoRecord is one fake MaxMind lookup result.
type geoRecord struct {
	city, lat, lon, country, countryCode string
}

// goldenGeoRecords covers every IP appearing in either fixture.
// 198.51.100.20 is deliberately absent, so Annotate returns nil for it -
// the nil-geo path every consumer (banned_ip labels, geographic/alert/pattern
// collection) must tolerate.
func goldenGeoRecords() map[string]geoRecord {
	return map[string]geoRecord{
		"203.0.113.10":  {"New York", "40.712800", "-74.006000", "United States", "US"},
		"203.0.113.11":  {"Beijing", "39.904200", "116.407400", "China", "CN"},
		"203.0.113.12":  {"Moscow", "55.755800", "37.617300", "Russia", "RU"},
		"203.0.113.13":  {"Paris", "48.856600", "2.352200", "France", "FR"},
		"203.0.113.14":  {"Los Angeles", "34.052200", "-118.243700", "United States", "US"},
		"203.0.113.99":  {"Chicago", "41.878100", "-87.629800", "United States", "US"},
		"203.0.113.200": {"Berlin", "52.520000", "13.405000", "Germany", "DE"},
		"198.51.100.21": {"Tokyo", "35.676200", "139.650300", "Japan", "JP"},
	}
}

// fakeGeoProvider is a deterministic geo.Provider backed by a fixed map.
type fakeGeoProvider struct {
	records map[string]geoRecord
}

func (p *fakeGeoProvider) Annotate(ip string) map[string]string {
	r, ok := p.records[ip]
	if !ok {
		return nil
	}
	return map[string]string{
		"city":         r.city,
		"latitude":     r.lat,
		"longitude":    r.lon,
		"country":      r.country,
		"country_code": r.countryCode,
	}
}

func (p *fakeGeoProvider) GetLabels() []string {
	return []string{"city", "latitude", "longitude", "country", "country_code"}
}

// newGoldenCollector wires a Collector to the fake socket, fixture database,
// fixed clock, fake geo provider and non-empty customer/tenant labels - every
// input the golden fixture is meant to exercise.
func newGoldenCollector(srv *fakeF2BServer, db *database.Database) *Collector {
	return &Collector{
		socketPath:       srv.SocketPath(),
		databasePath:     "fixture",
		exporterVersion:  "1.2.0-beta-test",
		hostname:         "test-host",
		customerID:       "cust-1",
		customerName:     "Acme Corp",
		tenantID:         "tenant-42",
		geoProvider:      &fakeGeoProvider{records: goldenGeoRecords()},
		geoEnabled:       true,
		db:               db,
		maxIPMetrics:     0,
		nowFn:            newTickingClock(fixedNow),
		seenCountries:    make(map[string]bool),
		lastJailActivity: make(map[string]int64),
		alertSettings: &cfg.AlertSettings{
			HighBanRateThreshold:    10.0,
			CoordinatedAttackMinIPs: 2,
			JailInactivityHours:     24,
		},
	}
}

// normalizedDurationFamilies are the metric families whose sample values
// depend on real elapsed wall-clock time even under a frozen nowFn (or
// would, the moment a refactor times real I/O instead of clock deltas).
// Their labels and presence are golden; their values are not, so they are
// rewritten to a placeholder rather than compared or dropped.
var normalizedDurationFamilies = map[string]bool{
	"f2b_collection_duration_seconds":     true,
	"f2b_database_query_duration_seconds": true,
	"f2b_geo_lookup_duration_seconds":     true,
}

const normalizedPlaceholder = -1

func normalizeDurationMetrics(families []*dto.MetricFamily) {
	for _, mf := range families {
		if !normalizedDurationFamilies[mf.GetName()] {
			continue
		}
		for _, m := range mf.Metric {
			if g := m.GetGauge(); g != nil {
				v := float64(normalizedPlaceholder)
				g.Value = &v
			}
		}
	}
}

// renderMetrics gathers reg (sorted deterministically by client_golang),
// normalizes known-nondeterministic duration values, and renders stable
// Prometheus text exposition format - the same path promhttp.Handler uses.
func renderMetrics(t *testing.T, reg *prometheus.Registry) string {
	t.Helper()

	families, err := reg.Gather()
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}
	normalizeDurationMetrics(families)

	var buf bytes.Buffer
	enc := expfmt.NewEncoder(&buf, expfmt.NewFormat(expfmt.TypeTextPlain))
	for _, mf := range families {
		if err := enc.Encode(mf); err != nil {
			t.Fatalf("encode metric family %s: %v", mf.GetName(), err)
		}
	}
	if closer, ok := enc.(expfmt.Closer); ok {
		if err := closer.Close(); err != nil {
			t.Fatalf("close encoder: %v", err)
		}
	}
	return buf.String()
}

// familyBlocks splits Prometheus text exposition format into one text block
// per metric family, keyed by family name, so two renders can be compared
// family-by-family instead of as one indistinguishable blob.
func familyBlocks(text string) map[string]string {
	blocks := make(map[string]string)
	var name string
	var b strings.Builder

	flush := func() {
		if name != "" {
			blocks[name] = b.String()
		}
	}

	for _, line := range strings.Split(text, "\n") {
		if strings.HasPrefix(line, "# HELP ") {
			flush()
			b.Reset()
			fields := strings.SplitN(line, " ", 4)
			name = fields[2]
		}
		if line == "" {
			continue
		}
		b.WriteString(line)
		b.WriteString("\n")
	}
	flush()
	return blocks
}

func TestCollectGolden(t *testing.T) {
	srv := newFakeF2BServer(t, goldenSocketFixture())
	db := newFixtureDatabase(t, goldenBanRows())
	c := newGoldenCollector(srv, db)

	reg1 := prometheus.NewRegistry()
	if err := reg1.Register(c); err != nil {
		t.Fatalf("register collector: %v", err)
	}
	got1 := renderMetrics(t, reg1)

	goldenPath := filepath.Join("testdata", "metrics.golden")
	if *update {
		if err := os.MkdirAll(filepath.Dir(goldenPath), 0o755); err != nil {
			t.Fatalf("create testdata dir: %v", err)
		}
		if err := os.WriteFile(goldenPath, []byte(got1), 0o644); err != nil {
			t.Fatalf("write golden file: %v", err)
		}
	}

	want, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatalf("read golden file (run with -update to create it): %v", err)
	}
	if got1 != string(want) {
		t.Errorf("metrics output does not match %s (run with -update to regenerate)\n--- got ---\n%s\n--- want ---\n%s", goldenPath, got1, string(want))
	}

	// Second scrape against the same Collector: alert state (seenCountries,
	// lastJailActivity, lastRepeatOffenderCount, lastCollectionTime) and the
	// DB cache carry over, since it's the same *Collector, registered again
	// into a fresh registry so Gather doesn't just replay reg1's result.
	reg2 := prometheus.NewRegistry()
	if err := reg2.Register(c); err != nil {
		t.Fatalf("register collector for second collection: %v", err)
	}
	got2 := renderMetrics(t, reg2)

	assertOnlyNewCountryAttackDiffers(t, got1, got2)
}

// assertOnlyNewCountryAttackDiffers documents and enforces the one piece of
// cross-scrape state the next milestone must preserve: f2b_alert_new_country_attack
// fires once per newly observed country, so a country already alerted on in
// the first scrape produces no sample in the second. Every other family must
// render byte-identical output on both scrapes.
func assertOnlyNewCountryAttackDiffers(t *testing.T, first, second string) {
	t.Helper()

	const edgeTriggeredFamily = "f2b_alert_new_country_attack"
	blocks1 := familyBlocks(first)
	blocks2 := familyBlocks(second)

	if _, ok := blocks1[edgeTriggeredFamily]; !ok {
		t.Errorf("expected %s to have fired on the first collection", edgeTriggeredFamily)
	}
	if b2, ok := blocks2[edgeTriggeredFamily]; ok {
		t.Errorf("expected %s to be absent on the second collection (all countries already seen), got:\n%s", edgeTriggeredFamily, b2)
	}

	for name, b1 := range blocks1 {
		if name == edgeTriggeredFamily {
			continue
		}
		b2, ok := blocks2[name]
		if !ok {
			t.Errorf("family %s present on first collection, missing on second", name)
			continue
		}
		if b1 != b2 {
			t.Errorf("family %s differs between first and second collection:\n--- first ---\n%s\n--- second ---\n%s", name, b1, b2)
		}
	}
	for name := range blocks2 {
		if name == edgeTriggeredFamily {
			continue
		}
		if _, ok := blocks1[name]; !ok {
			t.Errorf("family %s present on second collection but not first", name)
		}
	}
}

// TestCollectorConcurrentAccess proves Collect and IsHealthy can be called
// concurrently without racing or panicking now that both hold c.mu for
// their full duration. Run with -race; a wrong or missing lock fails loudly.
func TestCollectorConcurrentAccess(t *testing.T) {
	srv := newFakeF2BServer(t, goldenSocketFixture())
	db := newFixtureDatabase(t, goldenBanRows())
	c := newGoldenCollector(srv, db)

	const goroutines = 20
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func(i int) {
			defer wg.Done()
			if i%2 == 0 {
				ch := make(chan prometheus.Metric)
				done := make(chan struct{})
				go func() {
					for range ch {
					}
					close(done)
				}()
				c.Collect(ch)
				close(ch)
				<-done
			} else {
				c.IsHealthy()
			}
		}(i)
	}
	wg.Wait()
}
