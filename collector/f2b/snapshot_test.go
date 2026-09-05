package f2b

import (
	"bytes"
	"encoding/json"
	"math"
	"sort"
	"testing"
	"time"

	"github.com/NightSquawk/fail2ban-prometheus-exporter/collector/database"
	"github.com/prometheus/client_golang/prometheus"
)

// drainCollect calls c.Collect fully, draining the channel concurrently so
// Collect never blocks on an unread send - the same pattern
// TestCollectorConcurrentAccess uses.
func drainCollect(c *Collector) {
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
}

// TestSnapshotDoesNotMutateAlertStateWithoutOptIn proves the central claim
// SnapshotOptions.MutateAlertState exists to make: a poll that does not set
// it observes the same pending "new country" edge every time, never
// consumes it, and never writes to the collector's edge-triggered state -
// only Collect() (MutateAlertState: true) may do that.
func TestSnapshotDoesNotMutateAlertStateWithoutOptIn(t *testing.T) {
	srv := newFakeF2BServer(t, goldenSocketFixture())
	db := newFixtureDatabase(t, goldenBanRows())
	c := newGoldenCollector(srv, db)

	readOnlyOpts := SnapshotOptions{Include: allSections, MutateAlertState: false}

	snap1, err := c.Snapshot(readOnlyOpts)
	if err != nil {
		t.Fatalf("Snapshot (1st, read-only): %v", err)
	}
	if snap1.Alerts == nil || len(snap1.Alerts.NewCountries) == 0 {
		t.Fatalf("expected the golden fixture to have at least one new-country alert pending, got %+v", snap1.Alerts)
	}
	if len(c.seenCountries) != 0 {
		t.Fatalf("Snapshot with MutateAlertState=false must not write c.seenCountries, got %v", c.seenCountries)
	}
	if c.lastCollectionTime != 0 {
		t.Fatalf("Snapshot with MutateAlertState=false must not advance c.lastCollectionTime, got %d", c.lastCollectionTime)
	}
	if len(c.lastJailActivity) != 0 {
		t.Fatalf("Snapshot with MutateAlertState=false must not write c.lastJailActivity, got %v", c.lastJailActivity)
	}

	// A second read-only poll must see exactly the same pending edge - not
	// an empty one (already consumed) and not a duplicated one (double
	// dedup failure).
	snap2, err := c.Snapshot(readOnlyOpts)
	if err != nil {
		t.Fatalf("Snapshot (2nd, read-only): %v", err)
	}
	first := append([]string(nil), snap1.Alerts.NewCountries...)
	second := append([]string(nil), snap2.Alerts.NewCountries...)
	sort.Strings(first)
	sort.Strings(second)
	if len(first) != len(second) {
		t.Fatalf("two read-only polls disagree on pending new countries: %v vs %v", first, second)
	}
	for i := range first {
		if first[i] != second[i] {
			t.Fatalf("two read-only polls disagree on pending new countries: %v vs %v", first, second)
		}
	}

	// Each poll's own list must be duplicate-free: two jails sharing an
	// attacking country must fold into one entry per gather even though
	// c.seenCountries could not be written to dedupe across the call.
	assertNoDuplicateStrings(t, snap1.Alerts.NewCountries)
	assertNoDuplicateStrings(t, snap2.Alerts.NewCountries)

	// Now let Collect() (MutateAlertState: true) actually consume the edge.
	drainCollect(c)
	if len(c.seenCountries) == 0 {
		t.Fatalf("Collect() must have recorded the seen countries, got %v", c.seenCountries)
	}

	// A read-only poll after Collect() must no longer report those
	// countries as new.
	snap3, err := c.Snapshot(readOnlyOpts)
	if err != nil {
		t.Fatalf("Snapshot (3rd, read-only, post-Collect): %v", err)
	}
	if len(snap3.Alerts.NewCountries) != 0 {
		t.Fatalf("expected no new countries after Collect() consumed them, got %v", snap3.Alerts.NewCountries)
	}
}

func assertNoDuplicateStrings(t *testing.T, values []string) {
	t.Helper()
	seen := make(map[string]bool, len(values))
	for _, v := range values {
		if seen[v] {
			t.Fatalf("duplicate value %q in %v", v, values)
		}
		seen[v] = true
	}
}

// TestSnapshotMaxIPsCapsReturnedBansIndependentlyOfCollectorCeiling proves
// SnapshotOptions.MaxIPs caps bans.items on its own terms - a request-scoped
// ceiling distinct from --collector.f2b.max-ip-metrics (c.maxIPMetrics),
// which the golden fixture leaves at 0 (unlimited) so it never exercises
// this path.
func TestSnapshotMaxIPsCapsReturnedBansIndependentlyOfCollectorCeiling(t *testing.T) {
	// goldenBanRows only has one ban that is both real-clock-active (the
	// database's own strftime('now') predicate, independent of any
	// injected test clock) and dateable (timeofban != 0) - not enough to
	// exercise capping - so this test builds its own fixture with three.
	now := time.Now().Unix()
	rows := []database.BannedIP{
		{Jail: "sshd", IP: "203.0.113.1", TimeOfBan: now - 3600, BanTime: 100 * secondsPerYear},
		{Jail: "sshd", IP: "203.0.113.2", TimeOfBan: now - 7200, BanTime: 100 * secondsPerYear},
		{Jail: "sshd", IP: "203.0.113.3", TimeOfBan: now - 1800, BanTime: 100 * secondsPerYear},
	}
	srv := newFakeF2BServer(t, goldenSocketFixture())
	db := newFixtureDatabase(t, rows)
	c := newGoldenCollector(srv, db)

	full, err := c.Snapshot(SnapshotOptions{Include: allSections, MaxIPs: 0})
	if err != nil {
		t.Fatalf("Snapshot (uncapped): %v", err)
	}
	if full.Bans == nil || len(full.Bans.Items) != len(rows) {
		t.Fatalf("expected %d dateable active bans, got %+v", len(rows), full.Bans)
	}
	total := full.Bans.Total

	capped, err := c.Snapshot(SnapshotOptions{Include: allSections, MaxIPs: 1})
	if err != nil {
		t.Fatalf("Snapshot (capped): %v", err)
	}
	if capped.Bans == nil {
		t.Fatalf("expected a bans section")
	}
	if got := len(capped.Bans.Items); got != 1 {
		t.Fatalf("MaxIPs: 1 should return exactly 1 item, got %d", got)
	}
	if capped.Bans.Total != total {
		t.Fatalf("MaxIPs must not change bans.total (post-collapse row count), got %d want %d", capped.Bans.Total, total)
	}
	if !capped.Bans.Truncated {
		t.Fatalf("expected bans.truncated=true when MaxIPs < total")
	}
}

// TestSnapshotMaxIPsKeepsMostRecentItemsFirst proves truncation keeps the
// head of the documented ordering (docs/metrics-json-schema-v1.md §3.2:
// "bannedAt descending... truncation keeps the head of that ordering - the
// most recent bans") rather than an arbitrary or input-order-dependent
// subset. The fixture rows are deliberately inserted out of chronological
// order, so a bug that truncated before sorting (or sorted on insertion
// order) would return the wrong item.
func TestSnapshotMaxIPsKeepsMostRecentItemsFirst(t *testing.T) {
	now := time.Now().Unix()
	rows := []database.BannedIP{
		// Inserted oldest-first, so a truncate-before-sort bug would keep
		// this row instead of the actually-most-recent one below.
		{Jail: "sshd", IP: "203.0.113.1", TimeOfBan: now - 7200, BanTime: 100 * secondsPerYear},
		{Jail: "sshd", IP: "203.0.113.2", TimeOfBan: now - 3600, BanTime: 100 * secondsPerYear},
		{Jail: "sshd", IP: "203.0.113.3", TimeOfBan: now - 1800, BanTime: 100 * secondsPerYear}, // most recent
	}
	srv := newFakeF2BServer(t, goldenSocketFixture())
	db := newFixtureDatabase(t, rows)
	c := newGoldenCollector(srv, db)

	snap, err := c.Snapshot(SnapshotOptions{Include: allSections, MaxIPs: 2})
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	if snap.Bans == nil || len(snap.Bans.Items) != 2 {
		t.Fatalf("expected 2 items, got %+v", snap.Bans)
	}
	if !snap.Bans.Truncated {
		t.Fatalf("expected bans.truncated=true (2 of 3)")
	}
	if got := []string{snap.Bans.Items[0].IP, snap.Bans.Items[1].IP}; got[0] != "203.0.113.3" || got[1] != "203.0.113.2" {
		t.Errorf("items = %v, want [203.0.113.3 203.0.113.2] (the two most recent bans, most-recent-first)", got)
	}
}

// TestSnapshotMaxIPsCeilingCannotBeWidened proves the hard bound
// docs/metrics-json-schema-v1.md §1.2 documents: a request may narrow
// bans.items below --collector.f2b.max-ip-metrics, but can never widen past
// it. c.maxIPMetrics (the configured ceiling) is set below the fixture's
// true row count, and the request asks for far more than that ceiling.
func TestSnapshotMaxIPsCeilingCannotBeWidened(t *testing.T) {
	now := time.Now().Unix()
	rows := []database.BannedIP{
		{Jail: "sshd", IP: "203.0.113.1", TimeOfBan: now - 3600, BanTime: 100 * secondsPerYear},
		{Jail: "sshd", IP: "203.0.113.2", TimeOfBan: now - 7200, BanTime: 100 * secondsPerYear},
		{Jail: "sshd", IP: "203.0.113.3", TimeOfBan: now - 1800, BanTime: 100 * secondsPerYear},
	}
	srv := newFakeF2BServer(t, goldenSocketFixture())
	db := newFixtureDatabase(t, rows)
	c := newGoldenCollector(srv, db)
	c.maxIPMetrics = 2 // the configured ceiling: below the fixture's 3 rows.

	snap, err := c.Snapshot(SnapshotOptions{Include: allSections, MaxIPs: 100})
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	if snap.Bans == nil {
		t.Fatalf("expected a bans section")
	}
	if got := len(snap.Bans.Items); got != 2 {
		t.Fatalf("requesting MaxIPs=100 against a ceiling of 2 returned %d items, want 2 (the ceiling must clamp down, never widen)", got)
	}
	if snap.Bans.Total != len(rows) {
		t.Errorf("bans.total = %d, want %d (the full pre-truncation count)", snap.Bans.Total, len(rows))
	}
	if !snap.Bans.Truncated {
		t.Errorf("expected bans.truncated=true")
	}
}

// TestEffectiveMaxIPs pins the resolution table in
// docs/metrics-json-schema-v1.md §1.2 directly, independent of any gather.
func TestEffectiveMaxIPs(t *testing.T) {
	tests := []struct {
		name    string
		ceiling int
		request int
		wantCap int
	}{
		{"absent (0) with a positive ceiling", 500, 0, 500},
		{"absent (0) with unlimited ceiling", 0, 0, 0},
		{"below the ceiling", 500, 10, 10},
		{"equal to the ceiling", 500, 500, 500},
		{"above a positive ceiling clamps down", 500, 1000, 500},
		{"above zero with an unlimited ceiling is unclamped", 0, 1000, 1000},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &Collector{maxIPMetrics: tt.ceiling}
			if got := c.EffectiveMaxIPs(tt.request); got != tt.wantCap {
				t.Errorf("EffectiveMaxIPs(%d) with ceiling %d = %d, want %d", tt.request, tt.ceiling, got, tt.wantCap)
			}
		})
	}
}

// TestParseFiniteFloatRejectsNonFiniteAndMalformedInput exercises
// parseFiniteFloat directly. It exists to keep NaN/+-Inf out of the JSON
// marshaller: docs/metrics-json-schema-v1.md's "Relationship to /metrics"
// section states that any non-finite geo.lat/geo.lon reaching
// encoding/json.Marshal fails the whole /metrics.json response, so a
// regression here would only otherwise be caught in production as a total
// outage.
func TestParseFiniteFloatRejectsNonFiniteAndMalformedInput(t *testing.T) {
	tests := []struct {
		name string
		in   string
	}{
		{"NaN", "NaN"},
		{"positive infinity", "+Inf"},
		{"negative infinity", "-Inf"},
		{"bare Inf", "Inf"},
		{"empty string", ""},
		{"malformed", "not-a-number"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v, ok := parseFiniteFloat(tt.in)
			if ok {
				t.Errorf("parseFiniteFloat(%q) = (%v, true), want (0, false)", tt.in, v)
			}
			if v != 0 {
				t.Errorf("parseFiniteFloat(%q) returned value %v, want 0", tt.in, v)
			}
		})
	}

	// A normal finite value must still parse and round-trip exactly - the
	// guard must not reject legitimate coordinates.
	if v, ok := parseFiniteFloat("40.7128"); !ok || v != 40.7128 {
		t.Errorf(`parseFiniteFloat("40.7128") = (%v, %v), want (40.7128, true)`, v, ok)
	}
}

// TestFiniteOrZeroReplacesNonFiniteWithZero exercises finiteOrZero directly,
// the sibling guard applied to computed floats (attack velocity, suspicious
// score, pattern score) rather than parsed strings.
func TestFiniteOrZeroReplacesNonFiniteWithZero(t *testing.T) {
	tests := []struct {
		name string
		in   float64
		want float64
	}{
		{"NaN", math.NaN(), 0},
		{"positive infinity", math.Inf(1), 0},
		{"negative infinity", math.Inf(-1), 0},
		{"finite value passes through unchanged", 12.5, 12.5},
		{"zero passes through unchanged", 0, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := finiteOrZero(tt.in); got != tt.want {
				t.Errorf("finiteOrZero(%v) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}

// TestSnapshotBansGeoOmitsNonFiniteCoordinates proves the parseFiniteFloat
// guard is actually wired up end to end through geoPointFromProvider: a
// geo.Provider that returns a non-finite string for latitude/longitude (as
// MaxMind or a future provider bug plausibly could) must not propagate a
// NaN/Inf into BanItem.Geo.Lat/Lon, and the resulting Snapshot must still be
// JSON-marshalable - the whole reason the guard exists. City/country still
// come through unaffected: only the two numeric fields are guarded.
func TestSnapshotBansGeoOmitsNonFiniteCoordinates(t *testing.T) {
	now := time.Now().Unix()
	const attackerIP = "203.0.113.77"
	rows := []database.BannedIP{
		{Jail: "sshd", IP: attackerIP, TimeOfBan: now - 100, BanTime: 100 * secondsPerYear},
	}
	srv := newFakeF2BServer(t, goldenSocketFixture())
	db := newFixtureDatabase(t, rows)
	c := newGoldenCollector(srv, db)
	c.geoProvider = &fakeGeoProvider{records: map[string]geoRecord{
		attackerIP: {"Nullisland", "NaN", "+Inf", "Nullcountry", "NU"},
	}}

	snap, err := c.Snapshot(SnapshotOptions{Include: map[string]bool{"bans": true}})
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	if snap.Bans == nil || len(snap.Bans.Items) != 1 {
		t.Fatalf("expected exactly one bans.items row, got %+v", snap.Bans)
	}
	item := snap.Bans.Items[0]
	if item.Geo == nil {
		t.Fatalf("expected a geo object (city/country still present even without coordinates)")
	}
	if item.Geo.City != "Nullisland" || item.Geo.CountryCode != "NU" {
		t.Errorf("geo city/countryCode = %q/%q, want the non-coordinate fields to still come through", item.Geo.City, item.Geo.CountryCode)
	}
	if item.Geo.Lat != nil {
		t.Errorf("geo.lat = %v, want nil (NaN must not survive parseFiniteFloat)", *item.Geo.Lat)
	}
	if item.Geo.Lon != nil {
		t.Errorf("geo.lon = %v, want nil (+Inf must not survive parseFiniteFloat)", *item.Geo.Lon)
	}

	if _, err := json.Marshal(snap); err != nil {
		t.Fatalf("json.Marshal(snap) = %v, want success - a non-finite float must never reach the marshaller", err)
	}
}

// TestSnapshotBansOmitsGeoWhenProviderHasNoRecord proves
// docs/metrics-json-schema-v1.md §3.2's "geo is omitted... when the lookup
// returned nothing" claim for the case where geo is enabled but the specific
// banned address simply has no MaxMind record. Every pre-existing test that
// inspects BanItem.Geo only ever supplies addresses that DO have a
// fakeGeoProvider record, so this is the only test where item.Geo is
// expected to be nil.
func TestSnapshotBansOmitsGeoWhenProviderHasNoRecord(t *testing.T) {
	now := time.Now().Unix()
	const attackerIP = "203.0.113.61"
	rows := []database.BannedIP{
		{Jail: "sshd", IP: attackerIP, TimeOfBan: now - 100, BanTime: 100 * secondsPerYear},
	}
	srv := newFakeF2BServer(t, goldenSocketFixture())
	db := newFixtureDatabase(t, rows)
	c := newGoldenCollector(srv, db)
	// Deliberately empty: attackerIP has no MaxMind record, unlike every
	// other geo test in this package.
	c.geoProvider = &fakeGeoProvider{records: map[string]geoRecord{}}

	snap, err := c.Snapshot(SnapshotOptions{Include: map[string]bool{"bans": true}})
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	if snap.Bans == nil || len(snap.Bans.Items) != 1 {
		t.Fatalf("expected exactly one bans.items row, got %+v", snap.Bans)
	}
	item := snap.Bans.Items[0]
	if item.Geo != nil {
		t.Errorf("item.Geo = %+v, want nil when the provider has no record for the address", item.Geo)
	}

	body, err := json.Marshal(snap)
	if err != nil {
		t.Fatalf("marshal snapshot: %v", err)
	}
	if bytes.Contains(body, []byte(`"geo"`)) {
		t.Errorf("marshalled output contains a \"geo\" key even though the provider had no record for the only banned address:\n%s", body)
	}
}
