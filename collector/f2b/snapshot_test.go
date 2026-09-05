package f2b

import (
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
