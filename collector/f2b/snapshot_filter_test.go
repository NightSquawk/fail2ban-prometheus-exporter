package f2b

import (
	"regexp"
	"testing"

	"github.com/NightSquawk/fail2ban-prometheus-exporter/cfg"
	"github.com/NightSquawk/fail2ban-prometheus-exporter/collector/database"
)

// TestSnapshotJailFilterReachesEverySection proves the docs/metrics-json-
// schema-v1.md §3 preamble: --collector.f2b.jail-include/-exclude are
// applied once, upstream of everything, and a filtered-out jail is absent
// EVERYWHERE (jails, bans, patterns, geo, activity, alerts) - never present
// as a zero row. The fixture gives the excluded jail enough activity to trip
// every one of those six sections if the filter were ever bypassed for one
// of them: 5 distinct IPs (port_scan), one IP banned 3x (brute_force), and
// 5 distinct countries (would trip distributed and populate geo/alerts) -
// so any section that leaked the excluded jail's data would fail loudly.
func TestSnapshotJailFilterReachesEverySection(t *testing.T) {
	const keptJail = "sshd"
	const excludedJail = "excluded-jail"

	// Real, resolvable addresses in the excluded jail, one per country, so
	// that DetectPortScan (>=5 distinct IPs) and DetectDistributed (>=3
	// distinct countries) both fire for it if its bans are ever allowed to
	// reach the pattern detector.
	excludedGeo := map[string]geoRecord{
		"198.51.100.50": {"Shenzhen", "22.5431", "114.0579", "China", "CN"},
		"198.51.100.51": {"Moscow", "55.7558", "37.6173", "Russia", "RU"},
		"198.51.100.52": {"Paris", "48.8566", "2.3522", "France", "FR"},
		"198.51.100.53": {"Berlin", "52.5200", "13.4050", "Germany", "DE"},
		"198.51.100.54": {"Tokyo", "35.6762", "139.6503", "Japan", "JP"},
		// The kept jail's single IP gets its own, distinct country so its
		// presence in geo/alerts is unambiguous and separable from the
		// excluded jail's countries.
		"203.0.113.10": {"London", "51.5074", "-0.1278", "United Kingdom", "GB"},
	}

	socketFixture := fakeF2BFixture{
		Version: "1.0.2",
		Jails: []fakeJailFixture{
			{
				Name: keptJail, FailedCurrent: 1, FailedTotal: 5, BannedCurrent: 1, BannedTotal: 1,
				BannedIPs: "203.0.113.10", BanTime: 3600, FindTime: 600, MaxRetry: 5,
			},
			{
				Name: excludedJail, FailedCurrent: 2, FailedTotal: 9, BannedCurrent: 5, BannedTotal: 5,
				BannedIPs: "198.51.100.50,198.51.100.51,198.51.100.52,198.51.100.53,198.51.100.54",
				BanTime:   3600, FindTime: 600, MaxRetry: 3,
			},
		},
	}

	at := func(offsetSeconds int64) int64 { return fixedNow.Unix() + offsetSeconds }
	rows := []database.BannedIP{
		{Jail: keptJail, IP: "203.0.113.10", TimeOfBan: at(-3600), BanTime: 100 * secondsPerYear},

		// Brute force: .50 banned 3 times within the 48h pattern window.
		{Jail: excludedJail, IP: "198.51.100.50", TimeOfBan: at(-1 * 3600), BanTime: 100 * secondsPerYear},
		{Jail: excludedJail, IP: "198.51.100.50", TimeOfBan: at(-2 * 3600), BanTime: 3600},
		{Jail: excludedJail, IP: "198.51.100.50", TimeOfBan: at(-3 * 3600), BanTime: 3600},
		// Port scan / distributed: 5 distinct IPs, 5 distinct countries.
		{Jail: excludedJail, IP: "198.51.100.51", TimeOfBan: at(-4 * 3600), BanTime: 100 * secondsPerYear},
		{Jail: excludedJail, IP: "198.51.100.52", TimeOfBan: at(-5 * 3600), BanTime: 100 * secondsPerYear},
		{Jail: excludedJail, IP: "198.51.100.53", TimeOfBan: at(-6 * 3600), BanTime: 100 * secondsPerYear},
		{Jail: excludedJail, IP: "198.51.100.54", TimeOfBan: at(-7 * 3600), BanTime: 100 * secondsPerYear},
	}

	srv := newFakeF2BServer(t, socketFixture)
	db := newFixtureDatabase(t, rows)
	c := newGoldenCollector(srv, db)
	c.jails = newJailFilter(cfg.FilterSettings{JailExclude: regexp.MustCompile("^" + excludedJail + "$")})
	c.geoProvider = &fakeGeoProvider{records: excludedGeo}

	snap, err := c.Snapshot(SnapshotOptions{Include: allSections, MutateAlertState: false})
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}

	// 1. jails: only the kept jail, never a zero row for the excluded one.
	if snap.Jails == nil {
		t.Fatalf("expected a jails section")
	}
	if len(*snap.Jails) != 1 || (*snap.Jails)[0].Name != keptJail {
		t.Errorf("jails = %+v, want exactly [%s]", *snap.Jails, keptJail)
	}

	// 2. bans: only the kept jail's item.
	if snap.Bans == nil {
		t.Fatalf("expected a bans section")
	}
	for _, item := range snap.Bans.Items {
		if item.Jail == excludedJail {
			t.Errorf("bans.items contains an item from the excluded jail: %+v", item)
		}
	}
	if len(snap.Bans.Items) != 1 || snap.Bans.Items[0].Jail != keptJail {
		t.Errorf("bans.items = %+v, want exactly one item from %s", snap.Bans.Items, keptJail)
	}

	// 3. patterns: the excluded jail's data alone would trip brute_force,
	// port_scan AND distributed - none of them may appear.
	if snap.Patterns == nil {
		t.Fatalf("expected a patterns section")
	}
	for _, p := range *snap.Patterns {
		if p.Jail == excludedJail {
			t.Errorf("patterns contains an entry from the excluded jail: %+v", p)
		}
	}
	if len(*snap.Patterns) != 0 {
		t.Errorf("patterns = %+v, want none (the kept jail alone trips no pattern)", *snap.Patterns)
	}

	// 4. geo: the excluded jail's 5 countries must never appear; the kept
	// jail's single country (GB) must.
	if snap.Geo == nil {
		t.Fatalf("expected a geo section")
	}
	var sawGB bool
	for _, cs := range snap.Geo.ByCountry {
		if cs.CountryCode == "GB" {
			sawGB = true
		}
		for _, excludedCC := range []string{"CN", "RU", "FR", "DE", "JP"} {
			if cs.CountryCode == excludedCC {
				t.Errorf("geo.byCountry contains %s, sourced only from the excluded jail: %+v", excludedCC, snap.Geo.ByCountry)
			}
		}
	}
	if !sawGB {
		t.Errorf("geo.byCountry = %+v, want it to include GB (the kept jail's country)", snap.Geo.ByCountry)
	}

	// 5. activity: attack counts must reflect ONLY the kept jail's single
	// ban, not the excluded jail's 7 historical rows.
	if snap.Activity == nil {
		t.Fatalf("expected an activity section")
	}
	total := 0
	for _, h := range snap.Activity.ByHour {
		total += h.Attacks
	}
	if total != 1 {
		t.Errorf("activity.byHour sums to %d attacks, want 1 (only the kept jail's ban; the excluded jail's 7 rows must not count)", total)
	}

	// 6. alerts: newCountries must include the kept jail's country (GB) and
	// exclude every one of the excluded jail's 5 countries.
	if snap.Alerts == nil {
		t.Fatalf("expected an alerts section")
	}
	sawGB = false
	for _, cc := range snap.Alerts.NewCountries {
		if cc == "GB" {
			sawGB = true
		}
		for _, excludedCC := range []string{"CN", "RU", "FR", "DE", "JP"} {
			if cc == excludedCC {
				t.Errorf("alerts.newCountries contains %s, sourced only from the excluded jail: %v", excludedCC, snap.Alerts.NewCountries)
			}
		}
	}
	if !sawGB {
		t.Errorf("alerts.newCountries = %v, want it to include GB (the kept jail's country)", snap.Alerts.NewCountries)
	}
}
