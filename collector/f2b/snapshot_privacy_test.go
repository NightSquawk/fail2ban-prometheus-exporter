package f2b

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"github.com/NightSquawk/fail2ban-prometheus-exporter/cfg"
	"github.com/NightSquawk/fail2ban-prometheus-exporter/collector/database"
)

// goldenFixtureAddresses is every real address appearing in goldenBanRows -
// used to prove none of them leak into anonymized JSON output, in any field.
var goldenFixtureAddresses = []string{
	"203.0.113.99", "203.0.113.10", "203.0.113.11", "203.0.113.12",
	"203.0.113.13", "203.0.113.14", "198.51.100.20", "198.51.100.21",
	"203.0.113.200",
}

// assertNoRawAddressesInJSON marshals snap and fails if any of
// goldenFixtureAddresses appears anywhere in the output, quoted as a JSON
// string value - asserting on the serialised bytes rather than just a
// struct field, so a stray field elsewhere cannot leak an address that a
// more narrowly-scoped assertion would miss.
func assertNoRawAddressesInJSON(t *testing.T, snap *Snapshot) {
	t.Helper()
	body, err := json.Marshal(snap)
	if err != nil {
		t.Fatalf("marshal snapshot: %v", err)
	}
	for _, ip := range goldenFixtureAddresses {
		needle := []byte(`"` + ip + `"`)
		if bytes.Contains(body, needle) {
			t.Errorf("marshalled JSON leaked the real address %s:\n%s", ip, body)
		}
	}
}

// TestSnapshotPatternsIPIsAnonymized covers the highest-risk gap in the
// /metrics.json feature: patterns[].ip is a JSON-only surface with no
// Prometheus analogue - f2b_attack_pattern_type deliberately carries no
// per-IP label to keep cardinality bounded (docs/metrics-json-schema-v1.md
// §3.3) - so nothing in the pre-existing Prometheus code path ever
// anonymized it, and buildPatternsAndActivity (snapshot.go) feeds the
// pattern detector the real address. Under both --collector.f2b.
// ip-anonymize modes, patterns[].ip must be the anonymized label, and the
// real attacking address must not appear anywhere in the marshalled JSON.
func TestSnapshotPatternsIPIsAnonymized(t *testing.T) {
	// goldenBanRows: 203.0.113.10 bans sshd 3 times inside the 48h pattern
	// window, tripping DetectBruteForce with that IP as the attribution.
	const attackerIP = "203.0.113.10"

	tests := []struct {
		name     string
		settings cfg.PrivacySettings
		wantIP   string // exact expected label; empty means "assert shape only" (hash).
	}{
		{
			name:     "mask",
			settings: cfg.PrivacySettings{Mode: cfg.AnonymizeMask, MaskBitsV4: 24, MaskBitsV6: 64},
			wantIP:   "203.0.113.0/24",
		},
		{
			name:     "hash",
			settings: cfg.PrivacySettings{Mode: cfg.AnonymizeHash, HashSalt: "test-salt"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := newFakeF2BServer(t, goldenSocketFixture())
			db := newFixtureDatabase(t, goldenBanRows())
			c := newGoldenCollector(srv, db)
			c.ipAnon = newIPAnonymizer(tt.settings)

			snap, err := c.Snapshot(SnapshotOptions{Include: map[string]bool{"patterns": true}})
			if err != nil {
				t.Fatalf("Snapshot: %v", err)
			}
			if snap.Patterns == nil {
				t.Fatalf("expected a patterns section")
			}

			var sawBruteForce bool
			for _, p := range *snap.Patterns {
				if p.Type != "brute_force" {
					// port_scan/distributed always carry ip="" regardless
					// of anonymization - nothing to check on those rows.
					continue
				}
				sawBruteForce = true
				if p.IP == attackerIP {
					t.Errorf("patterns[].ip = %q, still the raw attacking address", p.IP)
				}
				if p.IP == "" {
					t.Errorf("patterns[].ip is empty for a brute_force pattern, want the anonymized label")
				}
				if tt.wantIP != "" && p.IP != tt.wantIP {
					t.Errorf("patterns[].ip = %q, want %q", p.IP, tt.wantIP)
				}
				if tt.name == "hash" && len(p.IP) != 16 {
					t.Errorf("hashed patterns[].ip = %q, want a 16-character digest", p.IP)
				}
			}
			if !sawBruteForce {
				t.Fatalf("expected the golden fixture to trip DetectBruteForce for %s, got %+v", attackerIP, *snap.Patterns)
			}

			assertNoRawAddressesInJSON(t, snap)
		})
	}
}

// TestSnapshotBansAnonymizationAndCollapse proves the full set of claims
// docs/metrics-json-schema-v1.md §3.2 makes about bans.items under
// --collector.f2b.ip-anonymize=mask:
//
//   - items[].ip is the anonymized label, never the raw address.
//   - items collapse on (jail, label), most-recent-ban-wins.
//   - total/returned/truncated all count POST-collapse rows.
//   - banCount/firstSeenAt/lastSeenAt/repeatOffender are label-scoped ACROSS
//     jails: two items sharing a label in different jails report identical
//     values for all four, aggregating the label's entire ban history.
//   - geo is looked up from the REAL address that won the collapse, so
//     masking does not suppress geolocation.
//
// The fixture puts four distinct real addresses in one masked /24 block,
// split across two jails, so the collapse actually engages across a jail
// boundary rather than only within one jail.
func TestSnapshotBansAnonymizationAndCollapse(t *testing.T) {
	now := time.Now().Unix()
	const activeBanTime = 100 * secondsPerYear

	rows := []database.BannedIP{
		// sshd: two real addresses collapse onto one masked block; the
		// more recent one (.10) must win the collapse.
		{Jail: "sshd", IP: "203.0.113.10", TimeOfBan: now - 100, BanTime: activeBanTime},
		{Jail: "sshd", IP: "203.0.113.11", TimeOfBan: now - 500000, BanTime: activeBanTime},
		// apache-auth: a third real address in the SAME masked block but a
		// DIFFERENT jail - collapse key is (jail, label), so this stays a
		// separate item from sshd's, even though the label is identical.
		{Jail: "apache-auth", IP: "203.0.113.12", TimeOfBan: now - 200000, BanTime: activeBanTime},
		// Purely historical (long expired) entry for a FOURTH real address
		// in the same masked block: contributes to the label's banCount/
		// firstSeenAt/lastSeenAt across jails without adding a fourth
		// active bans.items row.
		{Jail: "apache-auth", IP: "203.0.113.13", TimeOfBan: now - 900000, BanTime: 60},
		// Unrelated control row in a distinct masked block, for contrast:
		// its label's history must NOT be affected by the shared block.
		{Jail: "apache-auth", IP: "198.51.100.5", TimeOfBan: now - 300, BanTime: activeBanTime},
	}

	geoRecords := map[string]geoRecord{
		"203.0.113.10": {"New York", "40.712800", "-74.006000", "United States", "US"},
		"203.0.113.11": {"Beijing", "39.904200", "116.407400", "China", "CN"},
		"203.0.113.12": {"Moscow", "55.755800", "37.617300", "Russia", "RU"},
		"203.0.113.13": {"Paris", "48.856600", "2.352200", "France", "FR"},
		"198.51.100.5": {"Tokyo", "35.676200", "139.650300", "Japan", "JP"},
	}

	srv := newFakeF2BServer(t, goldenSocketFixture())
	db := newFixtureDatabase(t, rows)
	c := newGoldenCollector(srv, db)
	c.ipAnon = newIPAnonymizer(cfg.PrivacySettings{Mode: cfg.AnonymizeMask, MaskBitsV4: 24, MaskBitsV6: 64})
	c.geoProvider = &fakeGeoProvider{records: geoRecords}

	snap, err := c.Snapshot(SnapshotOptions{Include: map[string]bool{"bans": true}})
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	if snap.Bans == nil {
		t.Fatalf("expected a bans section")
	}

	const sharedLabel = "203.0.113.0/24"
	const controlLabel = "198.51.100.0/24"

	if snap.Bans.Total != 3 {
		t.Fatalf("bans.total = %d, want 3 post-collapse rows (4 active raw rows collapse to 3)", snap.Bans.Total)
	}
	if snap.Bans.Returned != 3 {
		t.Fatalf("bans.returned = %d, want 3", snap.Bans.Returned)
	}
	if snap.Bans.Truncated {
		t.Fatalf("bans.truncated = true, want false (no cap in effect)")
	}
	if len(snap.Bans.Items) != 3 {
		t.Fatalf("len(items) = %d, want 3", len(snap.Bans.Items))
	}

	var sshdItem, apacheSharedItem, controlItem *BanItem
	for i := range snap.Bans.Items {
		item := &snap.Bans.Items[i]
		for _, raw := range []string{"203.0.113.10", "203.0.113.11", "203.0.113.12", "203.0.113.13", "198.51.100.5"} {
			if item.IP == raw {
				t.Errorf("items[%d].ip = %q, still a raw address", i, item.IP)
			}
		}
		switch {
		case item.Jail == "sshd" && item.IP == sharedLabel:
			sshdItem = item
		case item.Jail == "apache-auth" && item.IP == sharedLabel:
			apacheSharedItem = item
		case item.Jail == "apache-auth" && item.IP == controlLabel:
			controlItem = item
		}
	}
	if sshdItem == nil || apacheSharedItem == nil || controlItem == nil {
		t.Fatalf("expected exactly the 3 collapsed rows (sshd/%s, apache-auth/%s, apache-auth/%s), got %+v",
			sharedLabel, sharedLabel, controlLabel, snap.Bans.Items)
	}

	// Most-recent-ban-wins: sshd's masked item must reflect .10 (now-100),
	// not .11 (now-500000) - the older record is dropped, not merged.
	wantBannedAt := time.Unix(now-100, 0).UTC()
	if !sshdItem.BannedAt.Equal(wantBannedAt) {
		t.Errorf("sshd/%s bannedAt = %v, want %v (the most recent ban in the collapsed group)", sharedLabel, sshdItem.BannedAt, wantBannedAt)
	}

	// banCount/firstSeenAt/lastSeenAt/repeatOffender are IP-label-scoped
	// ACROSS jails: sshd's and apache-auth's items sharing the label must
	// report IDENTICAL values, aggregating all 4 historical entries
	// assigned to that label (2 from sshd, 2 from apache-auth) - even
	// though apache-auth's own jail only ever recorded 1 of them.
	if sshdItem.BanCount != 4 || apacheSharedItem.BanCount != 4 {
		t.Errorf("banCount = sshd:%d apache-auth:%d, want 4/4 (label history spans both jails)", sshdItem.BanCount, apacheSharedItem.BanCount)
	}
	if !sshdItem.RepeatOffender || !apacheSharedItem.RepeatOffender {
		t.Errorf("repeatOffender = sshd:%v apache-auth:%v, want true/true", sshdItem.RepeatOffender, apacheSharedItem.RepeatOffender)
	}
	if sshdItem.FirstSeenAt == nil || apacheSharedItem.FirstSeenAt == nil || !sshdItem.FirstSeenAt.Equal(*apacheSharedItem.FirstSeenAt) {
		t.Errorf("firstSeenAt disagrees between jails sharing a label: %v vs %v", sshdItem.FirstSeenAt, apacheSharedItem.FirstSeenAt)
	}
	if sshdItem.LastSeenAt == nil || apacheSharedItem.LastSeenAt == nil || !sshdItem.LastSeenAt.Equal(*apacheSharedItem.LastSeenAt) {
		t.Errorf("lastSeenAt disagrees between jails sharing a label: %v vs %v", sshdItem.LastSeenAt, apacheSharedItem.LastSeenAt)
	}
	wantFirstSeen := time.Unix(now-900000, 0).UTC()
	wantLastSeen := time.Unix(now-100, 0).UTC()
	if sshdItem.FirstSeenAt == nil || !sshdItem.FirstSeenAt.Equal(wantFirstSeen) {
		t.Errorf("firstSeenAt = %v, want %v", sshdItem.FirstSeenAt, wantFirstSeen)
	}
	if sshdItem.LastSeenAt == nil || !sshdItem.LastSeenAt.Equal(wantLastSeen) {
		t.Errorf("lastSeenAt = %v, want %v", sshdItem.LastSeenAt, wantLastSeen)
	}

	// The control item's label is untouched by the shared block and must
	// report its own, much smaller, history - proving the cross-jail
	// aggregation above is scoped by label, not accidentally global.
	if controlItem.BanCount != 1 || controlItem.RepeatOffender {
		t.Errorf("control item banCount/repeatOffender = %d/%v, want 1/false", controlItem.BanCount, controlItem.RepeatOffender)
	}

	// Geo is derived from the REAL address that won the collapse (.10 for
	// sshd, .12 for apache-auth), not suppressed by masking and not pinned
	// to any single canonical address for the block.
	if sshdItem.Geo == nil || sshdItem.Geo.City != "New York" {
		t.Errorf("sshd item geo = %+v, want city New York (.10, the real address that won the collapse)", sshdItem.Geo)
	}
	if apacheSharedItem.Geo == nil || apacheSharedItem.Geo.City != "Moscow" {
		t.Errorf("apache-auth item geo = %+v, want city Moscow (.12, the real address that won the collapse)", apacheSharedItem.Geo)
	}

	// Defense in depth: no raw address anywhere in the marshalled JSON,
	// including inside the geo object (which must describe cities, never
	// echo an address).
	body, err := json.Marshal(snap)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for _, ip := range []string{"203.0.113.10", "203.0.113.11", "203.0.113.12", "203.0.113.13", "198.51.100.5"} {
		if bytes.Contains(body, []byte(`"`+ip+`"`)) {
			t.Errorf("marshalled JSON leaked raw address %s:\n%s", ip, body)
		}
	}
}
