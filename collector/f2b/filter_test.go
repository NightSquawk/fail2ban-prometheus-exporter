package f2b

import (
	"regexp"
	"testing"

	"github.com/NightSquawk/fail2ban-prometheus-exporter/cfg"
	"github.com/NightSquawk/fail2ban-prometheus-exporter/collector/database"
)

func TestJailFilterAllows(t *testing.T) {
	tests := []struct {
		name    string
		include string
		exclude string
		jail    string
		want    bool
	}{
		{"no patterns allows everything", "", "", "sshd", true},
		{"include matches", "^ssh", "", "sshd", true},
		{"include does not match", "^ssh", "", "apache-auth", false},
		{"exclude matches", "", "recidive", "recidive", false},
		{"exclude does not match", "", "recidive", "sshd", true},
		{"exclude wins over include", "sshd", "sshd", "sshd", false},
		{"patterns are unanchored substrings", "auth", "", "apache-auth", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newJailFilter(cfg.FilterSettings{
				JailInclude: compileOrNil(t, tt.include),
				JailExclude: compileOrNil(t, tt.exclude),
			})
			if got := f.allows(tt.jail); got != tt.want {
				t.Errorf("allows(%q) = %v, want %v", tt.jail, got, tt.want)
			}
		})
	}
}

func compileOrNil(t *testing.T, pattern string) *regexp.Regexp {
	t.Helper()
	if pattern == "" {
		return nil
	}
	return regexp.MustCompile(pattern)
}

func TestJailFilterFilterJailsAndBans(t *testing.T) {
	f := newJailFilter(cfg.FilterSettings{JailExclude: regexp.MustCompile("^recidive$")})

	jails := f.filterJails([]string{"sshd", "recidive", "apache-auth"})
	want := []string{"sshd", "apache-auth"}
	if len(jails) != len(want) {
		t.Fatalf("filterJails() = %v, want %v", jails, want)
	}
	for i := range want {
		if jails[i] != want[i] {
			t.Fatalf("filterJails() = %v, want %v", jails, want)
		}
	}

	bans := f.filterBans([]database.BannedIP{
		{Jail: "sshd", IP: "1.1.1.1"},
		{Jail: "recidive", IP: "2.2.2.2"},
	})
	if len(bans) != 1 || bans[0].Jail != "sshd" {
		t.Errorf("filterBans() = %v, want only the sshd row", bans)
	}
}

// TestJailFilterDisabledReturnsInput pins the fast path: with no patterns the
// filter must hand back the caller's slice rather than an allocated copy.
func TestJailFilterDisabledReturnsInput(t *testing.T) {
	f := newJailFilter(cfg.FilterSettings{})
	in := []string{"sshd"}
	if got := f.filterJails(in); &got[0] != &in[0] {
		t.Error("filterJails copied the slice even though no pattern is configured")
	}
}

func TestIPAnonymizerLabel(t *testing.T) {
	mask := newIPAnonymizer(cfg.PrivacySettings{Mode: cfg.AnonymizeMask, MaskBitsV4: 24, MaskBitsV6: 64})
	tests := []struct {
		in   string
		want string
	}{
		{"203.0.113.42", "203.0.113.0/24"},
		{"2001:db8:1:2:3:4:5:6", "2001:db8:1:2::/64"},
		{"::ffff:203.0.113.42", "203.0.113.0/24"},
		{"not-an-ip", unparseableIPLabel},
	}
	for _, tt := range tests {
		if got := mask.label(tt.in); got != tt.want {
			t.Errorf("mask label(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}

	none := newIPAnonymizer(cfg.PrivacySettings{Mode: cfg.AnonymizeNone})
	if got := none.label("203.0.113.42"); got != "203.0.113.42" {
		t.Errorf("none label() = %q, want the address unchanged", got)
	}
	if none.enabled() {
		t.Error("none mode should report itself as disabled")
	}
}

func TestIPAnonymizerHashIsStableAndSalted(t *testing.T) {
	a := newIPAnonymizer(cfg.PrivacySettings{Mode: cfg.AnonymizeHash, HashSalt: "pepper"})
	first := a.label("203.0.113.42")
	if first == "203.0.113.42" || len(first) != 16 {
		t.Fatalf("hash label = %q, want a 16-character digest", first)
	}
	if second := a.label("203.0.113.42"); second != first {
		t.Errorf("hash label is not stable: %q then %q", first, second)
	}
	if other := a.label("203.0.113.43"); other == first {
		t.Error("distinct addresses hashed to the same label")
	}

	different := newIPAnonymizer(cfg.PrivacySettings{Mode: cfg.AnonymizeHash, HashSalt: "salt"})
	if different.label("203.0.113.42") == first {
		t.Error("a different salt produced the same digest")
	}
}

// TestIPAnonymizerCollapseBans covers the case that would otherwise make Gather
// fail: two addresses in one masked block, in one jail, are one series.
func TestIPAnonymizerCollapseBans(t *testing.T) {
	a := newIPAnonymizer(cfg.PrivacySettings{Mode: cfg.AnonymizeMask, MaskBitsV4: 24, MaskBitsV6: 64})
	collapsed := a.collapseBans([]database.BannedIP{
		{Jail: "sshd", IP: "203.0.113.10", TimeOfBan: 100, BanTime: 60, ExpiryTime: 160},
		{Jail: "sshd", IP: "203.0.113.11", TimeOfBan: 500, BanTime: 60, ExpiryTime: 560},
		{Jail: "apache-auth", IP: "203.0.113.12", TimeOfBan: 300, BanTime: 60, ExpiryTime: 360},
	})

	if len(collapsed) != 2 {
		t.Fatalf("collapseBans() returned %d rows, want 2: %v", len(collapsed), collapsed)
	}
	if collapsed[0].Jail != "sshd" || collapsed[0].IP != "203.0.113.0/24" {
		t.Errorf("first row = %+v, want the sshd 203.0.113.0/24 block", collapsed[0])
	}
	// The most recent ban in the block wins, so ban age and expiry describe the
	// freshest ban rather than an arbitrary one.
	if collapsed[0].TimeOfBan != 500 {
		t.Errorf("collapsed TimeOfBan = %d, want 500 (the most recent ban)", collapsed[0].TimeOfBan)
	}
	if collapsed[1].Jail != "apache-auth" {
		t.Errorf("second row = %+v, want the apache-auth block", collapsed[1])
	}
}

func TestIPAnonymizerCollapseBansDisabled(t *testing.T) {
	a := newIPAnonymizer(cfg.PrivacySettings{Mode: cfg.AnonymizeNone})
	in := []database.BannedIP{
		{Jail: "sshd", IP: "203.0.113.10"},
		{Jail: "sshd", IP: "203.0.113.11"},
	}
	if got := a.collapseBans(in); len(got) != 2 || got[0].IP != "203.0.113.10" {
		t.Errorf("collapseBans() = %v, want the input unchanged", got)
	}
}
