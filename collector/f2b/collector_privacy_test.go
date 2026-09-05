package f2b

import (
	"regexp"
	"strings"
	"testing"

	"github.com/NightSquawk/fail2ban-prometheus-exporter/cfg"
	"github.com/prometheus/client_golang/prometheus"
)

// TestCollectWithJailFilterAndMasking drives the full collector against the
// same fixtures as the golden test, with a jail excluded and IP masking on.
// Gathering at all is half the assertion: the sshd fixture bans three addresses
// inside one /24, which would be three series with identical labels if
// collapseBans were not applied.
func TestCollectWithJailFilterAndMasking(t *testing.T) {
	srv := newFakeF2BServer(t, goldenSocketFixture())
	db := newFixtureDatabase(t, goldenBanRows())
	c := newGoldenCollector(srv, db)
	c.jails = newJailFilter(cfg.FilterSettings{JailExclude: regexp.MustCompile("^recidive$")})
	c.ipAnon = newIPAnonymizer(cfg.PrivacySettings{Mode: cfg.AnonymizeMask, MaskBitsV4: 24, MaskBitsV6: 64})

	reg := prometheus.NewRegistry()
	if err := reg.Register(c); err != nil {
		t.Fatalf("register collector: %v", err)
	}
	out := renderMetrics(t, reg)

	if strings.Contains(out, `jail="recidive"`) {
		t.Error("excluded jail 'recidive' still appears in the exported metrics")
	}
	if !strings.Contains(out, `jail="sshd"`) || !strings.Contains(out, `jail="apache-auth"`) {
		t.Error("expected the non-excluded jails to still be exported")
	}

	// jail_count reports the filtered view, not fail2ban's three configured jails.
	if !strings.Contains(out, `f2b_jail_count{customer_id="cust-1",customer_name="Acme Corp",system="test-host",tenant_id="tenant-42"} 2`) {
		t.Errorf("f2b_jail_count does not reflect the jail filter:\n%s", familyBlocks(out)["f2b_jail_count"])
	}

	bannedIP := familyBlocks(out)["f2b_banned_ip"]
	if strings.Contains(bannedIP, `ip="203.0.113.10"`) {
		t.Errorf("f2b_banned_ip leaked an unmasked address:\n%s", bannedIP)
	}
	if !strings.Contains(bannedIP, `ip="203.0.113.0/24"`) {
		t.Errorf("f2b_banned_ip is missing the masked block:\n%s", bannedIP)
	}
	// The sshd fixture's three banned addresses all live in that one block.
	if got := strings.Count(bannedIP, `jail="sshd"`); got != 1 {
		t.Errorf("expected sshd's banned addresses to collapse into 1 series, got %d:\n%s", got, bannedIP)
	}
}

// TestCollectWithHashingHidesAddresses checks the other anonymization mode
// still produces a gatherable, address-free exposition.
func TestCollectWithHashingHidesAddresses(t *testing.T) {
	srv := newFakeF2BServer(t, goldenSocketFixture())
	db := newFixtureDatabase(t, goldenBanRows())
	c := newGoldenCollector(srv, db)
	c.ipAnon = newIPAnonymizer(cfg.PrivacySettings{Mode: cfg.AnonymizeHash, HashSalt: "test-salt"})

	reg := prometheus.NewRegistry()
	if err := reg.Register(c); err != nil {
		t.Fatalf("register collector: %v", err)
	}
	out := renderMetrics(t, reg)

	for _, ip := range []string{"203.0.113.10", "203.0.113.99", "198.51.100.20"} {
		if strings.Contains(out, `ip="`+ip+`"`) {
			t.Errorf("hashed output still contains the raw address %s", ip)
		}
	}
	if !strings.Contains(out, "f2b_banned_ip{") {
		t.Error("expected f2b_banned_ip to still be exported when hashing")
	}
	// Geo labels are derived from the real address, so hashing the label must
	// not cost the geo annotation.
	if !strings.Contains(out, `city="New York"`) {
		t.Errorf("geo labels were lost when hashing the ip label:\n%s", familyBlocks(out)["f2b_banned_ip"])
	}
}
