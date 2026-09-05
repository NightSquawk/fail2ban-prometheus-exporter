package cfg

import (
	"regexp"
	"time"

	"github.com/NightSquawk/fail2ban-prometheus-exporter/auth"
)

type GeoSettings struct {
	Enabled  bool
	DBPath   string
	Provider string
}

type CustomerSettings struct {
	ID       string
	Name     string
	TenantID string
}

type AlertSettings struct {
	HighBanRateThreshold    float64
	CoordinatedAttackMinIPs int
	JailInactivityHours     int
}

// FilterSettings restricts which jails are exported. A nil pattern means the
// corresponding rule is disabled.
type FilterSettings struct {
	JailInclude *regexp.Regexp
	JailExclude *regexp.Regexp
}

// AnonymizeMode selects how banned IP addresses are rendered in metric labels.
type AnonymizeMode string

const (
	// AnonymizeNone exports the banned IP address verbatim.
	AnonymizeNone AnonymizeMode = "none"
	// AnonymizeMask truncates the address to a network prefix, e.g. 1.2.3.0/24.
	AnonymizeMask AnonymizeMode = "mask"
	// AnonymizeHash replaces the address with a salted, truncated SHA-256 digest.
	AnonymizeHash AnonymizeMode = "hash"
)

// PrivacySettings controls anonymization of the `ip` label. Geo lookups always
// use the real address; only the exported label is transformed.
type PrivacySettings struct {
	Mode       AnonymizeMode
	MaskBitsV4 int
	MaskBitsV6 int
	HashSalt   string
}

type AppSettings struct {
	VersionMode           bool
	DryRunMode            bool
	MetricsAddress        string
	WebConfigFile         string
	Fail2BanSocketPath    string
	Fail2BanDatabasePath  string
	Fail2BanTimeout       time.Duration
	MaxIPMetrics          int
	DatabaseCacheTTL      int
	FileCollectorPath     string
	AuthProvider          auth.AuthProvider
	ExitOnSocketConnError bool
	Geo                   GeoSettings
	Customer              CustomerSettings
	Alert                 AlertSettings
	Filter                FilterSettings
	Privacy               PrivacySettings
}
