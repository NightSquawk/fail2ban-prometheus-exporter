package f2b

import (
	"log"
	"math"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/NightSquawk/fail2ban-prometheus-exporter/collector/database"
	"github.com/NightSquawk/fail2ban-prometheus-exporter/geo"
	"github.com/NightSquawk/fail2ban-prometheus-exporter/socket"
)

// exporterName is the constant "name" field of the JSON envelope. It has no
// Prometheus analogue (the "exporter" label on f2b_version carries the
// version string, not this name).
const exporterName = "fail2ban-prometheus-exporter"

// BuildInfo carries version metadata injected by main via -ldflags, so the
// JSON envelope's exporter.commit has somewhere to come from. Version alone
// already reaches /metrics through the f2b_version gauge's "exporter" label.
type BuildInfo struct {
	Version string
	Commit  string
}

// SnapshotOptions selects what a gather computes.
type SnapshotOptions struct {
	// Include gates the optional sections by their schema name ("jails",
	// "bans", "patterns", "geo", "activity", "alerts"). The envelope is
	// always computed.
	Include map[string]bool
	// MaxIPs caps bans.items. 0 means the collector's configured ceiling.
	MaxIPs int
	// MutateAlertState is true only for Collect(). See the alert-state
	// fields on AlertsSnapshot for what that gates.
	MutateAlertState bool
	// HonorExitOnSocketConnError gates whether a failed top-level socket
	// dial may call os.Exit(1) per --collector.f2b.exit-on-socket-
	// connection-error. Only Collect() (the /metrics scrape path) sets this
	// true. Any other caller - including a future /metrics.json handler -
	// must leave it false, so a down socket degrades to the documented
	// fail2ban.up=false response (docs/metrics-json-schema-v1.md §1.4)
	// instead of killing the process on a routine, authenticated GET.
	HonorExitOnSocketConnError bool
}

// allSections is every section Collect() always wants; a full gather behind
// /metrics never has a reason to skip one. It also enumerates every valid
// section name - see ValidSections.
var allSections = map[string]bool{
	"jails":    true,
	"bans":     true,
	"patterns": true,
	"geo":      true,
	"activity": true,
	"alerts":   true,
}

// defaultIncludeSections is what /metrics.json gathers when its include query
// parameter is omitted (docs/metrics-json-schema-v1.md §1.1: "jails,alerts").
var defaultIncludeSections = map[string]bool{
	"jails":  true,
	"alerts": true,
}

// ValidSections returns a fresh copy of every section name SnapshotOptions.
// Include accepts ("jails", "bans", "patterns", "geo", "activity", "alerts").
// The collector is the single source of truth for this set; callers (e.g.
// the /metrics.json handler validating its include query parameter) must use
// this instead of hardcoding a second copy of the list. Each call returns a
// new map so a caller cannot mutate package state.
func ValidSections() map[string]bool {
	return cloneSectionSet(allSections)
}

// DefaultSections returns a fresh copy of the sections /metrics.json gathers
// when its include query parameter is absent (docs/metrics-json-schema-v1.md
// §1.1). Each call returns a new map so a caller cannot mutate package state.
func DefaultSections() map[string]bool {
	return cloneSectionSet(defaultIncludeSections)
}

func cloneSectionSet(src map[string]bool) map[string]bool {
	out := make(map[string]bool, len(src))
	for k, v := range src {
		out[k] = v
	}
	return out
}

// EffectiveMaxIPs resolves requested (a raw, already-validated maxIps query
// value; 0 means "not specified") against the collector's configured ceiling
// (--collector.f2b.max-ip-metrics), per the table in
// docs/metrics-json-schema-v1.md §1.2. buildBans uses this to cap
// bans.items, and any caller computing the ETag's request-scope digest
// (docs/metrics-json-schema-v1.md §1.3, "plus the effective maxIps") must
// resolve the SAME value through this method rather than hashing the raw
// request value - otherwise two requests that clamp to an identical
// effective cap, and therefore serve byte-identical bodies, would disagree
// on ETag. maxIPMetrics is set once at construction and never mutated
// afterward, so this is safe to call without holding c.mu.
func (c *Collector) EffectiveMaxIPs(requested int) int {
	if requested <= 0 {
		return c.maxIPMetrics
	}
	if c.maxIPMetrics > 0 && requested > c.maxIPMetrics {
		return c.maxIPMetrics
	}
	return requested
}

// ExporterInfo is the envelope's "exporter" object.
type ExporterInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Commit  string `json:"commit"`
}

// HostInfo is the envelope's "host" object.
type HostInfo struct {
	Hostname string `json:"hostname"`
}

// LabelsInfo is the envelope's "labels" object: the multi-tenant labels
// applied to every Prometheus series, mirrored verbatim.
type LabelsInfo struct {
	CustomerID   string `json:"customerId"`
	CustomerName string `json:"customerName"`
	TenantID     string `json:"tenantId"`
}

// Fail2banInfo is the envelope's "fail2ban" object.
type Fail2banInfo struct {
	Up              bool   `json:"up"`
	Version         string `json:"version"`
	DatabaseEnabled bool   `json:"databaseEnabled"`
	GeoEnabled      bool   `json:"geoEnabled"`
}

// ErrorsInfo is the envelope's "errors" object.
type ErrorsInfo struct {
	SocketConn int `json:"socketConn"`
	SocketReq  int `json:"socketReq"`
	Collection int `json:"collection"`
}

// JailFilterCounts is one jail's "filter" object (section 3.1).
type JailFilterCounts struct {
	CurrentlyFailed int `json:"currentlyFailed"`
	TotalFailed     int `json:"totalFailed"`
}

// JailActionCounts is one jail's "actions" object (section 3.1).
type JailActionCounts struct {
	CurrentlyBanned int `json:"currentlyBanned"`
	TotalBanned     int `json:"totalBanned"`
}

// JailConfigCounts is one jail's "config" object (section 3.1).
type JailConfigCounts struct {
	BanTimeSeconds  int `json:"banTimeSeconds"`
	FindTimeSeconds int `json:"findTimeSeconds"`
	MaxRetry        int `json:"maxRetry"`
}

// JailSnapshot is one entry of the "jails" array (section 3.1).
type JailSnapshot struct {
	Name    string           `json:"name"`
	Filter  JailFilterCounts `json:"filter"`
	Actions JailActionCounts `json:"actions"`
	Config  JailConfigCounts `json:"config"`

	// statsOK/banTimeOK/findTimeOK/maxRetryOK gate the corresponding
	// Prometheus gauges. The socket layer reports a field it could not
	// supply as a -1 sentinel (or, on a wholesale decode failure, leaves
	// the whole group at its zero value) but does not itself distinguish
	// "no sample" from "sample is -1" - Prometheus has always simply
	// skipped the gauge on any such error rather than exporting the
	// sentinel, and JSON surfaces the raw value unconditionally instead.
	statsOK    bool
	banTimeOK  bool
	findTimeOK bool
	maxRetryOK bool
}

// GeoPoint is a ban's "geo" object (section 3.2).
type GeoPoint struct {
	CountryCode string   `json:"countryCode"`
	Country     string   `json:"country"`
	City        string   `json:"city"`
	Lat         *float64 `json:"lat,omitempty"`
	Lon         *float64 `json:"lon,omitempty"`
}

// BanItem is one entry of bans.items (section 3.2).
type BanItem struct {
	Jail             string     `json:"jail"`
	IP               string     `json:"ip"`
	BannedAt         time.Time  `json:"bannedAt"`
	ExpiresAt        time.Time  `json:"expiresAt"`
	AgeSeconds       int64      `json:"ageSeconds"`
	RemainingSeconds int64      `json:"remainingSeconds"`
	BanCount         int        `json:"banCount"`
	FirstSeenAt      *time.Time `json:"firstSeenAt"`
	LastSeenAt       *time.Time `json:"lastSeenAt"`
	RepeatOffender   bool       `json:"repeatOffender"`
	Geo              *GeoPoint  `json:"geo,omitempty"`
}

// BansSnapshot is the "bans" section (section 3.2).
type BansSnapshot struct {
	Returned  int       `json:"returned"`
	Total     int       `json:"total"`
	Truncated bool      `json:"truncated"`
	Items     []BanItem `json:"items"`
}

// PatternSnapshot is one entry of the "patterns" array (section 3.3).
type PatternSnapshot struct {
	Type  string  `json:"type"`
	Jail  string  `json:"jail"`
	IP    string  `json:"ip"`
	Score float64 `json:"score"`
}

// CountryAttackStat is one entry of geo.byCountry (section 3.4).
type CountryAttackStat struct {
	CountryCode string `json:"countryCode"`
	Country     string `json:"country"`
	Attacks     int    `json:"attacks"`
	Rank        int    `json:"rank"`
}

// CityAttackStat is one entry of geo.byCity (section 3.4).
type CityAttackStat struct {
	City        string `json:"city"`
	CountryCode string `json:"countryCode"`
	Country     string `json:"country"`
	Attacks     int    `json:"attacks"`
}

// GeoSnapshot is the "geo" section (section 3.4).
type GeoSnapshot struct {
	ByCountry []CountryAttackStat `json:"byCountry"`
	ByCity    []CityAttackStat    `json:"byCity"`
}

// HourlyActivity is one entry of activity.byHour (section 3.5).
type HourlyActivity struct {
	Hour    int `json:"hour"`
	Attacks int `json:"attacks"`
}

// DailyActivity is one entry of activity.byDayOfWeek (section 3.5).
type DailyActivity struct {
	Day     int `json:"day"`
	Attacks int `json:"attacks"`
}

// ActivitySnapshot is the "activity" section (section 3.5): always
// zero-filled (24 hours, 7 days), unlike the sparse Prometheus families this
// gather also feeds.
type ActivitySnapshot struct {
	ByHour          []HourlyActivity `json:"byHour"`
	ByDayOfWeek     []DailyActivity  `json:"byDayOfWeek"`
	VelocityPerHour float64          `json:"velocityPerHour"`
	SuspiciousScore float64          `json:"suspiciousScore"`
}

// CoordinatedAttack is one entry of alerts.coordinatedAttack (section 3.6).
type CoordinatedAttack struct {
	Jail        string `json:"jail"`
	CountryCode string `json:"countryCode"`
}

// AlertsSnapshot is the "alerts" section (section 3.6). newCountries and
// repeatOffenderSpike are edge-triggered: the fields below capture enough of
// that edge for the mutation to be applied (or not) after the fact, per
// SnapshotOptions.MutateAlertState.
type AlertsSnapshot struct {
	HighBanRate         bool                `json:"highBanRate"`
	RepeatOffenderSpike bool                `json:"repeatOffenderSpike"`
	NewCountries        []string            `json:"newCountries"`
	JailInactive        []string            `json:"jailInactive"`
	CoordinatedAttack   []CoordinatedAttack `json:"coordinatedAttack"`

	// hasBaseline gates f2b_alert_high_ban_rate, which Prometheus has never
	// exported until a prior gather established c.lastCollectionTime. JSON
	// always shows HighBanRate, defaulting to false with no baseline.
	hasBaseline bool
	// gatheredOK is true when this gather's own socket dial and GetJails
	// both succeeded - only then does the original code (and now this one)
	// advance c.lastCollectionTime / c.lastJailActivity / c.seenCountries.
	gatheredOK bool
	// activeJails is this gather's set of jails observed with current
	// activity, applied to c.lastJailActivity only if MutateAlertState.
	activeJails map[string]bool
	// repeatOffenderComputed gates both f2b_alert_repeat_offender_spike and
	// the c.lastRepeatOffenderCount mutation: the original code skips both
	// when getAllBans() itself failed, even though c.db != nil.
	repeatOffenderComputed bool
	repeatOffenderCount    int
	// currentTime is this gather's nowFn().Unix(), reused for the
	// c.lastJailActivity / c.lastCollectionTime writes.
	currentTime int64
}

// Snapshot is the whole domain state of one gather. Exported, JSON-tagged
// fields are schema v1 (docs/metrics-json-schema-v1.md); unexported fields
// carry Prometheus-only detail that has no JSON representation, or JSON-only
// detail Prometheus never needed - the two exposition formats genuinely
// differ (see the package-level docs), and this is how one gather serves
// both without distorting either.
type Snapshot struct {
	SchemaVersion        int          `json:"schemaVersion"`
	CollectedAt          time.Time    `json:"collectedAt"`
	CollectionDurationMs int64        `json:"collectionDurationMs"`
	Exporter             ExporterInfo `json:"exporter"`
	Host                 HostInfo     `json:"host"`
	Labels               LabelsInfo   `json:"labels"`
	Fail2ban             Fail2banInfo `json:"fail2ban"`
	Errors               ErrorsInfo   `json:"errors"`

	// Jails and Patterns are *[]T (not []T) so that "section not requested"
	// (nil pointer, omitted by omitempty) and "section requested but empty"
	// (non-nil pointer to a zero-length slice, marshaled as "[]") are
	// distinguishable, mirroring how Bans/Geo/Activity/Alerts already behave
	// via *T. A plain []T with `omitempty` cannot make this distinction:
	// encoding/json drops the key whenever len() == 0 regardless of nilness.
	Jails    *[]JailSnapshot    `json:"jails,omitempty"`
	Bans     *BansSnapshot      `json:"bans,omitempty"`
	Patterns *[]PatternSnapshot `json:"patterns,omitempty"`
	Geo      *GeoSnapshot       `json:"geo,omitempty"`
	Activity *ActivitySnapshot  `json:"activity,omitempty"`
	Alerts   *AlertsSnapshot    `json:"alerts,omitempty"`

	// --- Prometheus-only bookkeeping below; flatten() reads all of it so it
	// never has to touch Collector's mutable state directly.

	// topDialOK mirrors "err == nil && s != nil" on the single top-level
	// socket dial: it gates f2b_jail_count, the per-jail families and
	// f2b_version, exactly as it always has.
	topDialOK bool
	// dbAvailable is c.db != nil, captured once so every DB-gated family
	// (and the +2 metricsExported contribution) reads a consistent value.
	dbAvailable bool
	// jailCount is fail2ban's filtered jail count, tracked independently of
	// len(Jails) because Jails is only populated when "jails" is included.
	jailCount int

	// bannedIPs backs f2b_banned_ip. It has no JSON analogue: bans.items
	// (below) is a different, DB-sourced gather of "currently banned",
	// carrying ban timing bannedIPs does not have.
	bannedIPs []bannedIPSeries

	// historyByIP/historyOK/historyExported/banHistoryTotal back
	// f2b_ip_ban_count_total and siblings, and feed bans.items's
	// banCount/firstSeenAt/lastSeenAt/repeatOffender (properties of the IP
	// label across all jails, per docs/metrics-json-schema-v1.md §3.2).
	historyOK       bool
	historyByIP     map[string]ipHistoryStat
	historyExported []ipHistoryStat
	banHistoryTotal int

	// patternsOK/patternCounts/nonZeroHours/nonZeroDays/velocity/
	// suspiciousScore back f2b_attack_pattern_type, f2b_attacks_by_hour,
	// f2b_attacks_by_day_of_week, f2b_attack_velocity and
	// f2b_suspicious_pattern_score. Unlike Activity above (zero-filled),
	// nonZeroHours/nonZeroDays only carry buckets that have data, matching
	// what Prometheus has always emitted.
	patternsOK      bool
	patternCounts   map[patternCountKey]int
	nonZeroHours    map[int]int
	nonZeroDays     map[int]int
	velocity        float64
	suspiciousScore float64

	// countryCounts/cityCounts back f2b_attacks_by_country_total,
	// f2b_attacks_by_city_total and f2b_geographic_attack_rate. Geo.ByCountry
	// (JSON) is the same aggregation, ranked and without the top-10 cutoff
	// f2b_top_attack_countries applies.
	countryCounts map[string]countryAgg
	cityCounts    map[string]cityAgg

	// collectionDuration/dbQueryDuration/geoLookupDuration back the three
	// *_duration_seconds gauges.
	collectionDuration time.Duration
	dbQueryDuration    time.Duration
	geoLookupDuration  time.Duration
}

// patternCountKey groups f2b_attack_pattern_type by (pattern_type, jail),
// deliberately excluding per-IP attribution to keep cardinality bounded -
// see patterns.go and docs/metrics-json-schema-v1.md §3.3.
type patternCountKey struct {
	patternType string
	jail        string
}

// bannedIPSeries is one f2b_banned_ip series, sourced from the socket's live
// per-jail banned-IP list. It has no JSON analogue.
type bannedIPSeries struct {
	jail                                            string
	ipLabel                                         string
	city, latitude, longitude, country, countryCode string
}

// ipHistoryStat is one IP label's aggregate across the whole ban history.
type ipHistoryStat struct {
	label     string
	banCount  int
	firstSeen int64
	lastSeen  int64
}

// countryAgg is one country's attack aggregate, sourced from the socket's
// live currently-banned IPs (distinct from the DB-sourced bans section).
type countryAgg struct {
	count int
	name  string
}

// cityAgg is one city's attack aggregate, keyed alongside its country.
type cityAgg struct {
	count       int
	countryCode string
	countryName string
}

// collapsedActiveBan is one row of the post-collapse active-ban list shared
// by the Prometheus ban_age/duration/expiry family and bans.items. realIP is
// the address before anonymization: geo always looks up the real address
// even when IP (below) is a masked or hashed label, per
// docs/metrics-json-schema-v1.md §3.2.
type collapsedActiveBan struct {
	database.BannedIP
	realIP string
}

// finiteOrZero guards a float before it enters the Snapshot: NaN and ±Inf
// are legal in the Prometheus text format but make encoding/json.Marshal
// fail the entire /metrics.json response, so every float that could
// theoretically go non-finite is clamped once here rather than at the
// (several) points it might later be serialized.
func finiteOrZero(f float64) float64 {
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return 0
	}
	return f
}

// Snapshot takes c.mu and gathers a fresh domain snapshot per opts. Safe to
// call concurrently with Collect and IsHealthy.
func (c *Collector) Snapshot(opts SnapshotOptions) (*Snapshot, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.snapshotLocked(opts)
}

// snapshotLocked gathers a Snapshot per opts. Callers must already hold c.mu;
// sync.Mutex is not reentrant, so this must never call Snapshot or take the
// lock itself.
func (c *Collector) snapshotLocked(opts SnapshotOptions) (*Snapshot, error) {
	gatherStart := c.nowFn()
	var collectionErrors int

	snap := &Snapshot{
		SchemaVersion: 1,
		// Truncated to whole seconds: the schema documents CollectedAt as
		// second-precision RFC3339 ("...41Z", never "...41.123456789Z"), but
		// gatherStart carries whatever sub-second resolution nowFn() returns
		// (the real clock, or the ticking test clock), and encoding/json's
		// default time.Time marshalling is RFC3339Nano unless truncated here.
		CollectedAt: gatherStart.UTC().Truncate(time.Second),
		Exporter: ExporterInfo{
			Name:    exporterName,
			Version: c.exporterVersion,
			Commit:  c.exporterCommit,
		},
		Host: HostInfo{Hostname: c.hostname},
		Labels: LabelsInfo{
			CustomerID:   c.customerID,
			CustomerName: c.customerName,
			TenantID:     c.tenantID,
		},
		Fail2ban: Fail2banInfo{
			DatabaseEnabled: c.db != nil,
			GeoEnabled:      c.geoEnabled && c.geoProvider != nil,
		},
		dbAvailable: c.db != nil,
	}

	// --- Top-level dial: server up, jail list/stats/config, server version.
	// This is the ONLY dial that increments socketConnectionErrorCount,
	// advances collectionErrors or honours --collector.f2b.exit-on-socket-
	// connection-error. Every other socket-touching section below opens its
	// own independent connection and fails silently by design - see
	// collector.go's package docs before consolidating any of them.
	s, err := socket.ConnectToSocketTimeout(c.socketPath, c.socketTimeout)
	if err != nil {
		log.Printf("error opening socket: %v", err)
		c.socketConnectionErrorCount++
		collectionErrors++
		if c.exitOnSocketConnError && opts.HonorExitOnSocketConnError {
			os.Exit(1)
		}
	} else {
		defer s.Close()
	}
	snap.topDialOK = err == nil && s != nil

	c.buildServerUpAndJails(snap, opts, s)

	// --- banned-IP series: own dial, silent failure, unconditional (no JSON
	// section gates it; f2b_banned_ip has always been emitted every gather).
	bannedIPStart := c.nowFn()
	snap.bannedIPs = c.buildBannedIPSeries()

	// --- bans + historical stats: DB only (cached via getActiveBans/
	// getAllBans), no socket dial.
	needHistory := (opts.Include["bans"] || opts.Include["alerts"]) && snap.dbAvailable
	if needHistory {
		t0 := c.nowFn()
		c.buildHistoricalStats(snap)
		snap.dbQueryDuration += c.nowFn().Sub(t0)
	}
	if opts.Include["bans"] {
		if snap.dbAvailable {
			t0 := c.nowFn()
			c.buildBans(snap, opts, gatherStart)
			snap.dbQueryDuration += c.nowFn().Sub(t0)
		} else {
			snap.Bans = &BansSnapshot{Items: []BanItem{}}
		}
	}

	// --- patterns + activity: DB only, no socket dial.
	if opts.Include["patterns"] || opts.Include["activity"] {
		if snap.dbAvailable {
			c.buildPatternsAndActivity(snap, opts)
		} else {
			if opts.Include["patterns"] {
				snap.Patterns = &[]PatternSnapshot{}
			}
			if opts.Include["activity"] {
				snap.Activity = zeroActivitySnapshot(nil, nil)
			}
		}
	}

	// --- geo aggregation: own dial, silent failure.
	if opts.Include["geo"] {
		c.buildGeo(snap)
	}

	// --- alerts: own dial, silent failure.
	if opts.Include["alerts"] {
		c.buildAlerts(snap, opts, gatherStart)
	}

	if snap.Fail2ban.GeoEnabled {
		snap.geoLookupDuration = c.nowFn().Sub(bannedIPStart)
	}

	snap.Errors = ErrorsInfo{
		SocketConn: c.socketConnectionErrorCount,
		SocketReq:  c.socketRequestErrorCount,
		Collection: collectionErrors,
	}

	gatherEnd := c.nowFn()
	snap.collectionDuration = gatherEnd.Sub(gatherStart)
	snap.CollectionDurationMs = snap.collectionDuration.Milliseconds()

	return snap, nil
}

// buildServerUpAndJails gathers fail2ban.up/version and, if requested, the
// per-jail detail - all off the single top-level connection s (nil if the
// dial failed).
func (c *Collector) buildServerUpAndJails(snap *Snapshot, opts SnapshotOptions, s *socket.Fail2BanSocket) {
	if opts.Include["jails"] {
		snap.Jails = &[]JailSnapshot{}
	}

	serverUp := false
	if s != nil {
		pingSuccess, err := s.Ping()
		if err != nil {
			c.socketRequestErrorCount++
			log.Print(err)
		}
		if err == nil && pingSuccess {
			serverUp = true
		}
	}
	snap.Fail2ban.Up = serverUp

	if s == nil {
		return
	}

	jails, err := s.GetJails()
	if err != nil {
		c.socketRequestErrorCount++
		log.Print(err)
	} else {
		jails = c.jails.filterJails(jails)
		snap.jailCount = len(jails)
	}

	if opts.Include["jails"] && err == nil {
		for _, jail := range jails {
			*snap.Jails = append(*snap.Jails, c.buildJailSnapshot(s, jail))
		}
		jailsSlice := *snap.Jails
		sort.Slice(jailsSlice, func(i, j int) bool { return jailsSlice[i].Name < jailsSlice[j].Name })
	}

	fail2banVersion, verr := s.GetServerVersion()
	if verr != nil {
		c.socketRequestErrorCount++
		log.Printf("failed to get fail2ban server version: %v", verr)
	}
	snap.Fail2ban.Version = fail2banVersion
}

// buildJailSnapshot gathers one jail's filter/action/config detail.
func (c *Collector) buildJailSnapshot(s *socket.Fail2BanSocket, jail string) JailSnapshot {
	js := JailSnapshot{Name: jail}

	stats, err := s.GetJailStats(jail)
	if err != nil {
		c.socketRequestErrorCount++
		log.Printf("failed to get stats for jail %s: %v", jail, err)
	} else {
		js.statsOK = true
	}
	js.Filter = JailFilterCounts{CurrentlyFailed: stats.FailedCurrent, TotalFailed: stats.FailedTotal}
	js.Actions = JailActionCounts{CurrentlyBanned: stats.BannedCurrent, TotalBanned: stats.BannedTotal}

	banTime, err := s.GetJailBanTime(jail)
	if err != nil {
		c.socketRequestErrorCount++
		log.Printf("failed to get ban time for jail %s: %v", jail, err)
	} else {
		js.banTimeOK = true
	}
	js.Config.BanTimeSeconds = banTime

	findTime, err := s.GetJailFindTime(jail)
	if err != nil {
		c.socketRequestErrorCount++
		log.Printf("failed to get find time for jail %s: %v", jail, err)
	} else {
		js.findTimeOK = true
	}
	js.Config.FindTimeSeconds = findTime

	maxRetry, err := s.GetJailMaxRetries(jail)
	if err != nil {
		c.socketRequestErrorCount++
		log.Printf("failed to get max retries for jail %s: %v", jail, err)
	} else {
		js.maxRetryOK = true
	}
	js.Config.MaxRetry = maxRetry

	return js
}

// buildBannedIPSeries gathers the live, socket-sourced currently-banned-IP
// list backing f2b_banned_ip. Own dial; every error here is silent by design
// (see snapshotLocked's comment on the top-level dial).
func (c *Collector) buildBannedIPSeries() []bannedIPSeries {
	s, err := socket.ConnectToSocketTimeout(c.socketPath, c.socketTimeout)
	if err != nil {
		log.Printf("failed to connect to socket for banned IP collection: %v", err)
		return nil
	}
	defer s.Close()

	jails, err := s.GetJails()
	if err != nil {
		log.Printf("failed to get jails for banned IP collection: %v", err)
		return nil
	}
	jails = c.jails.filterJails(jails)

	seenIPs := make(map[string]bool)
	exported := 0
	var out []bannedIPSeries
	for _, jail := range jails {
		ips, err := s.GetBannedIPs(jail)
		if err != nil {
			log.Printf("failed to get banned IPs for jail %s: %v", jail, err)
			continue
		}

		for _, ip := range ips {
			ipLabel := c.ipAnon.label(ip)
			key := jail + ":" + ipLabel
			if seenIPs[key] {
				continue
			}
			seenIPs[key] = true

			if c.maxIPMetrics > 0 && exported >= c.maxIPMetrics {
				log.Printf("banned IP metrics truncated at %d series (see --collector.f2b.max-ip-metrics)", c.maxIPMetrics)
				return out
			}
			out = append(out, c.buildBannedIPSeriesEntry(jail, ip, ipLabel))
			exported++
		}
	}
	return out
}

func (c *Collector) buildBannedIPSeriesEntry(jail, ip, ipLabel string) bannedIPSeries {
	entry := bannedIPSeries{jail: jail, ipLabel: ipLabel}
	if c.geoEnabled && c.geoProvider != nil {
		if geoLabels := c.geoProvider.Annotate(ip); geoLabels != nil {
			entry.city = geoLabels["city"]
			entry.latitude = geoLabels["latitude"]
			entry.longitude = geoLabels["longitude"]
			entry.country = geoLabels["country"]
			entry.countryCode = geoLabels["country_code"]
		}
	}
	return entry
}

// buildHistoricalStats gathers the per-IP-label aggregate across the whole
// ban history (all jails), backing f2b_ban_history_total, f2b_ip_ban_count_
// total and siblings, and feeding bans.items's banCount/firstSeenAt/
// lastSeenAt/repeatOffender. DB only, cached via getAllBans; no socket dial.
func (c *Collector) buildHistoricalStats(snap *Snapshot) {
	allBans, err := c.getAllBans()
	if err != nil {
		log.Printf("failed to get all bans for historical metrics: %v", err)
		return
	}
	snap.historyOK = true
	snap.banHistoryTotal = len(allBans)

	stats := make(map[string]*ipHistoryStat)
	var order []string
	for _, ban := range allBans {
		label := c.ipAnon.label(ban.IP)
		st, ok := stats[label]
		if !ok {
			st = &ipHistoryStat{label: label}
			stats[label] = st
			order = append(order, label)
		}
		st.banCount++
		if ban.TimeOfBan > 0 {
			if st.firstSeen == 0 || ban.TimeOfBan < st.firstSeen {
				st.firstSeen = ban.TimeOfBan
			}
			if ban.TimeOfBan > st.lastSeen {
				st.lastSeen = ban.TimeOfBan
			}
		}
	}

	snap.historyByIP = make(map[string]ipHistoryStat, len(stats))
	for label, st := range stats {
		snap.historyByIP[label] = *st
	}

	// Cap per-IP series at the most recently seen IPs, mirroring the
	// original collectHistoricalBanMetrics truncation. This uses the
	// collector's static ceiling directly (not the request-scoped
	// SnapshotOptions.MaxIPs, which only caps bans.items).
	exportLabels := order
	if c.maxIPMetrics > 0 && len(exportLabels) > c.maxIPMetrics {
		sorted := make([]string, len(exportLabels))
		copy(sorted, exportLabels)
		sort.Slice(sorted, func(i, j int) bool { return stats[sorted[i]].lastSeen > stats[sorted[j]].lastSeen })
		log.Printf("historical IP metrics truncated to %d most recent of %d IPs (see --collector.f2b.max-ip-metrics)", c.maxIPMetrics, len(exportLabels))
		exportLabels = sorted[:c.maxIPMetrics]
	}
	snap.historyExported = make([]ipHistoryStat, 0, len(exportLabels))
	for _, label := range exportLabels {
		snap.historyExported = append(snap.historyExported, *stats[label])
	}
}

// collapseActiveBansForSnapshot groups active bans by (jail, anonymized
// label), keeping the most recent ban of each group - mirroring
// ipAnonymizer.collapseBans exactly, but additionally retaining the real
// address so a masked or hashed label can still be geolocated. When
// anonymization is disabled this is a passthrough, one row per input row,
// exactly like collapseBans.
func (c *Collector) collapseActiveBansForSnapshot(bans []database.BannedIP) []collapsedActiveBan {
	if !c.ipAnon.enabled() {
		out := make([]collapsedActiveBan, len(bans))
		for i, b := range bans {
			out[i] = collapsedActiveBan{BannedIP: b, realIP: b.IP}
		}
		return out
	}

	type key struct{ jail, label string }
	index := make(map[key]int, len(bans))
	var collapsed []collapsedActiveBan
	for _, b := range bans {
		label := c.ipAnon.label(b.IP)
		k := key{b.Jail, label}
		if i, ok := index[k]; ok {
			if b.TimeOfBan > collapsed[i].TimeOfBan {
				labeled := b
				labeled.IP = label
				collapsed[i] = collapsedActiveBan{BannedIP: labeled, realIP: b.IP}
			}
			continue
		}
		labeled := b
		labeled.IP = label
		index[k] = len(collapsed)
		collapsed = append(collapsed, collapsedActiveBan{BannedIP: labeled, realIP: b.IP})
	}
	return collapsed
}

// buildBans gathers the active-ban list shared by bans.items and the
// Prometheus ban_age/duration/expiry family. Callers must only invoke this
// when snap.dbAvailable is true. DB only, cached via getActiveBans; no
// socket dial.
func (c *Collector) buildBans(snap *Snapshot, opts SnapshotOptions, gatherStart time.Time) {
	activeBans, err := c.getActiveBans()
	if err != nil {
		log.Printf("failed to get banned IPs from database for time-based metrics: %v", err)
		snap.Bans = &BansSnapshot{Items: []BanItem{}}
		return
	}

	collapsed := c.collapseActiveBansForSnapshot(activeBans)

	// bannedAt descending, tie-broken by jail then ip ascending - the head of
	// this order is what truncation keeps (the most recent bans). Sorting and
	// truncating happen on the FULL collapsed set, before dropping
	// zero-timing rows below - mirroring the pre-refactor
	// collectTimeBasedMetrics exactly: a truncation cap claims its slots by
	// recency first, and a slot that turns out to carry no usable timing is
	// simply skipped during emission, never backfilled from beyond the cap.
	// Filtering first and truncating second (as an earlier version of this
	// function did) silently admits one more IP than --collector.f2b.max-ip-
	// metrics should allow whenever a zero-timing row falls inside the
	// pre-filter truncation window - see docs/metrics-json-schema-v1.md §3.2.
	sort.Slice(collapsed, func(i, j int) bool {
		if collapsed[i].TimeOfBan != collapsed[j].TimeOfBan {
			return collapsed[i].TimeOfBan > collapsed[j].TimeOfBan
		}
		if collapsed[i].Jail != collapsed[j].Jail {
			return collapsed[i].Jail < collapsed[j].Jail
		}
		return collapsed[i].IP < collapsed[j].IP
	})

	// total counts every dateable row post-collapse, before truncation -
	// "Active bans before truncation" per the schema - independent of MaxIPs.
	total := 0
	for _, b := range collapsed {
		if b.TimeOfBan == 0 || b.BanTime == 0 {
			continue
		}
		total++
	}

	// The configured ceiling is a hard bound: a caller may narrow bans.items
	// but never widen past --collector.f2b.max-ip-metrics. Clamping here rather
	// than in the caller is deliberate - no request parameter must be able to
	// make a JSON poll show more than /metrics would. See
	// docs/metrics-json-schema-v1.md section 1.2. EffectiveMaxIPs is also what
	// the /metrics.json handler calls to keep its ETag's "effective maxIps"
	// scope component in sync with this clamp.
	maxIPs := c.EffectiveMaxIPs(opts.MaxIPs)
	capped := collapsed
	if maxIPs > 0 && len(capped) > maxIPs {
		capped = capped[:maxIPs]
	}

	currentTime := gatherStart.Unix()
	items := make([]BanItem, 0, len(capped))
	for _, b := range capped {
		// Bans whose timeofban or bantime is 0 carry no usable timing and are
		// skipped here, from the already-truncated set, matching the
		// Prometheus time-based families.
		if b.TimeOfBan == 0 || b.BanTime == 0 {
			continue
		}
		remaining := b.ExpiryTime - currentTime
		if remaining < 0 {
			remaining = 0
		}
		age := currentTime - b.TimeOfBan
		if age < 0 {
			age = 0
		}

		item := BanItem{
			Jail:             b.Jail,
			IP:               b.IP,
			BannedAt:         time.Unix(b.TimeOfBan, 0).UTC(),
			ExpiresAt:        time.Unix(b.ExpiryTime, 0).UTC(),
			AgeSeconds:       age,
			RemainingSeconds: remaining,
		}

		if hist, ok := snap.historyByIP[b.IP]; ok {
			item.BanCount = hist.banCount
			item.RepeatOffender = hist.banCount > 1
			if hist.firstSeen > 0 {
				t := time.Unix(hist.firstSeen, 0).UTC()
				item.FirstSeenAt = &t
			}
			if hist.lastSeen > 0 {
				t := time.Unix(hist.lastSeen, 0).UTC()
				item.LastSeenAt = &t
			}
		}

		if c.geoEnabled && c.geoProvider != nil {
			item.Geo = geoPointFromProvider(c.geoProvider, b.realIP)
		}

		items = append(items, item)
	}

	snap.Bans = &BansSnapshot{
		Returned:  len(items),
		Total:     total,
		Truncated: len(items) < total,
		Items:     items,
	}
}

// geoPointFromProvider looks up ip (always the real address) and, if found,
// returns the JSON geo object - omitting lat/lon when MaxMind reported no
// coordinates or when the label's string form does not parse to a finite
// float.
func geoPointFromProvider(p geo.Provider, ip string) *GeoPoint {
	labels := p.Annotate(ip)
	if labels == nil {
		return nil
	}
	gp := &GeoPoint{
		CountryCode: labels["country_code"],
		Country:     labels["country"],
		City:        labels["city"],
	}
	if lat, ok := parseFiniteFloat(labels["latitude"]); ok {
		gp.Lat = &lat
	}
	if lon, ok := parseFiniteFloat(labels["longitude"]); ok {
		gp.Lon = &lon
	}
	return gp
}

func parseFiniteFloat(s string) (float64, bool) {
	if s == "" {
		return 0, false
	}
	v, err := strconv.ParseFloat(s, 64)
	if err != nil || math.IsNaN(v) || math.IsInf(v, 0) {
		return 0, false
	}
	return v, true
}

// buildPatternsAndActivity runs the pattern detector over the last 48h of
// ban history, backing patterns/activity (JSON) and f2b_attack_pattern_type/
// f2b_attacks_by_hour/f2b_attacks_by_day_of_week/f2b_attack_velocity/
// f2b_suspicious_pattern_score (Prometheus). Callers must only invoke this
// when snap.dbAvailable is true. DB only, cached via getAllBans; no socket
// dial.
func (c *Collector) buildPatternsAndActivity(snap *Snapshot, opts SnapshotOptions) {
	allBans, err := c.getAllBans()
	if err != nil {
		log.Printf("failed to get bans for pattern analysis: %v", err)
		if opts.Include["patterns"] {
			snap.Patterns = &[]PatternSnapshot{}
		}
		if opts.Include["activity"] {
			snap.Activity = zeroActivitySnapshot(nil, nil)
		}
		return
	}

	detector := newPatternDetectorWithClock(c.nowFn)
	cutoffTime := c.nowFn().Unix() - (48 * 3600)
	for _, ban := range allBans {
		if ban.TimeOfBan < cutoffTime {
			continue
		}
		country := ""
		if c.geoEnabled && c.geoProvider != nil {
			if geoLabels := c.geoProvider.Annotate(ban.IP); geoLabels != nil {
				country = geoLabels["country_code"]
			}
		}
		detector.AddBan(ban.IP, ban.Jail, ban.TimeOfBan, country)
	}

	bruteForce := detector.DetectBruteForce()
	portScan := detector.DetectPortScan()
	distributed := detector.DetectDistributed()
	hourCounts, dayCounts := detector.DetectTemporalPattern()
	velocity := finiteOrZero(detector.CalculateAttackVelocity(1))
	score := finiteOrZero(detector.CalculateSuspiciousScore())

	snap.patternsOK = true
	snap.nonZeroHours = hourCounts
	snap.nonZeroDays = dayCounts
	snap.velocity = velocity
	snap.suspiciousScore = score

	snap.patternCounts = make(map[patternCountKey]int)
	for _, p := range bruteForce {
		snap.patternCounts[patternCountKey{p.Type, p.Jail}]++
	}
	for _, p := range portScan {
		snap.patternCounts[patternCountKey{p.Type, p.Jail}]++
	}
	for _, p := range distributed {
		snap.patternCounts[patternCountKey{p.Type, p.Jail}]++
	}

	if opts.Include["patterns"] {
		patterns := make([]PatternSnapshot, 0, len(bruteForce)+len(portScan)+len(distributed))
		for _, p := range bruteForce {
			patterns = append(patterns, PatternSnapshot{Type: p.Type, Jail: p.Jail, IP: c.ipAnon.label(p.IP), Score: finiteOrZero(p.Score)})
		}
		for _, p := range portScan {
			patterns = append(patterns, PatternSnapshot{Type: p.Type, Jail: p.Jail, IP: "", Score: finiteOrZero(p.Score)})
		}
		for _, p := range distributed {
			patterns = append(patterns, PatternSnapshot{Type: p.Type, Jail: p.Jail, IP: "", Score: finiteOrZero(p.Score)})
		}
		sort.Slice(patterns, func(i, j int) bool {
			if patterns[i].Type != patterns[j].Type {
				return patterns[i].Type < patterns[j].Type
			}
			if patterns[i].Jail != patterns[j].Jail {
				return patterns[i].Jail < patterns[j].Jail
			}
			return patterns[i].IP < patterns[j].IP
		})
		snap.Patterns = &patterns
	}

	if opts.Include["activity"] {
		snap.Activity = zeroActivitySnapshot(hourCounts, dayCounts)
		snap.Activity.VelocityPerHour = velocity
		snap.Activity.SuspiciousScore = score
	}
}

func zeroActivitySnapshot(hourCounts, dayCounts map[int]int) *ActivitySnapshot {
	byHour := make([]HourlyActivity, 24)
	for h := 0; h < 24; h++ {
		byHour[h] = HourlyActivity{Hour: h, Attacks: hourCounts[h]}
	}
	byDay := make([]DailyActivity, 7)
	for d := 0; d < 7; d++ {
		byDay[d] = DailyActivity{Day: d, Attacks: dayCounts[d]}
	}
	return &ActivitySnapshot{ByHour: byHour, ByDayOfWeek: byDay}
}

// buildGeo aggregates the socket's live currently-banned IPs by country and
// city, backing geo (JSON) and f2b_attacks_by_country_total/f2b_attacks_by_
// city_total/f2b_top_attack_countries/f2b_geographic_attack_rate
// (Prometheus). Own dial, silent failure. This is deliberately a *different*
// live fetch from buildBannedIPSeries and buildAlerts - see snapshotLocked's
// comment on the top-level dial for why the three are not consolidated.
func (c *Collector) buildGeo(snap *Snapshot) {
	empty := &GeoSnapshot{ByCountry: []CountryAttackStat{}, ByCity: []CityAttackStat{}}
	if !snap.Fail2ban.GeoEnabled {
		snap.Geo = empty
		return
	}

	s, err := socket.ConnectToSocketTimeout(c.socketPath, c.socketTimeout)
	if err != nil {
		log.Printf("failed to connect to socket for geographic metrics: %v", err)
		snap.Geo = empty
		return
	}
	defer s.Close()

	jails, err := s.GetJails()
	if err != nil {
		log.Printf("failed to get jails for geographic metrics: %v", err)
		snap.Geo = empty
		return
	}
	jails = c.jails.filterJails(jails)

	countryCounts := make(map[string]countryAgg)
	cityCounts := make(map[string]cityAgg)

	seenIPs := make(map[string]bool)
	for _, jail := range jails {
		ips, err := s.GetBannedIPs(jail)
		if err != nil {
			log.Printf("failed to get banned IPs for jail %s: %v", jail, err)
			continue
		}

		for _, ip := range ips {
			key := jail + ":" + ip
			if seenIPs[key] {
				continue
			}
			seenIPs[key] = true

			geoLabels := c.geoProvider.Annotate(ip)
			if geoLabels == nil {
				continue
			}

			countryCode := geoLabels["country_code"]
			countryName := geoLabels["country"]
			city := geoLabels["city"]

			if countryCode != "" {
				stats := countryCounts[countryCode]
				stats.count++
				if countryName != "" {
					stats.name = countryName
				}
				countryCounts[countryCode] = stats
			}
			if city != "" && countryCode != "" {
				cityKey := city + ":" + countryCode
				stats := cityCounts[cityKey]
				stats.count++
				stats.countryCode = countryCode
				if countryName != "" {
					stats.countryName = countryName
				}
				cityCounts[cityKey] = stats
			}
		}
	}

	snap.countryCounts = countryCounts
	snap.cityCounts = cityCounts

	byCountry := make([]CountryAttackStat, 0, len(countryCounts))
	for code, stats := range countryCounts {
		byCountry = append(byCountry, CountryAttackStat{CountryCode: code, Country: stats.name, Attacks: stats.count})
	}
	sort.Slice(byCountry, func(i, j int) bool {
		if byCountry[i].Attacks != byCountry[j].Attacks {
			return byCountry[i].Attacks > byCountry[j].Attacks
		}
		return byCountry[i].CountryCode < byCountry[j].CountryCode
	})
	for i := range byCountry {
		byCountry[i].Rank = i + 1
	}

	byCity := make([]CityAttackStat, 0, len(cityCounts))
	for key, stats := range cityCounts {
		city := key
		if idx := strings.LastIndexByte(key, ':'); idx >= 0 {
			city = key[:idx]
		}
		byCity = append(byCity, CityAttackStat{City: city, CountryCode: stats.countryCode, Country: stats.countryName, Attacks: stats.count})
	}
	sort.Slice(byCity, func(i, j int) bool {
		if byCity[i].Attacks != byCity[j].Attacks {
			return byCity[i].Attacks > byCity[j].Attacks
		}
		if byCity[i].City != byCity[j].City {
			return byCity[i].City < byCity[j].City
		}
		return byCity[i].CountryCode < byCity[j].CountryCode
	})

	snap.Geo = &GeoSnapshot{ByCountry: byCountry, ByCity: byCity}
}

// buildAlerts gathers every alert condition off one dial. newCountries and
// jailInactive/repeatOffenderSpike read edge-triggered collector state
// (c.seenCountries, c.lastJailActivity, c.lastRepeatOffenderCount); the
// mutation of that state - and of c.lastCollectionTime - only happens when
// opts.MutateAlertState is true, so a JSON gather observes pending edges
// without consuming them. Within a single gather, new-country dedup uses a
// call-local set regardless of MutateAlertState, so two identical-label
// f2b_alert_new_country_attack series are never produced even when the
// global c.seenCountries map cannot be written yet.
func (c *Collector) buildAlerts(snap *Snapshot, opts SnapshotOptions, gatherStart time.Time) {
	alerts := &AlertsSnapshot{
		NewCountries:      []string{},
		JailInactive:      []string{},
		CoordinatedAttack: []CoordinatedAttack{},
	}
	snap.Alerts = alerts

	currentTime := gatherStart.Unix()
	alerts.currentTime = currentTime

	s, err := socket.ConnectToSocketTimeout(c.socketPath, c.socketTimeout)
	if err != nil {
		log.Printf("failed to connect to socket for alert metrics: %v", err)
		return
	}
	defer s.Close()

	jails, err := s.GetJails()
	if err != nil {
		log.Printf("failed to get jails for alert metrics: %v", err)
		return
	}
	jails = c.jails.filterJails(jails)
	alerts.gatheredOK = true

	// High ban rate.
	var totalBans int
	for _, jail := range jails {
		stats, err := s.GetJailStats(jail)
		if err != nil {
			continue
		}
		totalBans += stats.BannedTotal
	}
	timeDelta := currentTime - c.lastCollectionTime
	if timeDelta > 0 && c.lastCollectionTime > 0 {
		bansPerMinute := float64(totalBans) / (float64(timeDelta) / 60.0)
		alerts.HighBanRate = bansPerMinute > c.alertSettings.HighBanRateThreshold
		alerts.hasBaseline = true
	}

	// New country attack: call-local dedup against a snapshot of
	// c.seenCountries, so repeats within this gather (or across jails) never
	// produce duplicate entries regardless of MutateAlertState.
	if c.geoEnabled && c.geoProvider != nil {
		newlySeen := make(map[string]bool)
		for _, jail := range jails {
			ips, err := s.GetBannedIPs(jail)
			if err != nil {
				continue
			}
			for _, ip := range ips {
				geoLabels := c.geoProvider.Annotate(ip)
				if geoLabels == nil {
					continue
				}
				countryCode := geoLabels["country_code"]
				if countryCode == "" {
					continue
				}
				if c.seenCountries[countryCode] || newlySeen[countryCode] {
					continue
				}
				newlySeen[countryCode] = true
				alerts.NewCountries = append(alerts.NewCountries, countryCode)
			}
		}
		sort.Strings(alerts.NewCountries)
	}

	// Coordinated attack: stateless, recomputed fresh every gather.
	if c.geoEnabled && c.geoProvider != nil {
		jailCountryIPs := make(map[string]map[string]int)
		for _, jail := range jails {
			ips, err := s.GetBannedIPs(jail)
			if err != nil {
				continue
			}
			for _, ip := range ips {
				geoLabels := c.geoProvider.Annotate(ip)
				if geoLabels == nil {
					continue
				}
				countryCode := geoLabels["country_code"]
				if countryCode == "" {
					continue
				}
				key := jail + ":" + countryCode
				if jailCountryIPs[key] == nil {
					jailCountryIPs[key] = make(map[string]int)
				}
				jailCountryIPs[key][ip] = 1
			}
		}
		for key, ipMap := range jailCountryIPs {
			if len(ipMap) < c.alertSettings.CoordinatedAttackMinIPs {
				continue
			}
			idx := strings.LastIndexByte(key, ':')
			alerts.CoordinatedAttack = append(alerts.CoordinatedAttack, CoordinatedAttack{Jail: key[:idx], CountryCode: key[idx+1:]})
		}
		sort.Slice(alerts.CoordinatedAttack, func(i, j int) bool {
			if alerts.CoordinatedAttack[i].Jail != alerts.CoordinatedAttack[j].Jail {
				return alerts.CoordinatedAttack[i].Jail < alerts.CoordinatedAttack[j].Jail
			}
			return alerts.CoordinatedAttack[i].CountryCode < alerts.CoordinatedAttack[j].CountryCode
		})
	}

	// Jail inactivity: read c.lastJailActivity; record which jails are
	// active this gather for the (possibly deferred) write below.
	activeJails := make(map[string]bool)
	for _, jail := range jails {
		stats, err := s.GetJailStats(jail)
		if err != nil {
			continue
		}
		if stats.BannedCurrent > 0 || stats.FailedCurrent > 0 {
			activeJails[jail] = true
			continue
		}
		lastActivity := c.lastJailActivity[jail]
		if lastActivity > 0 {
			inactivityHours := float64(currentTime-lastActivity) / 3600.0
			if inactivityHours >= float64(c.alertSettings.JailInactivityHours) {
				alerts.JailInactive = append(alerts.JailInactive, jail)
			}
		}
	}
	sort.Strings(alerts.JailInactive)
	alerts.activeJails = activeJails

	// Repeat offender spike: reuses the historical per-IP-label ban counts
	// (identical grouping to the original's own independent computation).
	if snap.historyOK {
		repeatOffenderCount := 0
		for _, hist := range snap.historyByIP {
			if hist.banCount > 1 {
				repeatOffenderCount++
			}
		}
		alerts.repeatOffenderComputed = true
		alerts.repeatOffenderCount = repeatOffenderCount
		if c.lastRepeatOffenderCount > 0 {
			increase := float64(repeatOffenderCount) / float64(c.lastRepeatOffenderCount)
			alerts.RepeatOffenderSpike = increase > 1.5
		}
	}

	if opts.MutateAlertState {
		for _, cc := range alerts.NewCountries {
			c.seenCountries[cc] = true
		}
		for jail := range alerts.activeJails {
			c.lastJailActivity[jail] = currentTime
		}
		if alerts.repeatOffenderComputed {
			c.lastRepeatOffenderCount = alerts.repeatOffenderCount
		}
		c.lastCollectionTime = currentTime
	}
}
