// Package f2b implements the fail2ban prometheus.Collector.
//
// Collect() works in two steps: snapshotLocked (snapshot.go) gathers the
// whole domain state of one scrape into a Snapshot, and flatten (flatten.go)
// reads that Snapshot to emit prometheus.Metric values. Nothing in flatten.go
// touches Collector's mutable state directly - every value it needs travels
// through the Snapshot, which is also what a future JSON endpoint serves
// (see docs/metrics-json-schema-v1.md).
//
// The fail2ban socket is dialed independently at several points rather than
// once and shared: the top-level dial in snapshotLocked, plus one each in
// buildBannedIPSeries, buildGeo and buildAlerts. Only the top-level dial
// increments socketConnectionErrorCount, advances the per-gather collection
// error count, or honours --collector.f2b.exit-on-socket-connection-error;
// the other three fail silently by design (a geo or alert hiccup should not
// take down the whole scrape). Consolidating these into one shared
// connection would change that error accounting - e.g. turning a single
// socket_req error into three or four - so do not do it. IsHealthy's own
// dial (collector.go), backing the unauthenticated /health endpoint, never
// touches these counters either, and for a stronger reason: see the comment
// on IsHealthy.
package f2b

import (
	"log"
	"os"
	"sync"
	"time"

	"github.com/NightSquawk/fail2ban-prometheus-exporter/cfg"
	"github.com/NightSquawk/fail2ban-prometheus-exporter/collector/database"
	"github.com/NightSquawk/fail2ban-prometheus-exporter/geo"
	"github.com/NightSquawk/fail2ban-prometheus-exporter/socket"
	"github.com/prometheus/client_golang/prometheus"
)

type Collector struct {
	socketPath                 string
	databasePath               string
	exporterVersion            string
	exporterCommit             string
	hostname                   string
	customerID                 string
	customerName               string
	tenantID                   string
	lastError                  error
	socketConnectionErrorCount int
	socketRequestErrorCount    int
	exitOnSocketConnError      bool
	geoProvider                geo.Provider
	geoEnabled                 bool
	db                         *database.Database
	maxIPMetrics               int
	socketTimeout              time.Duration
	jails                      jailFilter
	ipAnon                     *ipAnonymizer
	// nowFn is a clock seam for tests; defaults to time.Now in NewExporter.
	nowFn func() time.Time
	// mu guards every mutable field below it; held for the whole of Collect(), IsHealthy()
	// and Snapshot(), since a gather is I/O-bound (socket + SQLite) and the fields it
	// touches include maps. sync.Mutex is not reentrant: snapshotLocked assumes mu is
	// already held and must never be called except from a function that holds it.
	mu sync.Mutex
	// Database query cache (avoids full-table scans on every scrape)
	dbCacheTTL       time.Duration
	cachedActiveBans []database.BannedIP
	cachedAllBans    []database.BannedIP
	activeBansAt     time.Time
	allBansAt        time.Time
	// Alert state tracking
	seenCountries           map[string]bool
	lastJailActivity        map[string]int64 // jail -> last activity timestamp
	lastRepeatOffenderCount int
	lastCollectionTime      int64
	alertSettings           *cfg.AlertSettings
}

func NewExporter(appSettings *cfg.AppSettings, build BuildInfo) *Collector {
	log.Printf("reading fail2ban metrics from socket file: %s", appSettings.Fail2BanSocketPath)
	printFail2BanServerVersion(appSettings.Fail2BanSocketPath, appSettings.Fail2BanTimeout)

	// Get hostname
	hostname, err := os.Hostname()
	if err != nil {
		log.Printf("warning: failed to get hostname: %v, using 'unknown'", err)
		hostname = "unknown"
	}

	collector := &Collector{
		socketPath:                 appSettings.Fail2BanSocketPath,
		databasePath:               appSettings.Fail2BanDatabasePath,
		exporterVersion:            build.Version,
		exporterCommit:             build.Commit,
		hostname:                   hostname,
		customerID:                 appSettings.Customer.ID,
		customerName:               appSettings.Customer.Name,
		tenantID:                   appSettings.Customer.TenantID,
		lastError:                  nil,
		socketConnectionErrorCount: 0,
		socketRequestErrorCount:    0,
		exitOnSocketConnError:      appSettings.ExitOnSocketConnError,
		geoEnabled:                 appSettings.Geo.Enabled,
		maxIPMetrics:               appSettings.MaxIPMetrics,
		socketTimeout:              appSettings.Fail2BanTimeout,
		jails:                      newJailFilter(appSettings.Filter),
		ipAnon:                     newIPAnonymizer(appSettings.Privacy),
		dbCacheTTL:                 time.Duration(appSettings.DatabaseCacheTTL) * time.Second,
		seenCountries:              make(map[string]bool),
		lastJailActivity:           make(map[string]int64),
		lastRepeatOffenderCount:    0,
		lastCollectionTime:         0,
		alertSettings:              &appSettings.Alert,
		nowFn:                      time.Now,
	}

	// Initialize database if path is provided
	if appSettings.Fail2BanDatabasePath != "" {
		db, err := database.NewDatabase(appSettings.Fail2BanDatabasePath)
		if err != nil {
			log.Printf("warning: failed to open fail2ban database at %s: %v", appSettings.Fail2BanDatabasePath, err)
		} else {
			collector.db = db
			log.Printf("successfully connected to fail2ban database: %s", appSettings.Fail2BanDatabasePath)
		}
	}

	// Initialize geo provider if enabled
	if appSettings.Geo.Enabled {
		if appSettings.Geo.DBPath == "" {
			log.Printf("warning: geo-tagging enabled but no database path provided")
		} else {
			if appSettings.Geo.Provider == "maxmind" {
				geoProvider, err := geo.NewMaxMindProvider(appSettings.Geo.DBPath)
				if err != nil {
					log.Printf("warning: failed to initialize MaxMind geo provider: %v", err)
				} else {
					collector.geoProvider = geoProvider
					log.Printf("geo-tagging enabled with MaxMind database: %s", appSettings.Geo.DBPath)
				}
			} else {
				log.Printf("warning: unknown geo provider: %s", appSettings.Geo.Provider)
			}
		}
	}

	return collector
}

// getActiveBans returns currently active bans from the database, cached for
// dbCacheTTL so a 15s Prometheus scrape interval does not hammer SQLite.
func (c *Collector) getActiveBans() ([]database.BannedIP, error) {
	if c.dbCacheTTL > 0 && c.cachedActiveBans != nil && c.nowFn().Sub(c.activeBansAt) < c.dbCacheTTL {
		return c.cachedActiveBans, nil
	}
	bans, err := c.db.GetBannedIPs()
	if err != nil {
		return nil, err
	}
	bans = c.jails.filterBans(bans)
	c.cachedActiveBans = bans
	c.activeBansAt = c.nowFn()
	return bans, nil
}

// getAllBans returns the full ban history from the database, cached for
// dbCacheTTL. Shared by the historical, pattern, and alert collectors so a
// single scrape runs the full-table query at most once.
func (c *Collector) getAllBans() ([]database.BannedIP, error) {
	if c.dbCacheTTL > 0 && c.cachedAllBans != nil && c.nowFn().Sub(c.allBansAt) < c.dbCacheTTL {
		return c.cachedAllBans, nil
	}
	bans, err := c.db.GetAllBans()
	if err != nil {
		return nil, err
	}
	bans = c.jails.filterBans(bans)
	c.cachedAllBans = bans
	c.allBansAt = c.nowFn()
	return bans, nil
}

func (c *Collector) Describe(ch chan<- *prometheus.Desc) {
	ch <- metricServerUp
	ch <- metricJailCount
	ch <- metricJailFailedCurrent
	ch <- metricJailFailedTotal
	ch <- metricJailBannedCurrent
	ch <- metricJailBannedTotal
	ch <- metricErrorCount
	ch <- metricBannedIP
	ch <- metricBanDurationRemaining
	ch <- metricBanAge
	ch <- metricBanExpiry
	ch <- metricCollectionDuration
	ch <- metricDatabaseQueryDuration
	ch <- metricGeoLookupDuration
	ch <- metricMetricsExported
	ch <- metricCollectionErrors
	ch <- metricBanHistoryTotal
	ch <- metricIPBanCountTotal
	ch <- metricIPFirstSeen
	ch <- metricIPLastSeen
	ch <- metricRepeatOffender
	ch <- metricAttacksByCountry
	ch <- metricAttacksByCity
	ch <- metricTopAttackCountries
	ch <- metricGeographicAttackRate
	ch <- metricAttackPatternType
	ch <- metricAttacksByHour
	ch <- metricAttacksByDayOfWeek
	ch <- metricAttackVelocity
	ch <- metricSuspiciousPatternScore
	ch <- metricAlertHighBanRate
	ch <- metricAlertNewCountryAttack
	ch <- metricAlertCoordinatedAttack
	ch <- metricAlertJailInactive
	ch <- metricAlertRepeatOffenderSpike
}

// Collect gathers a full Snapshot (every section included, MutateAlertState
// true) and flattens it onto ch. All the actual gathering and emission logic
// lives in snapshot.go / flatten.go; this is deliberately thin.
func (c *Collector) Collect(ch chan<- prometheus.Metric) {
	c.mu.Lock()
	defer c.mu.Unlock()

	snap, err := c.snapshotLocked(SnapshotOptions{
		Include:                    allSections,
		MaxIPs:                     c.maxIPMetrics,
		MutateAlertState:           true,
		HonorExitOnSocketConnError: true,
	})
	if err != nil {
		// No path in snapshotLocked currently returns a non-nil error: every
		// failure mode (socket down, DB error, ...) is represented as
		// zero-valued/absent data instead, matching the JSON contract's "a
		// down fail2ban socket is not an error" (docs/metrics-json-schema-v1.md
		// §1.4). This guard is kept so a future failure mode fails loudly
		// rather than flattening a half-built Snapshot.
		log.Printf("snapshot gather failed: %v", err)
		return
	}

	c.flatten(ch, snap)
}

// IsHealthy backs the unauthenticated /health endpoint (server/handler.go):
// it dials the fail2ban socket and requires a successful ping. Deliberately
// NOT incremented here: socketConnectionErrorCount / socketRequestErrorCount.
// Those two feed f2b_errors_total{type="socket_conn"|"socket_req"} on
// /metrics, and /health has no auth in front of it - anyone who can reach the
// port could otherwise inflate an alerted-on counter for free by hammering
// /health while fail2ban is down, with no credentials and no trace. Collect()
// (the /metrics scrape path) is unaffected: its own top-level dial in
// snapshotLocked still counts every failure exactly as before. Everything
// else about the probe - taking c.mu, dialing with c.socketTimeout, closing
// the socket it opens, and logging the failure so the operator can still see
// it - is unchanged.
func (c *Collector) IsHealthy() bool {
	c.mu.Lock()
	defer c.mu.Unlock()

	s, err := socket.ConnectToSocketTimeout(c.socketPath, c.socketTimeout)
	if err != nil {
		log.Printf("error opening socket: %v", err)
		return false
	}
	defer s.Close()

	pingSuccess, err := s.Ping()
	if err != nil {
		log.Printf("error pinging fail2ban server: %v", err)
		return false
	}
	return pingSuccess
}

// Identity returns the exporter's constant name and its build-time version,
// for callers - such as the /health handler - that need to report exporter
// identity without hardcoding a second copy of either value. exporterName is
// a package const and exporterVersion is set once at construction and never
// mutated afterward, so - like EffectiveMaxIPs (snapshot.go) - this is safe
// to call without holding c.mu.
func (c *Collector) Identity() (name, version string) {
	return exporterName, c.exporterVersion
}

func printFail2BanServerVersion(socketPath string, timeout time.Duration) {
	s, err := socket.ConnectToSocketTimeout(socketPath, timeout)
	if err != nil {
		log.Printf("error connecting to socket: %v", err)
	} else {
		version, err := s.GetServerVersion()
		if err != nil {
			log.Printf("error interacting with socket: %v", err)
		} else {
			log.Printf("successfully connected to fail2ban socket! fail2ban version: %s", version)
		}
	}
}
