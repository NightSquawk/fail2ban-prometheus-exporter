package f2b

import (
	"fmt"
	"log"
	"os"
	"sort"
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
	// nowFn is a clock seam for tests; defaults to time.Now in NewExporter.
	nowFn func() time.Time
	// mu guards every mutable field below it; held for the whole of Collect() and IsHealthy(),
	// since a gather is I/O-bound (socket + SQLite) and the fields it touches include maps.
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

func NewExporter(appSettings *cfg.AppSettings, exporterVersion string) *Collector {
	log.Printf("reading fail2ban metrics from socket file: %s", appSettings.Fail2BanSocketPath)
	printFail2BanServerVersion(appSettings.Fail2BanSocketPath)

	// Get hostname
	hostname, err := os.Hostname()
	if err != nil {
		log.Printf("warning: failed to get hostname: %v, using 'unknown'", err)
		hostname = "unknown"
	}

	collector := &Collector{
		socketPath:                 appSettings.Fail2BanSocketPath,
		databasePath:               appSettings.Fail2BanDatabasePath,
		exporterVersion:            exporterVersion,
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

func (c *Collector) Collect(ch chan<- prometheus.Metric) {
	c.mu.Lock()
	defer c.mu.Unlock()

	collectionStart := c.nowFn()
	var metricsExported int
	var collectionErrors int
	var dbQueryDuration time.Duration
	var geoLookupDuration time.Duration

	s, err := socket.ConnectToSocket(c.socketPath)
	if err != nil {
		log.Printf("error opening socket: %v", err)
		c.socketConnectionErrorCount++
		collectionErrors++
		if c.exitOnSocketConnError {
			os.Exit(1)
		}
	} else {
		defer s.Close()
	}

	c.collectServerUpMetric(ch, s)
	metricsExported++
	if err == nil && s != nil {
		c.collectJailMetrics(ch, s)
		metricsExported++
		c.collectVersionMetric(ch, s)
		metricsExported++
	}

	// Track banned IP metrics collection
	bannedIPStart := c.nowFn()
	c.collectBannedIPMetrics(ch)
	metricsExported++

	// Track time-based metrics with database query timing
	if c.db != nil {
		dbStart := c.nowFn()
		c.collectTimeBasedMetrics(ch)
		dbQueryDuration += c.nowFn().Sub(dbStart)
		metricsExported++

		// Track historical ban metrics
		dbStart = c.nowFn()
		c.collectHistoricalBanMetrics(ch)
		dbQueryDuration += c.nowFn().Sub(dbStart)
		metricsExported++
	}

	// Collect geographic metrics (uses geo provider, not database)
	c.collectGeographicMetrics(ch)
	metricsExported++

	// Collect attack pattern metrics
	c.collectAttackPatternMetrics(ch)
	metricsExported++

	// Collect alert metrics
	c.collectAlertMetrics(ch)
	metricsExported++

	// Track geo lookup duration if enabled
	if c.geoEnabled && c.geoProvider != nil {
		geoStart := c.nowFn()
		// Geo lookups happen during banned IP collection, so we approximate
		// by measuring the time spent in banned IP collection
		geoLookupDuration = c.nowFn().Sub(bannedIPStart)
		_ = geoStart // Avoid unused variable warning
	}

	c.collectErrorCountMetric(ch)
	metricsExported++

	// Export performance metrics
	collectionDuration := c.nowFn().Sub(collectionStart)
	customerLabels := getCustomerLabels(c.customerID, c.customerName, c.tenantID)

	ch <- prometheus.MustNewConstMetric(
		metricCollectionDuration, prometheus.GaugeValue, collectionDuration.Seconds(),
		append([]string{c.hostname}, customerLabels...)...,
	)

	if dbQueryDuration > 0 {
		ch <- prometheus.MustNewConstMetric(
			metricDatabaseQueryDuration, prometheus.GaugeValue, dbQueryDuration.Seconds(),
			append([]string{"banned_ips", c.hostname}, customerLabels...)...,
		)
	}

	if geoLookupDuration > 0 {
		ch <- prometheus.MustNewConstMetric(
			metricGeoLookupDuration, prometheus.GaugeValue, geoLookupDuration.Seconds(),
			append([]string{c.hostname}, customerLabels...)...,
		)
	}

	ch <- prometheus.MustNewConstMetric(
		metricMetricsExported, prometheus.CounterValue, float64(metricsExported),
		append([]string{c.hostname}, customerLabels...)...,
	)

	if collectionErrors > 0 {
		ch <- prometheus.MustNewConstMetric(
			metricCollectionErrors, prometheus.CounterValue, float64(collectionErrors),
			append([]string{c.hostname}, customerLabels...)...,
		)
	}
}

func (c *Collector) IsHealthy() bool {
	c.mu.Lock()
	defer c.mu.Unlock()

	s, err := socket.ConnectToSocket(c.socketPath)
	if err != nil {
		log.Printf("error opening socket: %v", err)
		c.socketConnectionErrorCount++
		return false
	}
	pingSuccess, err := s.Ping()
	if err != nil {
		log.Printf("error pinging fail2ban server: %v", err)
		c.socketRequestErrorCount++
		return false
	}
	return pingSuccess
}

func (c *Collector) collectBannedIPMetrics(ch chan<- prometheus.Metric) {
	// Get banned IPs from socket
	s, err := socket.ConnectToSocket(c.socketPath)
	if err != nil {
		log.Printf("failed to connect to socket for banned IP collection: %v", err)
		return
	}
	defer s.Close()

	// Get all jails first
	jails, err := s.GetJails()
	if err != nil {
		log.Printf("failed to get jails for banned IP collection: %v", err)
		return
	}

	// Get banned IPs for each jail
	seenIPs := make(map[string]bool)
	exported := 0
	for _, jail := range jails {
		bannedIPs, err := s.GetBannedIPs(jail)
		if err != nil {
			log.Printf("failed to get banned IPs for jail %s: %v", jail, err)
			continue
		}

		for _, ip := range bannedIPs {
			// Create unique key for this jail+IP combination
			key := jail + ":" + ip
			if seenIPs[key] {
				continue
			}
			seenIPs[key] = true

			if c.maxIPMetrics > 0 && exported >= c.maxIPMetrics {
				log.Printf("banned IP metrics truncated at %d series (see --collector.f2b.max-ip-metrics)", c.maxIPMetrics)
				return
			}
			c.createBannedIPMetric(ch, jail, ip)
			exported++
		}
	}
}

func (c *Collector) createBannedIPMetric(ch chan<- prometheus.Metric, jail, ip string) {
	// Base labels: jail, ip, system
	labels := []string{jail, ip, c.hostname}

	// Add geo labels if geo provider is available
	// Always include all geo label positions, using empty strings if not available
	var city, latitude, longitude, country, countryCode string

	if c.geoEnabled && c.geoProvider != nil {
		geoLabels := c.geoProvider.Annotate(ip)
		if geoLabels != nil {
			if val, ok := geoLabels["city"]; ok {
				city = val
			}
			if val, ok := geoLabels["latitude"]; ok {
				latitude = val
			}
			if val, ok := geoLabels["longitude"]; ok {
				longitude = val
			}
			if val, ok := geoLabels["country"]; ok {
				country = val
			}
			if val, ok := geoLabels["country_code"]; ok {
				countryCode = val
			}
		}
	}

	// Append geo labels in the order defined in the metric descriptor
	labels = append(labels, city, latitude, longitude, country, countryCode)

	// Append customer labels
	labels = append(labels, c.customerID, c.customerName, c.tenantID)

	ch <- prometheus.MustNewConstMetric(
		metricBannedIP, prometheus.GaugeValue, float64(1), labels...,
	)
}

func (c *Collector) collectTimeBasedMetrics(ch chan<- prometheus.Metric) {
	if c.db == nil {
		// Database not available, skip time-based metrics
		return
	}

	bannedIPs, err := c.getActiveBans()
	if err != nil {
		log.Printf("failed to get banned IPs from database for time-based metrics: %v", err)
		return
	}

	// Cap per-IP series at the most recent bans
	if c.maxIPMetrics > 0 && len(bannedIPs) > c.maxIPMetrics {
		sorted := make([]database.BannedIP, len(bannedIPs))
		copy(sorted, bannedIPs)
		sort.Slice(sorted, func(i, j int) bool { return sorted[i].TimeOfBan > sorted[j].TimeOfBan })
		log.Printf("time-based IP metrics truncated to %d most recent of %d bans (see --collector.f2b.max-ip-metrics)", c.maxIPMetrics, len(bannedIPs))
		bannedIPs = sorted[:c.maxIPMetrics]
	}

	currentTime := c.nowFn().Unix()
	customerLabels := getCustomerLabels(c.customerID, c.customerName, c.tenantID)

	for _, bannedIP := range bannedIPs {
		// Skip if timing information is not available
		if bannedIP.TimeOfBan == 0 || bannedIP.BanTime == 0 {
			continue
		}

		baseLabels := []string{bannedIP.Jail, bannedIP.IP, c.hostname}
		labels := append(baseLabels, customerLabels...)

		// Calculate remaining duration (can be negative if ban already expired but still in DB)
		remainingDuration := bannedIP.ExpiryTime - currentTime
		if remainingDuration < 0 {
			remainingDuration = 0
		}

		// Calculate ban age
		banAge := currentTime - bannedIP.TimeOfBan
		if banAge < 0 {
			banAge = 0
		}

		// Export ban duration remaining
		ch <- prometheus.MustNewConstMetric(
			metricBanDurationRemaining, prometheus.GaugeValue, float64(remainingDuration), labels...,
		)

		// Export ban age
		ch <- prometheus.MustNewConstMetric(
			metricBanAge, prometheus.GaugeValue, float64(banAge), labels...,
		)

		// Export ban expiry timestamp
		ch <- prometheus.MustNewConstMetric(
			metricBanExpiry, prometheus.GaugeValue, float64(bannedIP.ExpiryTime), labels...,
		)
	}
}

func (c *Collector) collectHistoricalBanMetrics(ch chan<- prometheus.Metric) {
	if c.db == nil {
		// Database not available, skip historical metrics
		return
	}

	customerLabels := getCustomerLabels(c.customerID, c.customerName, c.tenantID)

	// Get all bans (including expired)
	allBans, err := c.getAllBans()
	if err != nil {
		log.Printf("failed to get all bans for historical metrics: %v", err)
		return
	}

	// Export total ban history count
	ch <- prometheus.MustNewConstMetric(
		metricBanHistoryTotal, prometheus.CounterValue, float64(len(allBans)),
		append([]string{c.hostname}, customerLabels...)...,
	)

	// Group bans by IP to calculate statistics
	type ipStat struct {
		banCount  int
		firstSeen int64
		lastSeen  int64
	}
	ipStats := make(map[string]ipStat)

	for _, ban := range allBans {
		stats := ipStats[ban.IP]
		stats.banCount++
		if ban.TimeOfBan > 0 {
			if stats.firstSeen == 0 || ban.TimeOfBan < stats.firstSeen {
				stats.firstSeen = ban.TimeOfBan
			}
			if ban.TimeOfBan > stats.lastSeen {
				stats.lastSeen = ban.TimeOfBan
			}
		}
		ipStats[ban.IP] = stats
	}

	// Cap per-IP series at the most recently seen IPs
	if c.maxIPMetrics > 0 && len(ipStats) > c.maxIPMetrics {
		ips := make([]string, 0, len(ipStats))
		for ip := range ipStats {
			ips = append(ips, ip)
		}
		sort.Slice(ips, func(i, j int) bool { return ipStats[ips[i]].lastSeen > ipStats[ips[j]].lastSeen })
		log.Printf("historical IP metrics truncated to %d most recent of %d IPs (see --collector.f2b.max-ip-metrics)", c.maxIPMetrics, len(ipStats))
		capped := make(map[string]ipStat, c.maxIPMetrics)
		for _, ip := range ips[:c.maxIPMetrics] {
			capped[ip] = ipStats[ip]
		}
		ipStats = capped
	}

	// Export per-IP metrics
	for ip, stats := range ipStats {
		baseLabels := []string{ip, c.hostname}
		labels := append(baseLabels, customerLabels...)

		// Export ban count
		ch <- prometheus.MustNewConstMetric(
			metricIPBanCountTotal, prometheus.CounterValue, float64(stats.banCount), labels...,
		)

		// Export first seen timestamp
		if stats.firstSeen > 0 {
			ch <- prometheus.MustNewConstMetric(
				metricIPFirstSeen, prometheus.GaugeValue, float64(stats.firstSeen), labels...,
			)
		}

		// Export last seen timestamp
		if stats.lastSeen > 0 {
			ch <- prometheus.MustNewConstMetric(
				metricIPLastSeen, prometheus.GaugeValue, float64(stats.lastSeen), labels...,
			)
		}

		// Export repeat offender flag (1 if banned more than once)
		repeatOffender := 0.0
		if stats.banCount > 1 {
			repeatOffender = 1.0
		}
		ch <- prometheus.MustNewConstMetric(
			metricRepeatOffender, prometheus.GaugeValue, repeatOffender, labels...,
		)
	}
}

func (c *Collector) collectGeographicMetrics(ch chan<- prometheus.Metric) {
	if !c.geoEnabled || c.geoProvider == nil {
		// Geo provider not available, skip geographic metrics
		return
	}

	customerLabels := getCustomerLabels(c.customerID, c.customerName, c.tenantID)

	// Get banned IPs from socket to analyze
	s, err := socket.ConnectToSocket(c.socketPath)
	if err != nil {
		log.Printf("failed to connect to socket for geographic metrics: %v", err)
		return
	}
	defer s.Close()

	jails, err := s.GetJails()
	if err != nil {
		log.Printf("failed to get jails for geographic metrics: %v", err)
		return
	}

	// Aggregate attacks by country and city
	countryCounts := make(map[string]struct {
		count int
		name  string
	})
	cityCounts := make(map[string]struct {
		count       int
		countryCode string
		countryName string
	})

	seenIPs := make(map[string]bool)
	for _, jail := range jails {
		bannedIPs, err := s.GetBannedIPs(jail)
		if err != nil {
			log.Printf("failed to get banned IPs for jail %s: %v", jail, err)
			continue
		}

		for _, ip := range bannedIPs {
			key := jail + ":" + ip
			if seenIPs[key] {
				continue
			}
			seenIPs[key] = true

			geoLabels := c.geoProvider.Annotate(ip)
			if geoLabels == nil {
				continue
			}

			countryCode := ""
			countryName := ""
			city := ""

			if val, ok := geoLabels["country_code"]; ok && val != "" {
				countryCode = val
			}
			if val, ok := geoLabels["country"]; ok && val != "" {
				countryName = val
			}
			if val, ok := geoLabels["city"]; ok && val != "" {
				city = val
			}

			// Aggregate by country
			if countryCode != "" {
				stats := countryCounts[countryCode]
				stats.count++
				if countryName != "" {
					stats.name = countryName
				}
				countryCounts[countryCode] = stats
			}

			// Aggregate by city
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

	// Export attacks by country
	for countryCode, stats := range countryCounts {
		labels := append([]string{countryCode, stats.name, c.hostname}, customerLabels...)
		ch <- prometheus.MustNewConstMetric(
			metricAttacksByCountry, prometheus.CounterValue, float64(stats.count), labels...,
		)
	}

	// Export attacks by city
	for cityKey, stats := range cityCounts {
		// Parse city and country code from key
		// cityKey format: "city:countryCode"
		labels := append([]string{stats.countryCode, stats.countryName, c.hostname}, customerLabels...)
		// Extract city name from key (everything before the colon)
		cityName := cityKey
		if idx := len(cityKey); idx > 0 {
			// Find the last colon to separate city from country code
			for i := len(cityKey) - 1; i >= 0; i-- {
				if cityKey[i] == ':' {
					cityName = cityKey[:i]
					break
				}
			}
		}
		labels = append([]string{cityName}, labels...)
		ch <- prometheus.MustNewConstMetric(
			metricAttacksByCity, prometheus.CounterValue, float64(stats.count), labels...,
		)
	}

	// Calculate and export top attack countries (top 10)
	type countryStat struct {
		code  string
		name  string
		count int
	}
	var sortedCountries []countryStat
	for code, stats := range countryCounts {
		sortedCountries = append(sortedCountries, countryStat{
			code:  code,
			name:  stats.name,
			count: stats.count,
		})
	}

	// Simple bubble sort to get top countries (or use sort package for better performance)
	for i := 0; i < len(sortedCountries)-1 && i < 9; i++ {
		for j := i + 1; j < len(sortedCountries); j++ {
			if sortedCountries[j].count > sortedCountries[i].count {
				sortedCountries[i], sortedCountries[j] = sortedCountries[j], sortedCountries[i]
			}
		}
	}

	// Export top 10 countries with rank
	for rank, country := range sortedCountries {
		if rank >= 10 {
			break
		}
		rankStr := fmt.Sprintf("%d", rank+1)
		labels := append([]string{country.code, country.name, rankStr, c.hostname}, customerLabels...)
		ch <- prometheus.MustNewConstMetric(
			metricTopAttackCountries, prometheus.GaugeValue, float64(country.count), labels...,
		)
	}

	// Export geographic attack rate (attacks per hour)
	// For simplicity, we'll calculate based on current counts
	// In a production system, you might want to track this over time
	for countryCode, stats := range countryCounts {
		// Simple rate: assume 1 hour window for now
		// In production, track time windows between collections
		rate := float64(stats.count) / 1.0 // attacks per hour
		labels := append([]string{countryCode, stats.name, c.hostname}, customerLabels...)
		ch <- prometheus.MustNewConstMetric(
			metricGeographicAttackRate, prometheus.GaugeValue, rate, labels...,
		)
	}
}

func (c *Collector) collectAttackPatternMetrics(ch chan<- prometheus.Metric) {
	if c.db == nil {
		// Database not available, skip pattern metrics
		return
	}

	customerLabels := getCustomerLabels(c.customerID, c.customerName, c.tenantID)

	// Get recent bans (last 48 hours) for pattern analysis
	allBans, err := c.getAllBans()
	if err != nil {
		log.Printf("failed to get bans for pattern analysis: %v", err)
		return
	}

	// Build a fresh detector every scrape: feeding the same bans into a
	// persistent detector would duplicate them and inflate pattern counts.
	detector := newPatternDetectorWithClock(c.nowFn)
	cutoffTime := c.nowFn().Unix() - (48 * 3600)
	for _, ban := range allBans {
		if ban.TimeOfBan >= cutoffTime {
			// Get country for this IP if geo is enabled
			country := ""
			if c.geoEnabled && c.geoProvider != nil {
				geoLabels := c.geoProvider.Annotate(ban.IP)
				if geoLabels != nil {
					if val, ok := geoLabels["country_code"]; ok {
						country = val
					}
				}
			}
			detector.AddBan(ban.IP, ban.Jail, ban.TimeOfBan, country)
		}
	}

	// Detect patterns
	bruteForce := detector.DetectBruteForce()
	portScan := detector.DetectPortScan()
	distributed := detector.DetectDistributed()
	hourCounts, dayCounts := detector.DetectTemporalPattern()
	velocity := detector.CalculateAttackVelocity(1) // Last hour
	score := detector.CalculateSuspiciousScore()

	// Export pattern counts by type and jail. Per-IP attribution stays out of
	// the labels to keep cardinality bounded (see README).
	type patternKey struct {
		patternType string
		jail        string
	}
	patternCounts := make(map[patternKey]int)
	for _, p := range bruteForce {
		patternCounts[patternKey{p.Type, p.Jail}]++
	}
	for _, p := range portScan {
		patternCounts[patternKey{p.Type, p.Jail}]++
	}
	for _, p := range distributed {
		patternCounts[patternKey{p.Type, p.Jail}]++
	}

	for key, count := range patternCounts {
		labels := append([]string{key.patternType, key.jail, c.hostname}, customerLabels...)
		ch <- prometheus.MustNewConstMetric(
			metricAttackPatternType, prometheus.GaugeValue, float64(count), labels...,
		)
	}

	// Export attacks by hour
	for hour, count := range hourCounts {
		hourStr := fmt.Sprintf("%d", hour)
		labels := append([]string{hourStr, c.hostname}, customerLabels...)
		ch <- prometheus.MustNewConstMetric(
			metricAttacksByHour, prometheus.CounterValue, float64(count), labels...,
		)
	}

	// Export attacks by day of week
	for day, count := range dayCounts {
		dayStr := fmt.Sprintf("%d", day)
		labels := append([]string{dayStr, c.hostname}, customerLabels...)
		ch <- prometheus.MustNewConstMetric(
			metricAttacksByDayOfWeek, prometheus.CounterValue, float64(count), labels...,
		)
	}

	// Export attack velocity
	labels := append([]string{c.hostname}, customerLabels...)
	ch <- prometheus.MustNewConstMetric(
		metricAttackVelocity, prometheus.GaugeValue, velocity, labels...,
	)

	// Export suspicious pattern score
	ch <- prometheus.MustNewConstMetric(
		metricSuspiciousPatternScore, prometheus.GaugeValue, score, labels...,
	)
}

func (c *Collector) collectAlertMetrics(ch chan<- prometheus.Metric) {
	customerLabels := getCustomerLabels(c.customerID, c.customerName, c.tenantID)
	currentTime := c.nowFn().Unix()

	// Get current jail stats
	s, err := socket.ConnectToSocket(c.socketPath)
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

	// Calculate ban rate (bans per minute)
	var totalBans int
	for _, jail := range jails {
		stats, err := s.GetJailStats(jail)
		if err != nil {
			continue
		}
		totalBans += stats.BannedTotal
	}

	// High ban rate alert
	timeDelta := currentTime - c.lastCollectionTime
	if timeDelta > 0 && c.lastCollectionTime > 0 {
		bansPerMinute := float64(totalBans) / (float64(timeDelta) / 60.0)
		highBanRate := 0.0
		if bansPerMinute > c.alertSettings.HighBanRateThreshold {
			highBanRate = 1.0
		}
		labels := append([]string{c.hostname}, customerLabels...)
		ch <- prometheus.MustNewConstMetric(
			metricAlertHighBanRate, prometheus.GaugeValue, highBanRate, labels...,
		)
	}

	// New country attack alert
	if c.geoEnabled && c.geoProvider != nil {
		for _, jail := range jails {
			bannedIPs, err := s.GetBannedIPs(jail)
			if err != nil {
				continue
			}
			for _, ip := range bannedIPs {
				geoLabels := c.geoProvider.Annotate(ip)
				if geoLabels != nil {
					if countryCode, ok := geoLabels["country_code"]; ok && countryCode != "" {
						if !c.seenCountries[countryCode] {
							// New country detected
							labels := append([]string{countryCode, c.hostname}, customerLabels...)
							ch <- prometheus.MustNewConstMetric(
								metricAlertNewCountryAttack, prometheus.GaugeValue, 1.0, labels...,
							)
							c.seenCountries[countryCode] = true
						}
					}
				}
			}
		}
	}

	// Coordinated attack alert
	if c.geoEnabled && c.geoProvider != nil {
		jailCountryIPs := make(map[string]map[string]int) // "jail:country" -> count of IPs
		for _, jail := range jails {
			bannedIPs, err := s.GetBannedIPs(jail)
			if err != nil {
				continue
			}
			for _, ip := range bannedIPs {
				geoLabels := c.geoProvider.Annotate(ip)
				if geoLabels != nil {
					if countryCode, ok := geoLabels["country_code"]; ok && countryCode != "" {
						key := jail + ":" + countryCode
						if jailCountryIPs[key] == nil {
							jailCountryIPs[key] = make(map[string]int)
						}
						jailCountryIPs[key][ip] = 1
					}
				}
			}
		}

		for key, ipMap := range jailCountryIPs {
			if len(ipMap) >= c.alertSettings.CoordinatedAttackMinIPs {
				// Parse jail and country from key
				var jail, countryCode string
				for i := len(key) - 1; i >= 0; i-- {
					if key[i] == ':' {
						jail = key[:i]
						countryCode = key[i+1:]
						break
					}
				}
				labels := append([]string{jail, countryCode, c.hostname}, customerLabels...)
				ch <- prometheus.MustNewConstMetric(
					metricAlertCoordinatedAttack, prometheus.GaugeValue, 1.0, labels...,
				)
			}
		}
	}

	// Jail inactivity alert
	for _, jail := range jails {
		stats, err := s.GetJailStats(jail)
		if err != nil {
			continue
		}

		// Update last activity time if there's activity
		if stats.BannedCurrent > 0 || stats.FailedCurrent > 0 {
			c.lastJailActivity[jail] = currentTime
		} else {
			// Check if jail has been inactive too long
			lastActivity := c.lastJailActivity[jail]
			if lastActivity > 0 {
				inactivityHours := float64(currentTime-lastActivity) / 3600.0
				if inactivityHours >= float64(c.alertSettings.JailInactivityHours) {
					labels := append([]string{jail, c.hostname}, customerLabels...)
					ch <- prometheus.MustNewConstMetric(
						metricAlertJailInactive, prometheus.GaugeValue, 1.0, labels...,
					)
				}
			}
		}
	}

	// Repeat offender spike alert
	if c.db != nil {
		allBans, err := c.getAllBans()
		if err == nil {
			ipCounts := make(map[string]int)
			for _, ban := range allBans {
				ipCounts[ban.IP]++
			}

			repeatOffenderCount := 0
			for _, count := range ipCounts {
				if count > 1 {
					repeatOffenderCount++
				}
			}

			// Check for significant increase
			spike := 0.0
			if c.lastRepeatOffenderCount > 0 {
				increase := float64(repeatOffenderCount) / float64(c.lastRepeatOffenderCount)
				if increase > 1.5 { // 50% increase
					spike = 1.0
				}
			}
			c.lastRepeatOffenderCount = repeatOffenderCount

			labels := append([]string{c.hostname}, customerLabels...)
			ch <- prometheus.MustNewConstMetric(
				metricAlertRepeatOffenderSpike, prometheus.GaugeValue, spike, labels...,
			)
		}
	}

	// Update last collection time
	c.lastCollectionTime = currentTime
}

func printFail2BanServerVersion(socketPath string) {
	s, err := socket.ConnectToSocket(socketPath)
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
