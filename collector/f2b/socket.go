// Package f2b: this file holds only the Prometheus metric descriptors and
// the small getCustomerLabels helper. The gathering and emission logic that
// used to live alongside these descriptors now lives in snapshot.go
// (gathering) and flatten.go (emission) - see collector.go's package docs.
package f2b

import (
	"github.com/prometheus/client_golang/prometheus"
)

const (
	namespace = "f2b"
)

// getCustomerLabels returns customer labels in the order: customer_id, customer_name, tenant_id
func getCustomerLabels(customerID, customerName, tenantID string) []string {
	return []string{customerID, customerName, tenantID}
}

var (
	metricErrorCount = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "errors_total"),
		"Number of errors found since startup",
		[]string{"type", "system", "customer_id", "customer_name", "tenant_id"}, nil,
	)
	metricServerUp = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "up"),
		"Check if the fail2ban server is up",
		[]string{"system", "customer_id", "customer_name", "tenant_id"}, nil,
	)
	metricJailCount = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "jail_count"),
		"Number of defined jails",
		[]string{"system", "customer_id", "customer_name", "tenant_id"}, nil,
	)
	metricJailFailedCurrent = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "jail_failed_current"),
		"Number of current failures on this jail's filter",
		[]string{"jail", "system", "customer_id", "customer_name", "tenant_id"}, nil,
	)
	// Reported as a counter: fail2ban's "Total failed" only resets when the
	// server restarts, which is exactly counter-reset semantics.
	metricJailFailedTotal = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "jail_failed_total"),
		"Number of total failures on this jail's filter",
		[]string{"jail", "system", "customer_id", "customer_name", "tenant_id"}, nil,
	)
	metricJailBannedCurrent = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "jail_banned_current"),
		"Number of IPs currently banned in this jail",
		[]string{"jail", "system", "customer_id", "customer_name", "tenant_id"}, nil,
	)
	// Reported as a counter, for the same reason as metricJailFailedTotal.
	metricJailBannedTotal = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "jail_banned_total"),
		"Total number of IPs banned by this jail (includes expired bans)",
		[]string{"jail", "system", "customer_id", "customer_name", "tenant_id"}, nil,
	)
	metricJailBanTime = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "config", "jail_ban_time"),
		"How long an IP is banned for in this jail (in seconds)",
		[]string{"jail", "system", "customer_id", "customer_name", "tenant_id"}, nil,
	)
	metricJailFindTime = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "config", "jail_find_time"),
		"How far back will the filter look for failures in this jail (in seconds)",
		[]string{"jail", "system", "customer_id", "customer_name", "tenant_id"}, nil,
	)
	metricJailMaxRetry = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "config", "jail_max_retries"),
		"The number of failures allowed until the IP is banned by this jail",
		[]string{"jail", "system", "customer_id", "customer_name", "tenant_id"}, nil,
	)
	metricVersionInfo = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "version"),
		"Version of the exporter and fail2ban server",
		[]string{"exporter", "fail2ban", "system", "customer_id", "customer_name", "tenant_id"}, nil,
	)
	metricBannedIP = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "banned_ip"),
		"Currently banned IP address (value is 1 if banned, 0 otherwise)",
		[]string{"jail", "ip", "system", "city", "latitude", "longitude", "country", "country_code", "customer_id", "customer_name", "tenant_id"}, nil,
	)
	metricBanDurationRemaining = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "ban_duration_remaining_seconds"),
		"Time remaining until ban expires in seconds",
		[]string{"jail", "ip", "system", "customer_id", "customer_name", "tenant_id"}, nil,
	)
	metricBanAge = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "ban_age_seconds"),
		"How long an IP has been banned in seconds",
		[]string{"jail", "ip", "system", "customer_id", "customer_name", "tenant_id"}, nil,
	)
	metricBanExpiry = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "ban_expiry_timestamp"),
		"Unix timestamp when ban expires",
		[]string{"jail", "ip", "system", "customer_id", "customer_name", "tenant_id"}, nil,
	)
	metricCollectionDuration = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "collection_duration_seconds"),
		"Time taken to complete metric collection in seconds",
		[]string{"system", "customer_id", "customer_name", "tenant_id"}, nil,
	)
	metricDatabaseQueryDuration = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "database_query_duration_seconds"),
		"Database query performance in seconds",
		[]string{"query_type", "system", "customer_id", "customer_name", "tenant_id"}, nil,
	)
	metricGeoLookupDuration = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "geo_lookup_duration_seconds"),
		"Geo lookup performance in seconds",
		[]string{"system", "customer_id", "customer_name", "tenant_id"}, nil,
	)
	metricMetricsExported = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "metrics_exported_total"),
		"Total number of metrics exported per collection",
		[]string{"system", "customer_id", "customer_name", "tenant_id"}, nil,
	)
	metricCollectionErrors = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "collection_errors_total"),
		"Errors encountered during collection",
		[]string{"system", "customer_id", "customer_name", "tenant_id"}, nil,
	)
	metricBanHistoryTotal = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "ban_history_total"),
		"Total bans ever recorded (including expired)",
		[]string{"system", "customer_id", "customer_name", "tenant_id"}, nil,
	)
	metricIPBanCountTotal = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "ip_ban_count_total"),
		"Total times an IP has been banned (across all jails)",
		[]string{"ip", "system", "customer_id", "customer_name", "tenant_id"}, nil,
	)
	metricIPFirstSeen = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "ip_first_seen_timestamp"),
		"First time IP was banned (Unix timestamp)",
		[]string{"ip", "system", "customer_id", "customer_name", "tenant_id"}, nil,
	)
	metricIPLastSeen = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "ip_last_seen_timestamp"),
		"Most recent ban time (Unix timestamp)",
		[]string{"ip", "system", "customer_id", "customer_name", "tenant_id"}, nil,
	)
	metricRepeatOffender = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "repeat_offender"),
		"Boolean flag (1 if banned multiple times, 0 otherwise)",
		[]string{"ip", "system", "customer_id", "customer_name", "tenant_id"}, nil,
	)
	metricAttacksByCountry = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "attacks_by_country_total"),
		"Total attacks by country code",
		[]string{"country_code", "country", "system", "customer_id", "customer_name", "tenant_id"}, nil,
	)
	metricAttacksByCity = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "attacks_by_city_total"),
		"Total attacks by city",
		[]string{"city", "country_code", "country", "system", "customer_id", "customer_name", "tenant_id"}, nil,
	)
	metricTopAttackCountries = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "top_attack_countries"),
		"Top N attacking countries (gauge with rank)",
		[]string{"country_code", "country", "rank", "system", "customer_id", "customer_name", "tenant_id"}, nil,
	)
	metricGeographicAttackRate = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "geographic_attack_rate"),
		"Attacks per country per hour",
		[]string{"country_code", "country", "system", "customer_id", "customer_name", "tenant_id"}, nil,
	)
	metricAttackPatternType = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "attack_pattern_type"),
		"Number of attack patterns of this type detected per jail",
		[]string{"pattern_type", "jail", "system", "customer_id", "customer_name", "tenant_id"}, nil,
	)
	metricAttacksByHour = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "attacks_by_hour"),
		"Attack distribution by hour of day (0-23)",
		[]string{"hour", "system", "customer_id", "customer_name", "tenant_id"}, nil,
	)
	metricAttacksByDayOfWeek = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "attacks_by_day_of_week"),
		"Attack distribution by day of week (0-6, Sunday=0)",
		[]string{"day", "system", "customer_id", "customer_name", "tenant_id"}, nil,
	)
	metricAttackVelocity = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "attack_velocity"),
		"Attacks per hour for recent time window",
		[]string{"system", "customer_id", "customer_name", "tenant_id"}, nil,
	)
	metricSuspiciousPatternScore = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "suspicious_pattern_score"),
		"Score indicating suspicious activity (0-100)",
		[]string{"system", "customer_id", "customer_name", "tenant_id"}, nil,
	)
	metricAlertHighBanRate = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "alert_high_ban_rate"),
		"1 if ban rate exceeds threshold, 0 otherwise",
		[]string{"system", "customer_id", "customer_name", "tenant_id"}, nil,
	)
	metricAlertNewCountryAttack = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "alert_new_country_attack"),
		"1 if attack from new country detected, 0 otherwise",
		[]string{"country_code", "system", "customer_id", "customer_name", "tenant_id"}, nil,
	)
	metricAlertCoordinatedAttack = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "alert_coordinated_attack"),
		"1 if multiple IPs from same country attacking same jail, 0 otherwise",
		[]string{"jail", "country_code", "system", "customer_id", "customer_name", "tenant_id"}, nil,
	)
	metricAlertJailInactive = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "alert_jail_inactive"),
		"1 if jail has no activity but should, 0 otherwise",
		[]string{"jail", "system", "customer_id", "customer_name", "tenant_id"}, nil,
	)
	metricAlertRepeatOffenderSpike = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "alert_repeat_offender_spike"),
		"1 if repeat offenders increase significantly, 0 otherwise",
		[]string{"system", "customer_id", "customer_name", "tenant_id"}, nil,
	)
)
