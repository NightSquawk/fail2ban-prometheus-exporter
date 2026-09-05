package f2b

import (
	"strconv"

	"github.com/prometheus/client_golang/prometheus"
)

// flatten emits every prometheus.Metric derived from snap. Every helper
// below reads only snap (and the customerLabels/hostname derived from it) -
// never c's mutable state - so this is exactly reproducible from a Snapshot
// alone.
func (c *Collector) flatten(ch chan<- prometheus.Metric, snap *Snapshot) {
	customerLabels := getCustomerLabels(snap.Labels.CustomerID, snap.Labels.CustomerName, snap.Labels.TenantID)
	host := snap.Host.Hostname

	flattenServerUp(ch, snap, host, customerLabels)
	if snap.topDialOK {
		flattenJails(ch, snap, host, customerLabels)
		flattenVersion(ch, snap, host, customerLabels)
	}
	flattenBannedIPSeries(ch, snap, host, customerLabels)
	if snap.dbAvailable {
		flattenBans(ch, snap, host, customerLabels)
		flattenHistorical(ch, snap, host, customerLabels)
	}
	flattenGeo(ch, snap, host, customerLabels)
	if snap.patternsOK {
		flattenPatterns(ch, snap, host, customerLabels)
		flattenActivity(ch, snap, host, customerLabels)
	}
	flattenAlerts(ch, snap, host, customerLabels)
	flattenErrorCount(ch, snap, host, customerLabels)
	flattenPerformance(ch, snap, host, customerLabels)
}

func flattenServerUp(ch chan<- prometheus.Metric, snap *Snapshot, host string, customerLabels []string) {
	up := 0.0
	if snap.Fail2ban.Up {
		up = 1.0
	}
	ch <- prometheus.MustNewConstMetric(
		metricServerUp, prometheus.GaugeValue, up,
		append([]string{host}, customerLabels...)...,
	)
}

func flattenJails(ch chan<- prometheus.Metric, snap *Snapshot, host string, customerLabels []string) {
	ch <- prometheus.MustNewConstMetric(
		metricJailCount, prometheus.GaugeValue, float64(snap.jailCount),
		append([]string{host}, customerLabels...)...,
	)

	var jails []JailSnapshot
	if snap.Jails != nil {
		jails = *snap.Jails
	}
	for _, j := range jails {
		if j.statsOK {
			labels := append([]string{j.Name, host}, customerLabels...)
			ch <- prometheus.MustNewConstMetric(metricJailFailedCurrent, prometheus.GaugeValue, float64(j.Filter.CurrentlyFailed), labels...)
			ch <- prometheus.MustNewConstMetric(metricJailFailedTotal, prometheus.CounterValue, float64(j.Filter.TotalFailed), labels...)
			ch <- prometheus.MustNewConstMetric(metricJailBannedCurrent, prometheus.GaugeValue, float64(j.Actions.CurrentlyBanned), labels...)
			ch <- prometheus.MustNewConstMetric(metricJailBannedTotal, prometheus.CounterValue, float64(j.Actions.TotalBanned), labels...)
		}
		if j.banTimeOK {
			labels := append([]string{j.Name, host}, customerLabels...)
			ch <- prometheus.MustNewConstMetric(metricJailBanTime, prometheus.GaugeValue, float64(j.Config.BanTimeSeconds), labels...)
		}
		if j.findTimeOK {
			labels := append([]string{j.Name, host}, customerLabels...)
			ch <- prometheus.MustNewConstMetric(metricJailFindTime, prometheus.GaugeValue, float64(j.Config.FindTimeSeconds), labels...)
		}
		if j.maxRetryOK {
			labels := append([]string{j.Name, host}, customerLabels...)
			ch <- prometheus.MustNewConstMetric(metricJailMaxRetry, prometheus.GaugeValue, float64(j.Config.MaxRetry), labels...)
		}
	}
}

func flattenVersion(ch chan<- prometheus.Metric, snap *Snapshot, host string, customerLabels []string) {
	ch <- prometheus.MustNewConstMetric(
		metricVersionInfo, prometheus.GaugeValue, 1,
		append([]string{snap.Exporter.Version, snap.Fail2ban.Version, host}, customerLabels...)...,
	)
}

func flattenBannedIPSeries(ch chan<- prometheus.Metric, snap *Snapshot, host string, customerLabels []string) {
	for _, b := range snap.bannedIPs {
		labels := []string{b.jail, b.ipLabel, host, b.city, b.latitude, b.longitude, b.country, b.countryCode}
		labels = append(labels, customerLabels...)
		ch <- prometheus.MustNewConstMetric(metricBannedIP, prometheus.GaugeValue, 1, labels...)
	}
}

func flattenBans(ch chan<- prometheus.Metric, snap *Snapshot, host string, customerLabels []string) {
	if snap.Bans == nil {
		return
	}
	for _, item := range snap.Bans.Items {
		labels := append([]string{item.Jail, item.IP, host}, customerLabels...)
		ch <- prometheus.MustNewConstMetric(metricBanDurationRemaining, prometheus.GaugeValue, float64(item.RemainingSeconds), labels...)
		ch <- prometheus.MustNewConstMetric(metricBanAge, prometheus.GaugeValue, float64(item.AgeSeconds), labels...)
		ch <- prometheus.MustNewConstMetric(metricBanExpiry, prometheus.GaugeValue, float64(item.ExpiresAt.Unix()), labels...)
	}
}

func flattenHistorical(ch chan<- prometheus.Metric, snap *Snapshot, host string, customerLabels []string) {
	if !snap.historyOK {
		return
	}
	ch <- prometheus.MustNewConstMetric(
		metricBanHistoryTotal, prometheus.CounterValue, float64(snap.banHistoryTotal),
		append([]string{host}, customerLabels...)...,
	)

	for _, st := range snap.historyExported {
		labels := append([]string{st.label, host}, customerLabels...)
		ch <- prometheus.MustNewConstMetric(metricIPBanCountTotal, prometheus.CounterValue, float64(st.banCount), labels...)
		if st.firstSeen > 0 {
			ch <- prometheus.MustNewConstMetric(metricIPFirstSeen, prometheus.GaugeValue, float64(st.firstSeen), labels...)
		}
		if st.lastSeen > 0 {
			ch <- prometheus.MustNewConstMetric(metricIPLastSeen, prometheus.GaugeValue, float64(st.lastSeen), labels...)
		}
		repeatOffender := 0.0
		if st.banCount > 1 {
			repeatOffender = 1.0
		}
		ch <- prometheus.MustNewConstMetric(metricRepeatOffender, prometheus.GaugeValue, repeatOffender, labels...)
	}
}

func flattenGeo(ch chan<- prometheus.Metric, snap *Snapshot, host string, customerLabels []string) {
	if !snap.Fail2ban.GeoEnabled {
		return
	}

	for countryCode, stats := range snap.countryCounts {
		labels := append([]string{countryCode, stats.name, host}, customerLabels...)
		ch <- prometheus.MustNewConstMetric(metricAttacksByCountry, prometheus.CounterValue, float64(stats.count), labels...)
	}

	for cityKey, stats := range snap.cityCounts {
		city := cityKey
		if idx := lastColon(cityKey); idx >= 0 {
			city = cityKey[:idx]
		}
		labels := append([]string{city, stats.countryCode, stats.countryName, host}, customerLabels...)
		ch <- prometheus.MustNewConstMetric(metricAttacksByCity, prometheus.CounterValue, float64(stats.count), labels...)
	}

	if snap.Geo != nil {
		for _, cs := range snap.Geo.ByCountry {
			if cs.Rank > 10 {
				break
			}
			labels := append([]string{cs.CountryCode, cs.Country, strconv.Itoa(cs.Rank), host}, customerLabels...)
			ch <- prometheus.MustNewConstMetric(metricTopAttackCountries, prometheus.GaugeValue, float64(cs.Attacks), labels...)
		}
	}

	for countryCode, stats := range snap.countryCounts {
		rate := float64(stats.count) / 1.0
		labels := append([]string{countryCode, stats.name, host}, customerLabels...)
		ch <- prometheus.MustNewConstMetric(metricGeographicAttackRate, prometheus.GaugeValue, rate, labels...)
	}
}

// lastColon mirrors the original code's manual reverse scan for the last ':'
// separator in a "city:countryCode" aggregation key.
func lastColon(s string) int {
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] == ':' {
			return i
		}
	}
	return -1
}

func flattenPatterns(ch chan<- prometheus.Metric, snap *Snapshot, host string, customerLabels []string) {
	for key, count := range snap.patternCounts {
		labels := append([]string{key.patternType, key.jail, host}, customerLabels...)
		ch <- prometheus.MustNewConstMetric(metricAttackPatternType, prometheus.GaugeValue, float64(count), labels...)
	}
}

func flattenActivity(ch chan<- prometheus.Metric, snap *Snapshot, host string, customerLabels []string) {
	for hour, count := range snap.nonZeroHours {
		labels := append([]string{strconv.Itoa(hour), host}, customerLabels...)
		ch <- prometheus.MustNewConstMetric(metricAttacksByHour, prometheus.GaugeValue, float64(count), labels...)
	}
	for day, count := range snap.nonZeroDays {
		labels := append([]string{strconv.Itoa(day), host}, customerLabels...)
		ch <- prometheus.MustNewConstMetric(metricAttacksByDayOfWeek, prometheus.GaugeValue, float64(count), labels...)
	}

	labels := append([]string{host}, customerLabels...)
	ch <- prometheus.MustNewConstMetric(metricAttackVelocity, prometheus.GaugeValue, snap.velocity, labels...)
	ch <- prometheus.MustNewConstMetric(metricSuspiciousPatternScore, prometheus.GaugeValue, snap.suspiciousScore, labels...)
}

func flattenAlerts(ch chan<- prometheus.Metric, snap *Snapshot, host string, customerLabels []string) {
	a := snap.Alerts
	if a == nil {
		return
	}

	if a.hasBaseline {
		v := 0.0
		if a.HighBanRate {
			v = 1.0
		}
		ch <- prometheus.MustNewConstMetric(metricAlertHighBanRate, prometheus.GaugeValue, v, append([]string{host}, customerLabels...)...)
	}

	for _, cc := range a.NewCountries {
		labels := append([]string{cc, host}, customerLabels...)
		ch <- prometheus.MustNewConstMetric(metricAlertNewCountryAttack, prometheus.GaugeValue, 1.0, labels...)
	}

	for _, ca := range a.CoordinatedAttack {
		labels := append([]string{ca.Jail, ca.CountryCode, host}, customerLabels...)
		ch <- prometheus.MustNewConstMetric(metricAlertCoordinatedAttack, prometheus.GaugeValue, 1.0, labels...)
	}

	for _, jail := range a.JailInactive {
		labels := append([]string{jail, host}, customerLabels...)
		ch <- prometheus.MustNewConstMetric(metricAlertJailInactive, prometheus.GaugeValue, 1.0, labels...)
	}

	if a.repeatOffenderComputed {
		v := 0.0
		if a.RepeatOffenderSpike {
			v = 1.0
		}
		ch <- prometheus.MustNewConstMetric(metricAlertRepeatOffenderSpike, prometheus.GaugeValue, v, append([]string{host}, customerLabels...)...)
	}
}

func flattenErrorCount(ch chan<- prometheus.Metric, snap *Snapshot, host string, customerLabels []string) {
	ch <- prometheus.MustNewConstMetric(
		metricErrorCount, prometheus.CounterValue, float64(snap.Errors.SocketConn),
		append([]string{"socket_conn", host}, customerLabels...)...,
	)
	ch <- prometheus.MustNewConstMetric(
		metricErrorCount, prometheus.CounterValue, float64(snap.Errors.SocketReq),
		append([]string{"socket_req", host}, customerLabels...)...,
	)
}

// flattenPerformance emits the self-monitoring families: collection
// duration (always), DB query / geo lookup duration (only when nonzero,
// exactly as before), metrics exported (the fixed 6/+2/+2 arithmetic
// documented on Collect) and collection errors (only when nonzero).
func flattenPerformance(ch chan<- prometheus.Metric, snap *Snapshot, host string, customerLabels []string) {
	labels := append([]string{host}, customerLabels...)

	ch <- prometheus.MustNewConstMetric(metricCollectionDuration, prometheus.GaugeValue, snap.collectionDuration.Seconds(), labels...)

	if snap.dbQueryDuration > 0 {
		dbLabels := append([]string{"banned_ips", host}, customerLabels...)
		ch <- prometheus.MustNewConstMetric(metricDatabaseQueryDuration, prometheus.GaugeValue, snap.dbQueryDuration.Seconds(), dbLabels...)
	}

	if snap.geoLookupDuration > 0 {
		ch <- prometheus.MustNewConstMetric(metricGeoLookupDuration, prometheus.GaugeValue, snap.geoLookupDuration.Seconds(), labels...)
	}

	metricsExported := 6
	if snap.topDialOK {
		metricsExported += 2
	}
	if snap.dbAvailable {
		metricsExported += 2
	}
	ch <- prometheus.MustNewConstMetric(metricMetricsExported, prometheus.CounterValue, float64(metricsExported), labels...)

	if snap.Errors.Collection > 0 {
		ch <- prometheus.MustNewConstMetric(metricCollectionErrors, prometheus.CounterValue, float64(snap.Errors.Collection), labels...)
	}
}
