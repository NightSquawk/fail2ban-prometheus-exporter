package f2b

import (
	"time"
)

// AttackPattern represents a detected attack pattern
type AttackPattern struct {
	Type      string  // brute_force, port_scan, distributed, etc.
	IP        string  // Attacking IP (brute_force only; empty for multi-IP patterns)
	Jail      string  // Jail the pattern was detected in
	Score     float64 // Suspicious pattern score (0-100)
	Velocity  float64 // Attacks per hour
	Hour      int     // Hour of day (0-23)
	DayOfWeek int     // Day of week (0-6, Sunday=0)
}

// PatternDetector analyzes bans to detect attack patterns
type PatternDetector struct {
	recentBans []BanRecord
	// now is a clock seam for tests; defaults to time.Now.
	now func() time.Time
}

// BanRecord represents a ban with timing information
type BanRecord struct {
	IP        string
	Jail      string
	TimeOfBan int64
	Country   string
}

// NewPatternDetector creates a new pattern detector
func NewPatternDetector() *PatternDetector {
	return newPatternDetectorWithClock(time.Now)
}

// newPatternDetectorWithClock creates a pattern detector with an injectable
// clock, so the 48h retention window and velocity cutoffs are deterministic
// in tests.
func newPatternDetectorWithClock(now func() time.Time) *PatternDetector {
	return &PatternDetector{
		recentBans: make([]BanRecord, 0),
		now:        now,
	}
}

// AddBan adds a ban record for pattern analysis
func (pd *PatternDetector) AddBan(ip, jail string, timeOfBan int64, country string) {
	pd.recentBans = append(pd.recentBans, BanRecord{
		IP:        ip,
		Jail:      jail,
		TimeOfBan: timeOfBan,
		Country:   country,
	})

	// Keep only last 48 hours of bans
	cutoffTime := pd.now().Unix() - (48 * 3600)
	filtered := make([]BanRecord, 0)
	for _, ban := range pd.recentBans {
		if ban.TimeOfBan >= cutoffTime {
			filtered = append(filtered, ban)
		}
	}
	pd.recentBans = filtered
}

// DetectBruteForce detects brute force attacks (multiple failures from same IP)
func (pd *PatternDetector) DetectBruteForce() []AttackPattern {
	ipJailCounts := make(map[string]int) // key: "ip:jail"

	for _, ban := range pd.recentBans {
		key := ban.IP + ":" + ban.Jail
		ipJailCounts[key]++
	}

	var patterns []AttackPattern
	for key, count := range ipJailCounts {
		if count >= 3 { // Threshold for brute force
			// Parse IP and jail from key
			var ip, jail string
			for i := len(key) - 1; i >= 0; i-- {
				if key[i] == ':' {
					ip = key[:i]
					jail = key[i+1:]
					break
				}
			}

			patterns = append(patterns, AttackPattern{
				Type:  "brute_force",
				IP:    ip,
				Jail:  jail,
				Score: float64(count) * 10.0, // Score based on count
			})
		}
	}

	return patterns
}

// DetectPortScan detects port scanning (multiple IPs attacking different jails)
func (pd *PatternDetector) DetectPortScan() []AttackPattern {
	jailIPs := make(map[string]map[string]bool) // jail -> set of IPs

	for _, ban := range pd.recentBans {
		if jailIPs[ban.Jail] == nil {
			jailIPs[ban.Jail] = make(map[string]bool)
		}
		jailIPs[ban.Jail][ban.IP] = true
	}

	var patterns []AttackPattern
	for jail, ips := range jailIPs {
		if len(ips) >= 5 { // Threshold: 5+ different IPs attacking same jail
			patterns = append(patterns, AttackPattern{
				Type:  "port_scan",
				Jail:  jail,
				Score: float64(len(ips)) * 5.0,
			})
		}
	}

	return patterns
}

// DetectDistributed detects distributed attacks (many IPs from different countries attacking same jail)
func (pd *PatternDetector) DetectDistributed() []AttackPattern {
	jailCountries := make(map[string]map[string]bool) // jail -> set of countries

	for _, ban := range pd.recentBans {
		if ban.Country == "" {
			continue
		}
		if jailCountries[ban.Jail] == nil {
			jailCountries[ban.Jail] = make(map[string]bool)
		}
		jailCountries[ban.Jail][ban.Country] = true
	}

	var patterns []AttackPattern
	for jail, countries := range jailCountries {
		if len(countries) >= 3 { // Threshold: 3+ different countries
			patterns = append(patterns, AttackPattern{
				Type:  "distributed",
				Jail:  jail,
				Score: float64(len(countries)) * 8.0,
			})
		}
	}

	return patterns
}

// DetectTemporalPattern analyzes time-based patterns
func (pd *PatternDetector) DetectTemporalPattern() (map[int]int, map[int]int) {
	hourCounts := make(map[int]int) // hour -> count
	dayCounts := make(map[int]int)  // day of week -> count

	for _, ban := range pd.recentBans {
		if ban.TimeOfBan > 0 {
			t := time.Unix(ban.TimeOfBan, 0)
			hour := t.Hour()
			day := int(t.Weekday())

			hourCounts[hour]++
			dayCounts[day]++
		}
	}

	return hourCounts, dayCounts
}

// CalculateAttackVelocity calculates attacks per hour for recent time window
func (pd *PatternDetector) CalculateAttackVelocity(hours int) float64 {
	cutoffTime := pd.now().Unix() - int64(hours*3600)
	count := 0

	for _, ban := range pd.recentBans {
		if ban.TimeOfBan >= cutoffTime {
			count++
		}
	}

	if hours > 0 {
		return float64(count) / float64(hours)
	}
	return 0.0
}

// CalculateSuspiciousScore calculates an overall suspicious pattern score
func (pd *PatternDetector) CalculateSuspiciousScore() float64 {
	score := 0.0

	// Check for brute force
	bruteForce := pd.DetectBruteForce()
	if len(bruteForce) > 0 {
		score += 20.0
	}

	// Check for port scan
	portScan := pd.DetectPortScan()
	if len(portScan) > 0 {
		score += 25.0
	}

	// Check for distributed attack
	distributed := pd.DetectDistributed()
	if len(distributed) > 0 {
		score += 30.0
	}

	// Check velocity
	velocity := pd.CalculateAttackVelocity(1) // Last hour
	if velocity > 10 {
		score += 15.0
	} else if velocity > 5 {
		score += 10.0
	}

	// Cap at 100
	if score > 100 {
		score = 100
	}

	return score
}
