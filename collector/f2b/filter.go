package f2b

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"log"
	"net/netip"
	"regexp"

	"github.com/NightSquawk/fail2ban-prometheus-exporter/cfg"
	"github.com/NightSquawk/fail2ban-prometheus-exporter/collector/database"
)

// jailFilter decides which jails are exported. Both patterns are optional;
// include is applied first, then exclude, so exclude always wins.
type jailFilter struct {
	include *regexp.Regexp
	exclude *regexp.Regexp
}

func newJailFilter(settings cfg.FilterSettings) jailFilter {
	return jailFilter{include: settings.JailInclude, exclude: settings.JailExclude}
}

// enabled reports whether the filter can drop anything, so callers can skip
// allocating a filtered copy in the common unfiltered case.
func (f jailFilter) enabled() bool {
	return f.include != nil || f.exclude != nil
}

func (f jailFilter) allows(jail string) bool {
	if f.include != nil && !f.include.MatchString(jail) {
		return false
	}
	if f.exclude != nil && f.exclude.MatchString(jail) {
		return false
	}
	return true
}

// filterJails returns the subset of jails that pass the filter, preserving order.
func (f jailFilter) filterJails(jails []string) []string {
	if !f.enabled() {
		return jails
	}
	kept := make([]string, 0, len(jails))
	for _, jail := range jails {
		if f.allows(jail) {
			kept = append(kept, jail)
		}
	}
	return kept
}

// filterBans returns the subset of database rows whose jail passes the filter.
func (f jailFilter) filterBans(bans []database.BannedIP) []database.BannedIP {
	if !f.enabled() {
		return bans
	}
	kept := make([]database.BannedIP, 0, len(bans))
	for _, ban := range bans {
		if f.allows(ban.Jail) {
			kept = append(kept, ban)
		}
	}
	return kept
}

// unparseableIPLabel replaces anything that is not a valid IP address once
// anonymization is on, so a malformed database row cannot leak through the
// `ip` label as raw text.
const unparseableIPLabel = "unknown"

// ipAnonymizer transforms an address into the value used for the `ip` label.
// Geo lookups deliberately keep using the real address; only labels change.
type ipAnonymizer struct {
	mode   cfg.AnonymizeMode
	v4Bits int
	v6Bits int
	salt   []byte
}

func newIPAnonymizer(settings cfg.PrivacySettings) *ipAnonymizer {
	a := &ipAnonymizer{
		mode:   settings.Mode,
		v4Bits: settings.MaskBitsV4,
		v6Bits: settings.MaskBitsV6,
		salt:   []byte(settings.HashSalt),
	}
	if a.mode == "" {
		a.mode = cfg.AnonymizeNone
	}
	if a.mode == cfg.AnonymizeHash && len(a.salt) == 0 {
		a.salt = randomSalt()
		log.Print("generated an ephemeral IP hash salt; set --collector.f2b.ip-hash-salt to keep the ip label stable across restarts")
	}
	if a.mode != cfg.AnonymizeNone {
		log.Printf("banned IP addresses will be anonymized in metric labels (mode: %s)", a.mode)
	}
	return a
}

func randomSalt() []byte {
	salt := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		// crypto/rand failing is not recoverable in a way that keeps the
		// privacy guarantee, so fail loudly rather than hash with a zero salt.
		log.Fatalf("failed to generate IP hash salt: %v", err)
	}
	return salt
}

// enabled reports whether label transforms the address at all.
func (a *ipAnonymizer) enabled() bool {
	return a != nil && a.mode != cfg.AnonymizeNone
}

// label returns the value to use for the `ip` label of the given address.
// Distinct addresses can collapse onto the same label in mask mode; callers
// that emit one series per IP must deduplicate on the returned value.
func (a *ipAnonymizer) label(ip string) string {
	if !a.enabled() {
		return ip
	}

	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return unparseableIPLabel
	}
	addr = addr.Unmap()

	switch a.mode {
	case cfg.AnonymizeHash:
		sum := sha256.Sum256(append(append([]byte{}, a.salt...), addr.AsSlice()...))
		return hex.EncodeToString(sum[:])[:16]
	case cfg.AnonymizeMask:
		bits := a.v6Bits
		if addr.Is4() {
			bits = a.v4Bits
		}
		prefix, err := addr.Prefix(bits)
		if err != nil {
			return unparseableIPLabel
		}
		return prefix.String()
	default:
		return ip
	}
}

// collapseBans deduplicates bans that share a (jail, anonymized IP) label pair,
// keeping the most recent ban of each group. Without this, mask mode would emit
// several series with identical labels and Gather would reject the scrape.
func (a *ipAnonymizer) collapseBans(bans []database.BannedIP) []database.BannedIP {
	if !a.enabled() {
		return bans
	}

	type key struct{ jail, ip string }
	index := make(map[key]int, len(bans))
	collapsed := make([]database.BannedIP, 0, len(bans))
	for _, ban := range bans {
		ban.IP = a.label(ban.IP)
		k := key{ban.Jail, ban.IP}
		if i, ok := index[k]; ok {
			if ban.TimeOfBan > collapsed[i].TimeOfBan {
				collapsed[i] = ban
			}
			continue
		}
		index[k] = len(collapsed)
		collapsed = append(collapsed, ban)
	}
	return collapsed
}
