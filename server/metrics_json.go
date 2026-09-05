package server

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/NightSquawk/fail2ban-prometheus-exporter/collector/f2b"
)

const (
	metricsJSONPath = "/metrics.json"
	// jsonContentType is set on every /metrics.json response that carries a
	// body (docs/metrics-json-schema-v1.md §1 / §1.4).
	jsonContentType = "application/json; charset=utf-8"
)

// jsonErrorEnvelope is the exact body of every /metrics.json error response
// (docs/metrics-json-schema-v1.md §1.4). Field order matters: it is what
// makes the literal example in the doc ({"schemaVersion":1,"error":"..."})
// byte-for-byte accurate.
type jsonErrorEnvelope struct {
	SchemaVersion int    `json:"schemaVersion"`
	Error         string `json:"error"`
}

// canonicalSectionOrder fixes the order "include" sections are hashed in for
// the ETag's request-scope prefix (docs/metrics-json-schema-v1.md §1.3), so
// ?include=bans,jails and ?include=jails,bans - which already gather and
// serve identically - also agree on ETag. This is a fixed slice, not a range
// over the request's own map, precisely so ordering never depends on Go's
// randomized map iteration.
var canonicalSectionOrder = []string{"jails", "bans", "patterns", "geo", "activity", "alerts"}

// metricsJSONHandler serves GET/HEAD /metrics.json. Like metricsHandler, it
// must be wrapped in AuthMiddleware by the caller (server.go) - there is no
// unauthenticated path to the fail2ban domain snapshot.
func metricsJSONHandler(collector *f2b.Collector) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// docs/metrics-json-schema-v1.md §1.4 promises "no request-scoped
		// deadline" on this endpoint: a slow-but-reachable fail2ban server
		// must make the request block, never truncate an in-flight
		// response. The http.Server shared by every route (server.go) sets
		// a 10s ReadTimeout/WriteTimeout for Slowloris protection; left in
		// place here, a gather+marshal+write that runs long would have this
		// connection's deadline expire mid-write, producing exactly the
		// "half-filled body" the project forbids. Clear both deadlines for
		// this response only. httptest.ResponseRecorder (used throughout
		// this package's tests) does not implement the optional deadline
		// interface, so http.ErrNotSupported is expected there and ignored.
		rc := http.NewResponseController(w)
		if err := rc.SetReadDeadline(time.Time{}); err != nil && !errors.Is(err, http.ErrNotSupported) {
			log.Printf("metrics.json: failed to clear read deadline: %v", err)
		}
		if err := rc.SetWriteDeadline(time.Time{}); err != nil && !errors.Is(err, http.ErrNotSupported) {
			log.Printf("metrics.json: failed to clear write deadline: %v", err)
		}

		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			writeJSONError(w, r, http.StatusMethodNotAllowed, "method not allowed: only GET and HEAD are supported")
			return
		}

		sections, sectionsErr := resolveIncludeSections(r)
		if sectionsErr != "" {
			writeJSONError(w, r, http.StatusBadRequest, sectionsErr)
			return
		}

		maxIPs, maxIPsErr := resolveMaxIPs(r)
		if maxIPsErr != "" {
			writeJSONError(w, r, http.StatusBadRequest, maxIPsErr)
			return
		}

		snap, err := collector.Snapshot(f2b.SnapshotOptions{
			Include: sections,
			MaxIPs:  maxIPs,
			// A JSON poll must not consume an alert edge: only Collect() (the
			// /metrics scrape path) may advance seenCountries/lastJailActivity/
			// lastRepeatOffenderCount/lastCollectionTime. See
			// docs/metrics-json-schema-v1.md §3.6.
			MutateAlertState: false,
			// An authenticated GET must never kill the process on a down
			// socket. Only Collect() honours --collector.f2b.exit-on-socket-
			// connection-error; a down socket here must degrade to
			// fail2ban.up=false instead (docs/metrics-json-schema-v1.md §1.4).
			HonorExitOnSocketConnError: false,
		})
		if err != nil {
			log.Printf("metrics.json: snapshot gather failed: %v", err)
			writeJSONError(w, r, http.StatusInternalServerError, "failed to gather metrics snapshot")
			return
		}

		// Marshal the whole body into a buffer FIRST. Only once this and the
		// ETag computation below both succeed do we touch the ResponseWriter,
		// so a serialisation failure never leaves a 200 half-written on the
		// wire (docs/metrics-json-schema-v1.md §1.4).
		body, err := json.Marshal(snap)
		if err != nil {
			log.Printf("metrics.json: failed to marshal snapshot: %v", err)
			writeJSONError(w, r, http.StatusInternalServerError, "failed to serialize metrics snapshot")
			return
		}

		// The ETag's request-scope component must reflect the EFFECTIVE
		// (post-ceiling-clamp) maxIps, not the raw query value: two requests
		// that clamp to the same ceiling serve byte-identical bans.items and
		// must share one ETag (docs/metrics-json-schema-v1.md §1.3). The
		// clamp itself happens once, deep inside collector.Snapshot's
		// buildBans; EffectiveMaxIPs recomputes the same deterministic
		// function of (raw request value, configured ceiling) so the two
		// never disagree.
		etag, err := computeETag(snap, sections, collector.EffectiveMaxIPs(maxIPs))
		if err != nil {
			log.Printf("metrics.json: failed to compute etag: %v", err)
			writeJSONError(w, r, http.StatusInternalServerError, "failed to serialize metrics snapshot")
			return
		}

		if ifNoneMatchSatisfied(r.Header.Get("If-None-Match"), etag) {
			w.Header().Set("ETag", etag)
			w.WriteHeader(http.StatusNotModified)
			return
		}

		w.Header().Set("Content-Type", jsonContentType)
		w.Header().Set("ETag", etag)
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		w.WriteHeader(http.StatusOK)
		if r.Method != http.MethodHead {
			_, _ = w.Write(body)
		}
	}
}

// writeJSONError writes the §1.4 error envelope. Like the success path, the
// body is built in full before any header is written, and HEAD never gets a
// body even for an error status.
func writeJSONError(w http.ResponseWriter, r *http.Request, status int, reason string) {
	body, err := json.Marshal(jsonErrorEnvelope{SchemaVersion: 1, Error: reason})
	if err != nil {
		// jsonErrorEnvelope is a fixed, simple shape (two strings); this
		// cannot fail in practice, but fall back rather than send nothing.
		body = []byte(`{"schemaVersion":1,"error":"internal error"}`)
	}
	w.Header().Set("Content-Type", jsonContentType)
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(status)
	if r.Method != http.MethodHead {
		_, _ = w.Write(body)
	}
}

// resolveIncludeSections implements docs/metrics-json-schema-v1.md §1.1. It
// returns (nil, errMsg) on any 400 condition; the caller distinguishes
// success from failure by whether errMsg is empty.
func resolveIncludeSections(r *http.Request) (map[string]bool, string) {
	values := r.URL.Query()["include"]
	if values == nil {
		// Key absent entirely: the documented default.
		return f2b.DefaultSections(), ""
	}
	// A repeated query key silently keeps only the first value under
	// url.Values.Get; that would serve a body that does not match what was
	// asked for, so treat repetition itself as a 400 rather than picking one.
	if len(values) > 1 {
		return nil, "include: repeated query parameter is not allowed"
	}
	return parseIncludeValue(values[0])
}

func parseIncludeValue(raw string) (map[string]bool, string) {
	valid := f2b.ValidSections()
	result := make(map[string]bool)
	for _, part := range strings.Split(raw, ",") {
		name := strings.TrimSpace(part)
		if name == "" {
			// Catches both "include=" (present but empty) and a stray comma
			// producing an empty member.
			return nil, "include: empty section name"
		}
		if !valid[name] {
			return nil, fmt.Sprintf("include: unknown section %q", name)
		}
		result[name] = true
	}
	return result, ""
}

// resolveMaxIPs implements the maxIps half of docs/metrics-json-schema-v1.md
// §1.1/§1.2. It only parses and validates the raw request value and passes
// it straight through; the ceiling-clamping table in §1.2 is applied later,
// via f2b.Collector.EffectiveMaxIPs - once inside Snapshot()'s buildBans (to
// cap bans.items) and once more by this handler (to compute the ETag's
// "effective maxIps" scope component) - so the raw value returned here must
// NOT be hashed directly into the ETag.
func resolveMaxIPs(r *http.Request) (int, string) {
	values := r.URL.Query()["maxIps"]
	if values == nil {
		return 0, ""
	}
	if len(values) > 1 {
		return 0, "maxIps: repeated query parameter is not allowed"
	}
	raw := strings.TrimSpace(values[0])
	n, err := strconv.Atoi(raw)
	if err != nil || n < 0 {
		return 0, fmt.Sprintf("maxIps: invalid non-negative integer %q", values[0])
	}
	return n, ""
}

// ifNoneMatchSatisfied reports whether header (the request's If-None-Match
// value) matches etag, per docs/metrics-json-schema-v1.md §1.3: a
// comma-separated list of entity tags, the wildcard *, and a W/ weak prefix
// on any listed tag are all honoured.
func ifNoneMatchSatisfied(header, etag string) bool {
	header = strings.TrimSpace(header)
	if header == "" {
		return false
	}
	for _, raw := range strings.Split(header, ",") {
		candidate := strings.TrimSpace(raw)
		if candidate == "*" {
			return true
		}
		candidate = strings.TrimPrefix(candidate, "W/")
		if candidate == etag {
			return true
		}
	}
	return false
}

// etagRequestScope is the normalised request scope hashed ahead of the body
// (docs/metrics-json-schema-v1.md §1.3), guarding against a coincidental body
// collision between two semantically different queries (e.g. differing
// include sections) producing a single shared ETag. MaxIps here MUST be the
// EFFECTIVE, post-ceiling-clamp value (f2b.Collector.EffectiveMaxIPs), not
// the raw query value: two requests whose maxIps clamps to the same ceiling
// serve byte-identical bans.items and are the same query for caching
// purposes, so they must share one ETag rather than churn on the raw input.
type etagRequestScope struct {
	Include []string `json:"include"`
	MaxIps  int      `json:"maxIps"`
}

// computeETag builds the canonical, wall-clock-stripped projection of snap
// and returns the strong ETag value (including its surrounding quotes) for
// it, prefixed by the request's normalised scope.
func computeETag(snap *f2b.Snapshot, sections map[string]bool, maxIPs int) (string, error) {
	scope := etagRequestScope{Include: orderedSections(sections), MaxIps: maxIPs}
	scopeBytes, err := json.Marshal(scope)
	if err != nil {
		return "", fmt.Errorf("marshal etag scope: %w", err)
	}

	canonical := canonicalizeForDigest(snap)
	bodyBytes, err := json.Marshal(canonical)
	if err != nil {
		return "", fmt.Errorf("marshal canonical snapshot: %w", err)
	}

	h := sha256.New()
	h.Write(scopeBytes)
	h.Write(bodyBytes)
	return fmt.Sprintf(`"sha256-%x"`, h.Sum(nil)), nil
}

// orderedSections returns the sections in sections that are set to true, in
// canonicalSectionOrder. It ranges over that fixed slice - never over
// sections itself - so the result is deterministic regardless of Go's
// randomized map iteration order.
func orderedSections(sections map[string]bool) []string {
	ordered := make([]string, 0, len(sections))
	for _, name := range canonicalSectionOrder {
		if sections[name] {
			ordered = append(ordered, name)
		}
	}
	return ordered
}

// canonicalizeForDigest returns a copy of snap with every wall-clock-derived
// field (docs/metrics-json-schema-v1.md §1.3) zeroed out, WITHOUT mutating
// snap itself: snap is the same value about to be marshaled and served to
// the client, so this only ever writes to copies. bannedAt/expiresAt are
// deliberately left untouched - the snapshot is considered changed when the
// ban set changes, not when time passes.
func canonicalizeForDigest(snap *f2b.Snapshot) *f2b.Snapshot {
	canonical := *snap
	canonical.CollectedAt = time.Time{}
	canonical.CollectionDurationMs = 0

	if snap.Bans != nil {
		items := make([]f2b.BanItem, len(snap.Bans.Items))
		for i, item := range snap.Bans.Items {
			item.AgeSeconds = 0
			item.RemainingSeconds = 0
			items[i] = item
		}
		bansCopy := *snap.Bans
		bansCopy.Items = items
		canonical.Bans = &bansCopy
	}

	return &canonical
}
