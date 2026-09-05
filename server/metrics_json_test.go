package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/NightSquawk/fail2ban-prometheus-exporter/cfg"
	"github.com/NightSquawk/fail2ban-prometheus-exporter/collector/f2b"
)

// newDownSocketCollector builds a Collector whose fail2ban socket path does
// not exist, so every dial fails immediately and every gather deterministically
// lands in the documented "down fail2ban socket" state
// (docs/metrics-json-schema-v1.md §1.4): fail2ban.up=false, jail-derived
// sections empty, HTTP 200. No fake socket server or database is needed to
// exercise the handler end to end.
func newDownSocketCollector(t *testing.T) *f2b.Collector {
	t.Helper()
	appSettings := &cfg.AppSettings{
		Fail2BanSocketPath: filepath.Join(t.TempDir(), "does-not-exist.sock"),
		Fail2BanTimeout:    time.Second,
		MaxIPMetrics:       500,
	}
	return f2b.NewExporter(appSettings, f2b.BuildInfo{Version: "test", Commit: "test"})
}

func doMetricsJSON(t *testing.T, collector *f2b.Collector, method, target string, header http.Header) *httptest.ResponseRecorder {
	t.Helper()
	handler := metricsJSONHandler(collector)
	r := httptest.NewRequest(method, target, nil)
	for k, vs := range header {
		for _, v := range vs {
			r.Header.Add(k, v)
		}
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, r)
	return rec
}

func TestMetricsJSONMethodNotAllowed(t *testing.T) {
	collector := newDownSocketCollector(t)
	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodOptions} {
		rec := doMetricsJSON(t, collector, method, "/metrics.json", nil)
		if rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("method %s: status = %d, want %d", method, rec.Code, http.StatusMethodNotAllowed)
		}
		var body jsonErrorEnvelope
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatalf("method %s: body did not parse as error envelope: %v (%q)", method, err, rec.Body.String())
		}
		if body.SchemaVersion != 1 || body.Error == "" {
			t.Errorf("method %s: unexpected error envelope %+v", method, body)
		}
	}
}

func TestMetricsJSONDefaultIncludeSections(t *testing.T) {
	collector := newDownSocketCollector(t)
	rec := doMetricsJSON(t, collector, http.MethodGet, "/metrics.json", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}

	var envelope map[string]json.RawMessage
	if err := json.Unmarshal(rec.Body.Bytes(), &envelope); err != nil {
		t.Fatalf("body did not parse as JSON object: %v", err)
	}

	for _, present := range []string{"jails", "alerts"} {
		if _, ok := envelope[present]; !ok {
			t.Errorf("default include must include %q, got keys %v", present, keysOf(envelope))
		}
	}
	for _, absent := range []string{"bans", "patterns", "geo", "activity"} {
		if _, ok := envelope[absent]; ok {
			t.Errorf("default include must NOT include %q (not requested), got keys %v", absent, keysOf(envelope))
		}
	}

	// The down-socket state itself: fail2ban.up must be false, never an
	// error, per docs/metrics-json-schema-v1.md §1.4.
	var fail2ban struct {
		Up bool `json:"up"`
	}
	if err := json.Unmarshal(envelope["fail2ban"], &fail2ban); err != nil {
		t.Fatalf("fail2ban object did not parse: %v", err)
	}
	if fail2ban.Up {
		t.Errorf("expected fail2ban.up=false for a down socket, got true")
	}
}

func TestMetricsJSONRequestedSectionPresentButEmpty(t *testing.T) {
	collector := newDownSocketCollector(t)
	rec := doMetricsJSON(t, collector, http.MethodGet, "/metrics.json?include=bans", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}

	var envelope map[string]json.RawMessage
	if err := json.Unmarshal(rec.Body.Bytes(), &envelope); err != nil {
		t.Fatalf("body did not parse as JSON object: %v", err)
	}
	raw, ok := envelope["bans"]
	if !ok {
		t.Fatalf("requested section 'bans' must be present, got keys %v", keysOf(envelope))
	}
	if string(raw) == "null" {
		t.Fatalf("requested-but-empty section must not serialise as null, got %s", raw)
	}
	if _, ok := envelope["jails"]; ok {
		t.Fatalf("include=bans must NOT include jails (not requested, and not the default), got keys %v", keysOf(envelope))
	}
}

func keysOf(m map[string]json.RawMessage) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func TestMetricsJSONIncludeValidation(t *testing.T) {
	collector := newDownSocketCollector(t)
	tests := []struct {
		name   string
		target string
	}{
		{"unknown section", "/metrics.json?include=bogus"},
		{"empty after trim", "/metrics.json?include=jails,%20,alerts"},
		{"present but empty", "/metrics.json?include="},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := doMetricsJSON(t, collector, http.MethodGet, tt.target, nil)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400, body=%s", rec.Code, rec.Body.String())
			}
		})
	}
}

func TestMetricsJSONRepeatedQueryKeyIsBadRequest(t *testing.T) {
	collector := newDownSocketCollector(t)
	r := httptest.NewRequest(http.MethodGet, "/metrics.json?include=jails&include=bans", nil)
	rec := httptest.NewRecorder()
	metricsJSONHandler(collector).ServeHTTP(rec, r)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("repeated include key: status = %d, want 400, body=%s", rec.Code, rec.Body.String())
	}

	r2 := httptest.NewRequest(http.MethodGet, "/metrics.json?maxIps=1&maxIps=2", nil)
	rec2 := httptest.NewRecorder()
	metricsJSONHandler(collector).ServeHTTP(rec2, r2)
	if rec2.Code != http.StatusBadRequest {
		t.Fatalf("repeated maxIps key: status = %d, want 400, body=%s", rec2.Code, rec2.Body.String())
	}
}

func TestMetricsJSONMaxIPsValidation(t *testing.T) {
	collector := newDownSocketCollector(t)
	badTargets := []string{
		"/metrics.json?maxIps=-1",
		"/metrics.json?maxIps=abc",
		"/metrics.json?maxIps=1.5",
	}
	for _, target := range badTargets {
		rec := doMetricsJSON(t, collector, http.MethodGet, target, nil)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%s: status = %d, want 400, body=%s", target, rec.Code, rec.Body.String())
		}
	}

	rec := doMetricsJSON(t, collector, http.MethodGet, "/metrics.json?maxIps=10", nil)
	if rec.Code != http.StatusOK {
		t.Errorf("maxIps=10: status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}
}

func TestMetricsJSONContentType(t *testing.T) {
	collector := newDownSocketCollector(t)
	rec := doMetricsJSON(t, collector, http.MethodGet, "/metrics.json", nil)
	if got := rec.Header().Get("Content-Type"); got != jsonContentType {
		t.Errorf("Content-Type = %q, want %q", got, jsonContentType)
	}

	badRec := doMetricsJSON(t, collector, http.MethodGet, "/metrics.json?include=bogus", nil)
	if got := badRec.Header().Get("Content-Type"); got != jsonContentType {
		t.Errorf("error response Content-Type = %q, want %q", got, jsonContentType)
	}
}

// TestMetricsJSONGetContentLengthMatchesBody is a self-consistency check on
// the single GET path: the declared Content-Length must equal the number of
// body bytes actually written.
func TestMetricsJSONGetContentLengthMatchesBody(t *testing.T) {
	rec := doMetricsJSON(t, newDownSocketCollector(t), http.MethodGet, "/metrics.json", nil)
	declared, err := strconv.Atoi(rec.Header().Get("Content-Length"))
	if err != nil {
		t.Fatalf("Content-Length header %q did not parse: %v", rec.Header().Get("Content-Length"), err)
	}
	if declared != rec.Body.Len() {
		t.Errorf("Content-Length = %d, actual body = %d bytes", declared, rec.Body.Len())
	}
}

// TestMetricsJSONHeadHasHeadersNoBody uses its own fresh, single-request
// collector (see TestMetricsJSONETagStableAcrossIdenticalRequests for why
// two gathers on one down-socket collector are not directly comparable) and
// checks HEAD's headers in isolation rather than against a separate GET.
func TestMetricsJSONHeadHasHeadersNoBody(t *testing.T) {
	headRec := doMetricsJSON(t, newDownSocketCollector(t), http.MethodHead, "/metrics.json", nil)

	if headRec.Code != http.StatusOK {
		t.Fatalf("HEAD status = %d, want 200", headRec.Code)
	}
	if headRec.Body.Len() != 0 {
		t.Errorf("HEAD body must be empty, got %d bytes", headRec.Body.Len())
	}
	declared, err := strconv.Atoi(headRec.Header().Get("Content-Length"))
	if err != nil || declared <= 0 {
		t.Errorf("HEAD Content-Length = %q, want a positive integer", headRec.Header().Get("Content-Length"))
	}
	if headRec.Header().Get("ETag") == "" {
		t.Errorf("HEAD must carry an ETag header")
	}
}

// TestMetricsJSONETagStableAcrossIdenticalRequests proves collectedAt/
// collectionDurationMs never leak into the ETag. It deliberately does NOT
// query one collector twice: errors.socketConn is a real,
// cumulative-since-startup counter that legitimately advances on every dial
// against a permanently-down socket, and that counter IS part of the digest
// (docs/metrics-json-schema-v1.md §1.3 excludes exactly four fields, and
// errors.socketConn is not one of them) - so two live gathers on the SAME
// collector are expected to disagree. Two freshly constructed collectors,
// each queried exactly once, instead produce byte-identical canonical
// projections (both see their first-ever dial failure) except for the
// wall-clock fields, isolating exactly the property under test.
func TestMetricsJSONETagStableAcrossIdenticalRequests(t *testing.T) {
	rec1 := doMetricsJSON(t, newDownSocketCollector(t), http.MethodGet, "/metrics.json", nil)
	// Sleep past a whole second so collectedAt/collectionDurationMs would
	// differ between the two gathers if they leaked into the digest.
	time.Sleep(1100 * time.Millisecond)
	rec2 := doMetricsJSON(t, newDownSocketCollector(t), http.MethodGet, "/metrics.json", nil)

	etag1 := rec1.Header().Get("ETag")
	etag2 := rec2.Header().Get("ETag")
	if etag1 == "" || etag2 == "" {
		t.Fatalf("expected non-empty ETags, got %q and %q", etag1, etag2)
	}
	if etag1 != etag2 {
		t.Errorf("ETag differs between two equivalent first-ever gathers: %q != %q", etag1, etag2)
	}
	if len(etag1) != len(`"sha256-`)+64+1 {
		t.Errorf("ETag %q does not look like \"sha256-<64 hex>\"", etag1)
	}
}

// TestMetricsJSONDifferentScopesGetDifferentETags uses one fresh, single-use
// collector per request (see the comment on
// TestMetricsJSONETagStableAcrossIdenticalRequests for why) so the only
// variable between responses is the requested scope itself.
func TestMetricsJSONDifferentScopesGetDifferentETags(t *testing.T) {
	recDefault := doMetricsJSON(t, newDownSocketCollector(t), http.MethodGet, "/metrics.json", nil)
	recBans := doMetricsJSON(t, newDownSocketCollector(t), http.MethodGet, "/metrics.json?include=bans", nil)
	recMaxIPs := doMetricsJSON(t, newDownSocketCollector(t), http.MethodGet, "/metrics.json?maxIps=5", nil)

	etagDefault := recDefault.Header().Get("ETag")
	etagBans := recBans.Header().Get("ETag")
	etagMaxIPs := recMaxIPs.Header().Get("ETag")

	if etagDefault == etagBans {
		t.Errorf("different include scopes must not share an ETag")
	}
	if etagDefault == etagMaxIPs {
		t.Errorf("different maxIps scopes must not share an ETag")
	}
}

// TestMetricsJSONIfNoneMatchReturns304WithEmptyBody, likewise, uses a fresh
// collector per request rather than reusing one collector for both halves of
// each comparison.
func TestMetricsJSONIfNoneMatchReturns304WithEmptyBody(t *testing.T) {
	reference := doMetricsJSON(t, newDownSocketCollector(t), http.MethodGet, "/metrics.json", nil)
	etag := reference.Header().Get("ETag")
	if etag == "" {
		t.Fatalf("expected a non-empty ETag from the reference request")
	}

	header := http.Header{"If-None-Match": {etag}}
	second := doMetricsJSON(t, newDownSocketCollector(t), http.MethodGet, "/metrics.json", header)
	if second.Code != http.StatusNotModified {
		t.Fatalf("status = %d, want 304, body=%s", second.Code, second.Body.String())
	}
	if second.Body.Len() != 0 {
		t.Errorf("304 body must be empty, got %d bytes", second.Body.Len())
	}
	if got := second.Header().Get("ETag"); got != etag {
		t.Errorf("304 ETag = %q, want %q", got, etag)
	}

	// Wildcard always matches, regardless of the collector's own state.
	wildcard := doMetricsJSON(t, newDownSocketCollector(t), http.MethodGet, "/metrics.json", http.Header{"If-None-Match": {"*"}})
	if wildcard.Code != http.StatusNotModified {
		t.Errorf("wildcard If-None-Match: status = %d, want 304", wildcard.Code)
	}

	weak := doMetricsJSON(t, newDownSocketCollector(t), http.MethodGet, "/metrics.json", http.Header{"If-None-Match": {"W/" + etag}})
	if weak.Code != http.StatusNotModified {
		t.Errorf("weak If-None-Match: status = %d, want 304", weak.Code)
	}

	// A single header line carrying a comma-separated list of entity tags -
	// not two separate "If-None-Match" header lines, which r.Header.Get would
	// silently collapse to just the first.
	listValue := `"sha256-0000000000000000000000000000000000000000000000000000000000000000", ` + etag
	list := doMetricsJSON(t, newDownSocketCollector(t), http.MethodGet, "/metrics.json", http.Header{"If-None-Match": {listValue}})
	if list.Code != http.StatusNotModified {
		t.Errorf("comma-separated list If-None-Match: status = %d, want 304", list.Code)
	}
}

// TestMetricsJSONIfNoneMatchMalformedHeaderNeither500Nor304 covers the
// coverage gaps in If-None-Match handling beyond wildcard/weak/list (already
// covered by TestMetricsJSONIfNoneMatchReturns304WithEmptyBody): a malformed
// header must never 500, and - the sharper failure mode - must never be
// mistaken for a match and wrongly served 304. Serving 304 to a client that
// never actually saw a matching ETag is a correctness bug that masquerades
// as a cache win: the client is left believing it already has the body it
// does not have.
func TestMetricsJSONIfNoneMatchMalformedHeaderNeither500Nor304(t *testing.T) {
	malformed := []string{
		",",
		",,,",
		"not-an-etag-at-all",
		`"sha256-truncated`,          // unterminated quote
		"W/",                         // weak prefix with nothing after it
		" , , ",                      // only whitespace and separators
		`"sha256-` + string(rune(0)), // embedded NUL byte
	}
	for _, header := range malformed {
		t.Run(header, func(t *testing.T) {
			collector := newDownSocketCollector(t)
			rec := doMetricsJSON(t, collector, http.MethodGet, "/metrics.json", http.Header{"If-None-Match": {header}})

			if rec.Code == http.StatusNotModified {
				t.Errorf("malformed If-None-Match %q: status = 304, want NOT 304 (never saw a body to have cached)", header)
			}
			if rec.Code >= 500 {
				t.Errorf("malformed If-None-Match %q: status = %d, want < 500", header, rec.Code)
			}
			if rec.Code != http.StatusOK {
				t.Errorf("malformed If-None-Match %q: status = %d, want 200", header, rec.Code)
			}
			if rec.Body.Len() == 0 {
				t.Errorf("malformed If-None-Match %q: expected a non-empty 200 body", header)
			}
		})
	}
}

// TestMetricsJSONDownSocketAllSectionsAre200WithEmptySections is the
// end-to-end version of docs/metrics-json-schema-v1.md §1.4's "a down
// fail2ban socket is not an error": requesting every section against a
// down-socket collector must still be 200, with fail2ban.up=false and every
// jail-derived section present but empty - never a 500, and never merely the
// default include's two sections (this asserts all six explicitly).
func TestMetricsJSONDownSocketAllSectionsAre200WithEmptySections(t *testing.T) {
	collector := newDownSocketCollector(t)
	rec := doMetricsJSON(t, collector, http.MethodGet, "/metrics.json?include=jails,bans,patterns,geo,activity,alerts", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}

	var body struct {
		Fail2ban struct {
			Up bool `json:"up"`
		} `json:"fail2ban"`
		Jails []json.RawMessage `json:"jails"`
		Bans  struct {
			Returned  int               `json:"returned"`
			Total     int               `json:"total"`
			Truncated bool              `json:"truncated"`
			Items     []json.RawMessage `json:"items"`
		} `json:"bans"`
		Patterns []json.RawMessage `json:"patterns"`
		Geo      struct {
			ByCountry []json.RawMessage `json:"byCountry"`
			ByCity    []json.RawMessage `json:"byCity"`
		} `json:"geo"`
		Activity struct {
			ByHour          []json.RawMessage `json:"byHour"`
			ByDayOfWeek     []json.RawMessage `json:"byDayOfWeek"`
			VelocityPerHour float64           `json:"velocityPerHour"`
			SuspiciousScore float64           `json:"suspiciousScore"`
		} `json:"activity"`
		Alerts struct {
			HighBanRate         bool              `json:"highBanRate"`
			RepeatOffenderSpike bool              `json:"repeatOffenderSpike"`
			NewCountries        []json.RawMessage `json:"newCountries"`
			JailInactive        []json.RawMessage `json:"jailInactive"`
			CoordinatedAttack   []json.RawMessage `json:"coordinatedAttack"`
		} `json:"alerts"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("body did not parse: %v (%s)", err, rec.Body.String())
	}

	if body.Fail2ban.Up {
		t.Error("fail2ban.up = true, want false for a down socket")
	}
	if len(body.Jails) != 0 {
		t.Errorf("jails = %v, want empty", body.Jails)
	}
	if body.Bans.Returned != 0 || body.Bans.Total != 0 || body.Bans.Truncated || len(body.Bans.Items) != 0 {
		t.Errorf("bans = %+v, want {returned:0 total:0 truncated:false items:[]}", body.Bans)
	}
	if len(body.Patterns) != 0 {
		t.Errorf("patterns = %v, want empty", body.Patterns)
	}
	if len(body.Geo.ByCountry) != 0 || len(body.Geo.ByCity) != 0 {
		t.Errorf("geo = %+v, want empty arrays", body.Geo)
	}
	if len(body.Activity.ByHour) != 24 {
		t.Errorf("activity.byHour has %d entries, want 24 (zero-filled)", len(body.Activity.ByHour))
	}
	if len(body.Activity.ByDayOfWeek) != 7 {
		t.Errorf("activity.byDayOfWeek has %d entries, want 7 (zero-filled)", len(body.Activity.ByDayOfWeek))
	}
	if body.Activity.VelocityPerHour != 0 || body.Activity.SuspiciousScore != 0 {
		t.Errorf("activity velocity/suspiciousScore = %v/%v, want 0/0", body.Activity.VelocityPerHour, body.Activity.SuspiciousScore)
	}
	if body.Alerts.HighBanRate || body.Alerts.RepeatOffenderSpike {
		t.Errorf("alerts highBanRate/repeatOffenderSpike = %v/%v, want false/false", body.Alerts.HighBanRate, body.Alerts.RepeatOffenderSpike)
	}
	if len(body.Alerts.NewCountries) != 0 || len(body.Alerts.JailInactive) != 0 || len(body.Alerts.CoordinatedAttack) != 0 {
		t.Errorf("alerts arrays = %+v, want all empty", body.Alerts)
	}

	// The typed struct above cannot tell a JSON `null` apart from an absent
	// or empty array: json.Unmarshal silently decodes `null` into a nil Go
	// slice with no error, so every len(...) == 0 assertion above would
	// still pass even if a regression made, e.g., zeroActivitySnapshot or
	// buildAlerts emit `var x []T` (nil) instead of `x := []T{}`.
	// docs/metrics-json-schema-v1.md §1.1 requires a requested section with
	// no data to serialise as `[]` or a zero-count object, never `null` -
	// assert directly against the raw bytes, the same technique
	// TestMetricsJSONRequestedSectionPresentButEmpty already uses for
	// "bans".
	var envelope map[string]json.RawMessage
	if err := json.Unmarshal(rec.Body.Bytes(), &envelope); err != nil {
		t.Fatalf("body did not parse as a JSON object: %v", err)
	}
	for _, section := range []string{"jails", "bans", "patterns", "geo", "activity", "alerts"} {
		raw, ok := envelope[section]
		if !ok {
			t.Errorf("requested section %q is absent from the response, want present", section)
			continue
		}
		if string(raw) == "null" {
			t.Errorf("requested section %q serialised as null, want [] or a zero-count object", section)
		}
	}

	assertObjectFieldsNotNull(t, envelope["bans"], "items")
	assertObjectFieldsNotNull(t, envelope["geo"], "byCountry", "byCity")
	assertObjectFieldsNotNull(t, envelope["activity"], "byHour", "byDayOfWeek")
	assertObjectFieldsNotNull(t, envelope["alerts"], "newCountries", "jailInactive", "coordinatedAttack")
}

// assertObjectFieldsNotNull unmarshals objectRaw (a JSON object) and fails if
// any of fields is present as literal `null`. A field absent entirely is not
// flagged here - callers that also care about presence should check that
// separately - this only guards against the null-vs-empty-array conflation
// that a typed []json.RawMessage struct field cannot detect.
func assertObjectFieldsNotNull(t *testing.T, objectRaw json.RawMessage, fields ...string) {
	t.Helper()
	var nested map[string]json.RawMessage
	if err := json.Unmarshal(objectRaw, &nested); err != nil {
		t.Fatalf("object did not parse: %v (%s)", err, objectRaw)
	}
	for _, field := range fields {
		raw, ok := nested[field]
		if ok && string(raw) == "null" {
			t.Errorf("field %q serialised as null, want [] (raw object: %s)", field, objectRaw)
		}
	}
}

func TestMetricsJSONIfNoneMatchMismatchStillServes200(t *testing.T) {
	collector := newDownSocketCollector(t)
	header := http.Header{"If-None-Match": {`"sha256-0000000000000000000000000000000000000000000000000000000000000000"`}}
	rec := doMetricsJSON(t, collector, http.MethodGet, "/metrics.json", header)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}
}

// sampleSnapshotForDigest builds a synthetic *f2b.Snapshot directly (no
// gather involved), letting the digest tests below pin down exactly which
// fields the ETag excludes without depending on a live collector's
// cumulative, ever-advancing error counters.
func sampleSnapshotForDigest(collectedAt time.Time, ageSeconds, remainingSeconds int64, socketConn int, bannedAt time.Time) *f2b.Snapshot {
	return &f2b.Snapshot{
		SchemaVersion:        1,
		CollectedAt:          collectedAt,
		CollectionDurationMs: 42,
		Exporter:             f2b.ExporterInfo{Name: "fail2ban-prometheus-exporter", Version: "test", Commit: "test"},
		Host:                 f2b.HostInfo{Hostname: "test-host"},
		Fail2ban:             f2b.Fail2banInfo{Up: true, DatabaseEnabled: true},
		Errors:               f2b.ErrorsInfo{SocketConn: socketConn},
		Bans: &f2b.BansSnapshot{
			Returned: 1,
			Total:    1,
			Items: []f2b.BanItem{{
				Jail:             "sshd",
				IP:               "203.0.113.1",
				BannedAt:         bannedAt,
				ExpiresAt:        bannedAt.Add(time.Hour),
				AgeSeconds:       ageSeconds,
				RemainingSeconds: remainingSeconds,
			}},
		},
	}
}

// TestComputeETagDigestExcludesExactlyTheDocumentedWallClockFields is a
// direct, gather-free test of computeETag/canonicalizeForDigest against
// docs/metrics-json-schema-v1.md §1.3: collectedAt, collectionDurationMs,
// bans.items[].ageSeconds and bans.items[].remainingSeconds must not affect
// the digest, while every other field - including bannedAt/expiresAt, which
// the doc explicitly says remain in the digest, and errors.socketConn, which
// the doc never lists as excluded - must.
func TestComputeETagDigestExcludesExactlyTheDocumentedWallClockFields(t *testing.T) {
	sections := map[string]bool{"bans": true}
	bannedAt := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	base := sampleSnapshotForDigest(time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC), 10, 20, 1, bannedAt)
	baseEtag, err := computeETag(base, sections, 0)
	if err != nil {
		t.Fatalf("computeETag(base): %v", err)
	}

	wallClockOnly := sampleSnapshotForDigest(time.Date(2099, 6, 15, 3, 4, 5, 0, time.UTC), 999999, 888888, 1, bannedAt)
	wallClockEtag, err := computeETag(wallClockOnly, sections, 0)
	if err != nil {
		t.Fatalf("computeETag(wallClockOnly): %v", err)
	}
	if wallClockEtag != baseEtag {
		t.Errorf("changing only collectedAt/collectionDurationMs/ageSeconds/remainingSeconds changed the ETag: %q != %q", wallClockEtag, baseEtag)
	}

	diffSocketConn := sampleSnapshotForDigest(time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC), 10, 20, 2, bannedAt)
	diffSocketConnEtag, err := computeETag(diffSocketConn, sections, 0)
	if err != nil {
		t.Fatalf("computeETag(diffSocketConn): %v", err)
	}
	if diffSocketConnEtag == baseEtag {
		t.Errorf("errors.socketConn is not in the documented exclusion list but did not affect the ETag")
	}

	diffBannedAt := sampleSnapshotForDigest(time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC), 10, 20, 1, bannedAt.Add(time.Minute))
	diffBannedAtEtag, err := computeETag(diffBannedAt, sections, 0)
	if err != nil {
		t.Fatalf("computeETag(diffBannedAt): %v", err)
	}
	if diffBannedAtEtag == baseEtag {
		t.Errorf("bannedAt must remain in the digest (the doc says so explicitly) but did not affect the ETag")
	}
}

// TestComputeETagDoesNotMutateSnapshot proves canonicalizeForDigest never
// writes to the snapshot it is handed - the same value the handler is about
// to marshal and serve.
func TestComputeETagDoesNotMutateSnapshot(t *testing.T) {
	bannedAt := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	snap := sampleSnapshotForDigest(time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC), 10, 20, 1, bannedAt)
	before, err := json.Marshal(snap)
	if err != nil {
		t.Fatalf("marshal before: %v", err)
	}

	if _, err := computeETag(snap, map[string]bool{"bans": true}, 0); err != nil {
		t.Fatalf("computeETag: %v", err)
	}

	after, err := json.Marshal(snap)
	if err != nil {
		t.Fatalf("marshal after: %v", err)
	}
	if string(before) != string(after) {
		t.Errorf("computeETag mutated the snapshot:\nbefore: %s\nafter:  %s", before, after)
	}
}
