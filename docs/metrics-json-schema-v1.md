# `/metrics.json` — Schema v1

Versioned contract for the JSON snapshot endpoint exposed by
`fail2ban-prometheus-exporter` from `1.2.0-beta` onward.

`schemaVersion` is `1`. Within v1 the exporter may **add** fields; it will not
remove or retype existing ones. Consumers must ignore unknown fields.

> This document describes an endpoint that has not shipped yet. Until
> `1.2.0-beta` is released, corrections to the text below are corrections to
> v1 itself, not breaking changes requiring a `schemaVersion: 2`.

---

## 1. Endpoint

```
GET /metrics.json
```

Protected by the **same** authentication as `/metrics`, under either of the
exporter's two mutually exclusive mechanisms (startup fails if both are
configured):

| Mechanism | Enforced by | Covers | Rejection |
| --- | --- | --- | --- |
| `--web.config-file` (recommended) | `prometheus/exporter-toolkit`, at the HTTP server layer before any handler runs | TLS, mTLS client certificates, multi-user bcrypt basic auth | `401` with a `WWW-Authenticate` header and the plain-text body `Unauthorized\n`; a rejected client certificate fails the TLS handshake with no HTTP response at all |
| `--web.basic-auth.username` / `--web.basic-auth.password` (deprecated) | this exporter's own per-route `AuthMiddleware` | single user, basic auth | `401` with an **empty** body |

Neither rejection uses the `{"schemaVersion":1,"error":"..."}` envelope of
§1.4 — both are produced before the JSON handler is reached.

`/metrics.json` **must** be registered through the same `AuthMiddleware`
wrapper as `/` and `/metrics`, not left bare like `/health`. There is no
unauthenticated data path.

Response `Content-Type: application/json; charset=utf-8`.

### 1.1. Query parameters

| Param | Type | Default | Behaviour |
| --- | --- | --- | --- |
| `include` | comma list | `jails,alerts` | Sections to gather. Valid: `jails`, `bans`, `patterns`, `geo`, `activity`, `alerts`. Unknown or empty-after-trim member → `400`. Duplicates are collapsed. `include=` (present but empty) → `400`. |
| `maxIps` | integer | configured ceiling | Per-request cap on `bans.items`. See §1.2. |

Sections not requested are **absent from the response body**, not `null` and
not empty. A requested section with no data is present and empty (`[]` or an
object with zero counts).

`--collector.f2b.ip-anonymize` and `--collector.f2b.jail-include` /
`--collector.f2b.jail-exclude` are **static server configuration**. No query
parameter can request raw or unfiltered data: `/metrics.json` cannot be used to
see anything `/metrics` hides.

### 1.2. `maxIps` resolution

Let `ceiling` be `--collector.f2b.max-ip-metrics` (default `500`; `0` means
unlimited).

| Request | Effective cap |
| --- | --- |
| `maxIps` absent | `ceiling` |
| `maxIps=0` | `ceiling` (i.e. `0`/unlimited only when `ceiling == 0`) |
| `0 < maxIps <= ceiling` | `maxIps` |
| `maxIps > ceiling > 0` | `ceiling` (clamped) |
| `maxIps < 0` or non-integer | `400` |

The cap applies to `bans.items` only, and counts rows **after** the
anonymization collapse of §3.2 — it caps exported rows, not pre-collapse ban
records, mirroring `--collector.f2b.max-ip-metrics` on the Prometheus path.
`bans.total` always reports the full pre-truncation count, and every aggregate section (`jails`, `geo`, `activity`,
`patterns`, `alerts`) is computed over the complete data set.

### 1.3. Caching — `ETag` / `If-None-Match`

Every `200` carries a strong `ETag` of the form `"sha256-<64 hex chars>"`.

The digest is **not** taken over the response bytes. It is taken over a
canonical projection with wall-clock-derived fields removed, so that an
unchanged fail2ban state yields a stable ETag across requests:

Excluded from the digest:

- `collectedAt`
- `collectionDurationMs`
- `bans.items[].ageSeconds`
- `bans.items[].remainingSeconds`

Included in the digest, ahead of the body, is the normalised request scope
(`include` sections in canonical order, plus the effective `maxIps`), so two
different queries can never collide on one ETag.

`If-None-Match` is honoured for both a comma-separated list of entity tags and
the wildcard `*`. On a match the exporter replies `304 Not Modified` with the
`ETag` header and an **empty body**. Weak comparison (`W/` prefix) is accepted
on the request side.

Note that `bannedAt` / `expiresAt` remain in the digest; a snapshot is
considered changed when the ban *set* changes, not when time passes. With the
default `--collector.f2b.database-cache-ttl` of 60s, a poller faster than the
cache TTL will typically see `304`.

### 1.4. Errors

Failures that cannot be represented in the schema return the status below and
this body — never a `200` with a partially populated envelope:

```json
{ "schemaVersion": 1, "error": "human-readable reason" }
```

| Status | Cause |
| --- | --- |
| `400` | Unknown `include` section, malformed `maxIps`. |
| `401` | Authentication configured and credentials absent or wrong. Body shape depends on the mechanism — see §1. |
| `405` | Method other than `GET` or `HEAD`. |
| `500` | Snapshot gather or JSON serialisation failed. |

There is **no request-scoped deadline** on `/metrics.json`. `/metrics` honours
Prometheus's `X-Prometheus-Scrape-Timeout-Seconds`; no such header exists for a
generic JSON `GET`, and none is invented here. `--collector.f2b.timeout` bounds
each individual socket dial and command, but a gather issuing several
per-jail round trips is not bounded by it in total. A slow-but-reachable
fail2ban server therefore makes the request **block** rather than return `503`;
callers must set their own client timeout. Because a gather holds the collector
mutex for its whole body, one slow gather also delays subsequent requests to
both endpoints.

A **down fail2ban socket is not an error.** It is a representable state:
`fail2ban.up` is `false`, `errors.socketConn` has advanced, and jail-derived
sections are empty. This mirrors `f2b_up 0` on the Prometheus path.

---

## 2. Envelope

```jsonc
{
  "schemaVersion": 1,
  "collectedAt": "2026-09-04T18:22:41Z",
  "collectionDurationMs": 42,
  "exporter": {
    "name": "fail2ban-prometheus-exporter",
    "version": "1.2.0-beta",
    "commit": "c890612"
  },
  "host":  { "hostname": "example-host-01" },
  "labels": { "customerId": "", "customerName": "", "tenantId": "" },
  "fail2ban": {
    "up": true,
    "version": "1.0.2",
    "databaseEnabled": true,
    "geoEnabled": true
  },
  "errors": { "socketConn": 0, "socketReq": 0, "collection": 0 }
}
```

| Field | Type | Notes |
| --- | --- | --- |
| `schemaVersion` | int | Always `1`. |
| `collectedAt` | RFC3339 UTC string | Second precision, `Z` suffix. |
| `collectionDurationMs` | int | Gather wall time, milliseconds. |
| `exporter.name` | string | Constant `"fail2ban-prometheus-exporter"`. |
| `exporter.version` | string | `main.version`, injected by the `-ldflags` in `Makefile` / `.github/workflows/release.yml`. |
| `exporter.commit` | string | `main.commit`, same mechanism; `"none"` on unstamped builds. |
| `host.hostname` | string | `os.Hostname()`, or `"unknown"`. Same value as the `system` Prometheus label. |
| `labels.*` | string | `--customer.id`, `--customer.name`, `--tenant.id`. Empty strings when unset, never omitted. |
| `fail2ban.up` | bool | Socket connected **and** `ping` returned `pong`. |
| `fail2ban.version` | string | fail2ban server version; `""` when the socket is down. |
| `fail2ban.databaseEnabled` | bool | `--collector.f2b.database` set and the database opened. |
| `fail2ban.geoEnabled` | bool | `--geo.enabled` set and the provider initialised. |
| `errors.socketConn` / `errors.socketReq` | int | Cumulative-since-startup counters, matching `f2b_errors_total{type=...}`. Both also advance on a socket **timeout** (`--collector.f2b.timeout`), not only on a refused connection or protocol error — they can climb while fail2ban is merely slow rather than down. |
| `errors.collection` | int | **Not** cumulative: the error count for *this* gather (`0` or `1`), matching the value `f2b_collection_errors_total` reports. |

The envelope is always fully populated, on every request, regardless of
`include`.

---

## 3. Sections

Two server-side transforms apply to **every** section below, not just the one
that names them:

- **Jail filtering.** `--collector.f2b.jail-include` / `--collector.f2b.jail-exclude`
  are applied once, upstream of everything. `jails`, `bans`, `patterns`, `geo`,
  `activity` and `alerts` are all computed over the filtered set. A filtered-out
  jail is simply **absent everywhere** — it is never represented as a zero row.
- **IP anonymization.** `--collector.f2b.ip-anonymize` rewrites every IP-valued
  field the endpoint emits (`bans.items[].ip`, `patterns[].ip`) exactly as it
  rewrites the Prometheus `ip` label. See §3.2.

### 3.1. `jails`

Array, ordered by `name` ascending. Sourced from the fail2ban socket. Empty
array when the socket is down.

```jsonc
"jails": [{
  "name": "sshd",
  "filter":  { "currentlyFailed": 6,  "totalFailed": 125 },
  "actions": { "currentlyBanned": 15, "totalBanned": 31 },
  "config":  { "banTimeSeconds": 600, "findTimeSeconds": 600, "maxRetry": 5 }
}]
```

Every numeric field is an int. A field the socket could not supply is `-1`,
matching the sentinel the socket layer already returns — it is **not** omitted,
so consumers can distinguish "fail2ban said zero" from "fail2ban did not say".

### 3.2. `bans`

Object. Requires the database; when `fail2ban.databaseEnabled` is `false` the
section is present with `{"returned":0,"total":0,"truncated":false,"items":[]}`.

```jsonc
"bans": {
  "returned": 15,
  "total": 15,
  "truncated": false,
  "items": [{
    "jail": "sshd",
    "ip": "1.2.3.4",
    "bannedAt":  "2026-09-04T18:15:00Z",
    "expiresAt": "2026-09-04T18:25:00Z",
    "ageSeconds": 420,
    "remainingSeconds": 180,
    "banCount": 3,
    "firstSeenAt": "2026-08-01T04:11:00Z",
    "lastSeenAt":  "2026-09-04T18:15:00Z",
    "repeatOffender": true,
    "geo": {
      "countryCode": "US",
      "country": "United States",
      "city": "New York",
      "lat": 40.7128,
      "lon": -74.006
    }
  }]
}
```

| Field | Type | Notes |
| --- | --- | --- |
| `returned` | int | `len(items)`. |
| `total` | int | Active bans before truncation. |
| `truncated` | bool | `returned < total`. |
| `bannedAt` | RFC3339 UTC | From `bans.timeofban`. |
| `expiresAt` | RFC3339 UTC | `timeofban + bantime`. |
| `ageSeconds` | int | `collectedAt - bannedAt`, floored at `0`. |
| `remainingSeconds` | int | `expiresAt - collectedAt`, floored at `0`. |
| `ip` | string | The **anonymized** label — see below. |
| `banCount` | int | Times this IP label appears across the whole ban history, all jails. |
| `firstSeenAt` / `lastSeenAt` | RFC3339 UTC or `null` | `null` when the history carries no usable timestamp. |
| `repeatOffender` | bool | `banCount > 1`. |
| `geo` | object or omitted | Omitted when geo is disabled or the lookup returned nothing. |

`geo.lat` / `geo.lon` are JSON numbers. They are omitted from the `geo` object
when MaxMind reported no coordinates — this is the deliberate departure from
the Prometheus path, where they are `""`-valued label strings.

`items` is ordered by `bannedAt` **descending**, tie-broken by `jail` then `ip`
ascending. Truncation keeps the head of that ordering — the most recent bans —
matching `--collector.f2b.max-ip-metrics` semantics.

Bans whose `timeofban` or `bantime` is `0` are excluded, matching the
Prometheus time-based families.

#### Anonymization and row collapse

`items[].ip` is the anonymized label — the exact value that reaches
`f2b_banned_ip{ip=...}` — and is **never** the raw address:

| `--collector.f2b.ip-anonymize` | `items[].ip` |
| --- | --- |
| `none` (default) | the real address |
| `mask` | the enclosing CIDR block, e.g. `203.0.113.0/24` |
| `hash` | the first 16 hex characters of a salted SHA-256 |
| `mask` or `hash`, address unparseable | the literal `"unknown"` |

`bans.items` **collapses** on that label, mirroring the Prometheus series
one-for-one: one item per `(jail, ip)` pair, so several real addresses sharing
a masked block yield a single item. The ban-lifecycle fields (`bannedAt`,
`expiresAt`, `ageSeconds`, `remainingSeconds`) are taken from the **most recent**
ban in the collapsed group — the older records are dropped, not merged.
`total`, `returned` and `truncated` all count post-collapse rows, so `bans.total`
never exceeds the number of `f2b_banned_ip` series for the same state.

`banCount`, `firstSeenAt`, `lastSeenAt` and `repeatOffender` are properties of
the **IP label, not of the `(jail, ip)` pair.** They aggregate that label's
entire ban history across every jail, matching `f2b_ip_ban_count_total{ip=...}`
and its siblings, which carry no `jail` label. Two items sharing an `ip` in
different jails therefore report *identical* values for these four fields, and
an item's `banCount` may exceed the number of bans its own jail ever recorded.
This is inherited from the Prometheus contract; it is not specific to `mask`
mode.

`geo` is always derived from the **real** address, even when `ip` is masked or
hashed — anonymizing the label does not suppress geolocation. Under `mask`,
`geo` describes whichever real address won the collapse, not a canonical
location for the block.

### 3.3. `patterns`

Array of heuristic detections over the last 48 hours of ban history. Requires
the database; empty array otherwise.

```jsonc
"patterns": [
  { "type": "brute_force", "jail": "sshd", "ip": "1.2.3.4", "score": 72 }
]
```

| `type` | Trigger | `ip` |
| --- | --- | --- |
| `brute_force` | 3+ bans of one IP in one jail | the attacking IP |
| `port_scan` | 5+ distinct IPs banned in one jail | `""` |
| `distributed` | bans from 3+ countries in one jail (needs geo) | `""` |

`score` is a float. `ip` is always present, empty for multi-IP pattern types.

`patterns[].ip` passes through the **same** `--collector.f2b.ip-anonymize`
transform as `bans.items[].ip` (§3.2). This is a JSON-only surface with no
Prometheus analogue to inherit the transform from — the pattern detector is fed
the real address — so the anonymization must be applied explicitly here or the
setting silently has no effect on this one field.

Ordered by `type` ascending, then `jail` ascending, then `ip` ascending.

> Per-IP attribution appears here but deliberately **not** on the Prometheus
> `f2b_attack_pattern_type` metric, where it would be unbounded cardinality.

### 3.4. `geo`

Object. Requires `--geo.enabled`; present with empty arrays otherwise.
Aggregated over IPs currently banned according to the socket.

```jsonc
"geo": {
  "byCountry": [
    { "countryCode": "CN", "country": "China", "attacks": 412, "rank": 1 }
  ],
  "byCity": [
    { "city": "Shenzhen", "countryCode": "CN", "country": "China", "attacks": 88 }
  ]
}
```

`byCountry` is ordered by `attacks` descending, tie-broken by `countryCode`
ascending, and carries a 1-based `rank`. It is **not** truncated to ten —
`rank <= 10` reproduces the `f2b_top_attack_countries` series.

`byCity` is ordered by `attacks` descending, tie-broken by `city` then
`countryCode` ascending.

`f2b_geographic_attack_rate` has no JSON counterpart: it is
`attacks / 1.0` and carries no information beyond `attacks`.

### 3.5. `activity`

Object. Requires the database; present with zero-filled buckets otherwise.

```jsonc
"activity": {
  "byHour":      [{ "hour": 0, "attacks": 3 }, /* … exactly 24, hour 0→23 */],
  "byDayOfWeek": [{ "day": 0,  "attacks": 9 }, /* … exactly 7,  day 0→6  */],
  "velocityPerHour": 18.4,
  "suspiciousScore": 61
}
```

`byHour` always has 24 entries and `byDayOfWeek` always 7, zero-filled — unlike
the Prometheus path, which only emits buckets that have data. `day` is `0` for
Sunday. Bucketing uses the exporter host's local timezone, matching
`f2b_attacks_by_hour`.

These counts are **not cumulative**. They are recomputed from the rolling
48-hour ban window on every gather and can fall as old bans age out, which is
why `f2b_attacks_by_hour` / `f2b_attacks_by_day_of_week` are gauges rather than
counters. Do not apply `rate()` reasoning to them.

`velocityPerHour` is bans in the last hour. `suspiciousScore` is the 0–100
heuristic from `f2b_suspicious_pattern_score`. Both are floats.

### 3.6. `alerts`

Object. Always fully populated — every field present, arrays `[]` rather than
`null`.

```jsonc
"alerts": {
  "highBanRate": false,
  "repeatOffenderSpike": false,
  "newCountries": ["BR"],
  "jailInactive": ["postfix"],
  "coordinatedAttack": [{ "jail": "sshd", "countryCode": "CN" }]
}
```

| Field | Corresponds to |
| --- | --- |
| `highBanRate` | `f2b_alert_high_ban_rate`. `false` when no prior collection has established a baseline. |
| `repeatOffenderSpike` | `f2b_alert_repeat_offender_spike` — repeat-offender count up >50% since the last state-advancing gather. |

| `newCountries` | `f2b_alert_new_country_attack`, sorted ascending. |
| `jailInactive` | `f2b_alert_jail_inactive`, sorted ascending. |
| `coordinatedAttack` | `f2b_alert_coordinated_attack`, sorted by `jail` then `countryCode`. |

#### Alert state is not consumed by this endpoint

`newCountries` and `repeatOffenderSpike` are **edge-triggered**: a country fires
once, the first time it is seen. That edge lives in collector state.

`/metrics.json` gathers with alert-state mutation **disabled**. A JSON poll
reports the pending edges but does not consume them, so a parallel Prometheus
scrape still observes them. The consequence, which consumers must handle: a
country stays in `newCountries` on every JSON response until a `/metrics`
scrape consumes it. If nothing ever scrapes `/metrics`, `newCountries`
accumulates and `highBanRate` never leaves `false` — there is no baseline.

Treat `alerts` as *current pending state*, not as an event stream.

Under `--collector.f2b.ip-anonymize=mask`, repeat-offender counting groups by
masked label, so distinct attackers inside one block collapse into a single,
more-frequently-banned "offender". `repeatOffenderSpike` can therefore fire on
ban data that would not trigger it under `none` or `hash`. This is a real
side effect of the privacy setting, not a bug.

## 4. Relationship to `/metrics`

Four deliberate departures from the Prometheus exposition:

1. **Timestamps are RFC3339 strings**, not Unix floats stuffed into gauge
   values.
2. **`lat`, `lon`, `rank`, `hour`, `day` are numbers**, not label strings.
3. **A ban is one object**, not eight metric families to re-join on
   `(jail, ip)`.
4. **`truncated` is explicit**, rather than `--collector.f2b.max-ip-metrics`
   silently dropping series with a log line.

And one deliberate omission: **textfile-collector output is out of scope.**
`--collector.textfile.directory` files are parsed by an independently
registered `prometheus.Collector` and appear on `/metrics` as ordinary typed
metrics, with no relationship to the fail2ban domain snapshot. `/metrics.json`
reflects `f2b.Collector.Snapshot()`, not the full contents of the default
gatherer; a consumer wanting textfile data reads `/metrics`. This also keeps
untrusted, operator-authored floating-point values (legally `NaN` / `±Inf` in
the Prometheus text format, and rejected outright by `encoding/json`) off the
JSON path entirely.

Both endpoints' fail2ban sections are served from the same
`Collector.Snapshot()` gather and the same 60s database cache, so polling JSON
does not double the SQLite load.

Any float that does reach the envelope (`score`, `velocityPerHour`,
`suspiciousScore`, `geo.lat` / `geo.lon`) must be checked for `NaN` and `±Inf`
before serialisation and omitted if non-finite — `encoding/json.Marshal` fails
the whole response otherwise.

---

## 5. Stability

| Guarantee | v1 |
| --- | --- |
| Field added | Allowed without a version bump. |
| Field removed or retyped | Requires `schemaVersion: 2`. |
| Ordering rules above | Stable — they are what makes the `ETag` meaningful. |
| Section added to `include` | Allowed; unknown sections still `400`, so probe before use. |
