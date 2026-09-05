# `/metrics.json` — Schema v1

Versioned contract for the JSON snapshot endpoint exposed by
`fail2ban-prometheus-exporter` from `1.2.0-beta` onward.

`schemaVersion` is `1`. Within v1 the exporter may **add** fields; it will not
remove or retype existing ones. Consumers must ignore unknown fields.

---

## 1. Endpoint

```
GET /metrics.json
```

Protected by the **same** auth middleware as `/metrics`. When
`--web.basic-auth.username` / `--web.basic-auth.password` are set, an
unauthenticated request receives `401` with an empty body. There is no
unauthenticated data path.

Response `Content-Type: application/json; charset=utf-8`.

### 1.1. Query parameters

| Param | Type | Default | Behaviour |
| --- | --- | --- | --- |
| `include` | comma list | `jails,alerts` | Sections to gather. Valid: `jails`, `bans`, `patterns`, `geo`, `activity`, `alerts`, `textfile`. Unknown or empty-after-trim member → `400`. Duplicates are collapsed. `include=` (present but empty) → `400`. |
| `maxIps` | integer | configured ceiling | Per-request cap on `bans.items`. See §1.2. |

Sections not requested are **absent from the response body**, not `null` and
not empty. A requested section with no data is present and empty (`[]` or an
object with zero counts).

`textfile` is only meaningful when `--collector.textfile.directory` is set. If
the flag is unset the section is omitted even when requested — the request is
not an error.

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

The cap applies to `bans.items` only. `bans.total` always reports the full
pre-truncation count, and every aggregate section (`jails`, `geo`, `activity`,
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
| `401` | Basic auth configured and credentials absent or wrong. |
| `405` | Method other than `GET` or `HEAD`. |
| `500` | Snapshot gather or JSON serialisation failed. |

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
  "host":  { "hostname": "ovhlax-nst9f63" },
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
| `exporter.version` | string | goreleaser `main.version`. |
| `exporter.commit` | string | goreleaser `main.commit`; `"none"` on unstamped builds. |
| `host.hostname` | string | `os.Hostname()`, or `"unknown"`. Same value as the `system` Prometheus label. |
| `labels.*` | string | `--customer.id`, `--customer.name`, `--tenant.id`. Empty strings when unset, never omitted. |
| `fail2ban.up` | bool | Socket connected **and** `ping` returned `pong`. |
| `fail2ban.version` | string | fail2ban server version; `""` when the socket is down. |
| `fail2ban.databaseEnabled` | bool | `--collector.f2b.database` set and the database opened. |
| `fail2ban.geoEnabled` | bool | `--geo.enabled` set and the provider initialised. |
| `errors.*` | int | Cumulative-since-startup counters, matching `f2b_errors{type=...}`. `collection` matches `f2b_collection_errors_total`. |

The envelope is always fully populated, on every request, regardless of
`include`.

---

## 3. Sections

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
| `banCount` | int | Times this IP appears across the whole ban history, all jails. |
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

### 3.7. `textfile`

Present only when `--collector.textfile.directory` is set **and** `textfile` is
in `include`. Passthrough of the operator-supplied `.prom` files that `/metrics`
appends verbatim, parsed into samples.

```jsonc
"textfile": {
  "samples": [
    { "name": "my_metric", "labels": { "foo": "bar" }, "value": 1.5 }
  ],
  "files": [
    { "name": "custom.prom", "readErrors": 0, "parseError": "" }
  ]
}
```

`samples` is ordered by `name` ascending, then by the canonical serialisation of
`labels`. `labels` is `{}` when the sample is unlabelled, never `null`.

A file that fails to parse contributes no samples and records its reason in
`files[].parseError`. **A parse failure does not fail the request** — operator
text is untrusted input, and one bad file must not take down the endpoint.

---

## 4. Relationship to `/metrics`

Four deliberate departures from the Prometheus exposition:

1. **Timestamps are RFC3339 strings**, not Unix floats stuffed into gauge
   values.
2. **`lat`, `lon`, `rank`, `hour`, `day` are numbers**, not label strings.
3. **A ban is one object**, not eight metric families to re-join on
   `(jail, ip)`.
4. **`truncated` is explicit**, rather than `--collector.f2b.max-ip-metrics`
   silently dropping series with a log line.

Both endpoints are served from the same `Collector.Snapshot()` gather and the
same 60s database cache, so polling JSON does not double the SQLite load.

---

## 5. Stability

| Guarantee | v1 |
| --- | --- |
| Field added | Allowed without a version bump. |
| Field removed or retyped | Requires `schemaVersion: 2`. |
| Ordering rules above | Stable — they are what makes the `ETag` meaningful. |
| Section added to `include` | Allowed; unknown sections still `400`, so probe before use. |
