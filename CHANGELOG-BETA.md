# Beta Changelog

This document tracks beta releases and pre-release versions.

## [1.2.0-beta] - unreleased

### Added
- TLS, mutual TLS and multi-user basic auth with bcrypt-hashed passwords via `--web.config-file`, using [prometheus/exporter-toolkit](https://github.com/prometheus/exporter-toolkit). The file is re-read per request, so certificates and credentials rotate without a restart
- `--collector.f2b.timeout` (default `5s`) bounding the socket dial and every command sent over it; `0` restores the previous unbounded behaviour
- The `X-Prometheus-Scrape-Timeout-Seconds` header Prometheus sends is now honoured, so an over-long gather returns `503` instead of holding the scrape connection open
- `--collector.f2b.jail-include` / `--collector.f2b.jail-exclude` regular expressions selecting which jails are exported, applied to every jail-scoped metric family including `f2b_jail_count`
- `--collector.f2b.ip-anonymize=none|mask|hash` with `--collector.f2b.ip-mask-bits-v4` / `-v6` and `--collector.f2b.ip-hash-salt`, for deployments that cannot export attacker addresses. Geo lookups and attack-pattern detection keep using the real address
- A promlint test over the golden `/metrics` fixture, so a new metric cannot land with a name or type that Prometheus conventions reject
- Tests for the textfile collector, the jail filter and IP anonymizer, socket timeout behaviour, and scrape-timeout header parsing
- `GET /metrics.json`, a schema-v1 JSON snapshot of fail2ban state behind the **same** authentication as `/metrics` — there is no unauthenticated path to this data. `?include=` selects which sections to gather and `?maxIps=` caps `bans.items`; a strong `ETag` over a wall-clock-stripped projection lets a poller send `If-None-Match` and get a `304` back for an unchanged snapshot instead of re-downloading it, while fail2ban stays up and unchanged — a persistently down or erroring socket advances `errors.socketConn`/`errors.socketReq` on every gather, which is not excluded from the digest, so a `304` should not be expected in that state. See [`docs/metrics-json-schema-v1.md`](docs/metrics-json-schema-v1.md) for the full field-by-field contract
- `/health` now reports the exporter's name and version in its body by default, so an operator hitting the endpoint learns what's actually running there. `--web.health.minimal` / `F2B_WEB_HEALTH_MINIMAL` restores the bare `{"healthy":bool}` shape for anyone who considers the version string a disclosure on an unauthenticated endpoint

### Changed
- **Breaking:** `f2b_errors` is renamed `f2b_errors_total`. The bundled Grafana dashboard is updated; external dashboards and alerting rules referencing the old name need updating
- **Breaking:** `f2b_jail_banned_total` and `f2b_jail_failed_total` are now exposed as counters instead of gauges (names unchanged). `f2b_attacks_by_hour` and `f2b_attacks_by_day_of_week` are now gauges instead of counters — they are recomputed each scrape from a rolling 48h window and fall as bans age out, so they were never valid counters
- **Behavioral:** `f2b_jail_count` reports the number of jails this exporter exports, which differs from the number fail2ban has configured when a jail filter is set
- The textfile collector now parses each `.prom` file as Prometheus text exposition format and emits real metrics, instead of appending raw file bytes to the HTTP response. Malformed files and duplicate metric families are reported through `textfile_error` and skipped rather than failing the whole scrape
- `--web.basic-auth.username` / `--web.basic-auth.password` are deprecated in favour of `--web.config-file` and cannot be combined with it. They continue to work unchanged
- The HTTP server uses its own `ServeMux` rather than `http.DefaultServeMux`
- Socket errors are now wrapped with `%w`, so callers can match them with `errors.Is`
- Dependency bump pulled in by exporter-toolkit: `client_golang` 1.21.1 → 1.23.2, `prometheus/common` 0.63.0 → 0.70.1
- The collector is now split into a domain snapshot (`collector/f2b/snapshot.go`) and a metric-emission step (`flatten.go`) that renders it as Prometheus metrics, with `Collect()` reduced to snapshot-then-flatten; `/metrics` stays byte-identical, pinned by the golden fixture (`collector/f2b/testdata/metrics.golden`). One intentional behavioral change ships alongside the refactor: ban age and remaining time (`f2b_ban_age_seconds`, `f2b_ban_duration_remaining_seconds`, and their `/metrics.json` equivalents) now derive from a single instant captured at the start of the gather, rather than a fresh clock read taken separately for each metric partway through a collection — the two families can no longer drift apart within one scrape

### Fixed
- Textfile metrics corrupted the scrape payload for any client sending `Accept-Encoding: gzip` — which Prometheus always does. The raw file bytes were appended after promhttp had already written and compressed the response body
- A wedged fail2ban server blocked a scrape indefinitely: no read, write or dial deadline was ever set on the unix socket. Because a collection holds a mutex for its full duration, every subsequent scrape queued behind the stuck one and goroutines accumulated
- `/health` no longer advances `f2b_errors_total`. It is unauthenticated, so any caller able to reach the port could previously inflate a counter operators alert on, simply by polling `/health` while fail2ban was down
- The health probe now closes the socket it opens. It never did, so every probe leaked a file descriptor — at the container healthcheck's 10s interval, a slow resource exhaustion

## [1.1.0-beta] - 2026-08-07

### Added
- Fail2ban SQLite database reader (`--collector.f2b.database`) using a pure Go driver (`modernc.org/sqlite`, no cgo) — logs a warning and continues if the database cannot be opened
- Time-based ban metrics: `f2b_ban_duration_remaining_seconds`, `f2b_ban_age_seconds`, `f2b_ban_expiry_timestamp`
- Historical ban metrics: `f2b_ban_history_total`, `f2b_ip_ban_count_total`, `f2b_ip_first_seen_timestamp`, `f2b_ip_last_seen_timestamp`, `f2b_repeat_offender`
- Geographic aggregate metrics: `f2b_attacks_by_country_total`, `f2b_attacks_by_city_total`, `f2b_top_attack_countries`, `f2b_geographic_attack_rate`
- Heuristic attack-pattern metrics: `f2b_attack_pattern_type` (brute_force / port_scan / distributed, per jail), `f2b_attacks_by_hour`, `f2b_attacks_by_day_of_week`, `f2b_attack_velocity`, `f2b_suspicious_pattern_score`
- Alert gauges with configurable thresholds (`--alert.ban-rate-threshold`, `--alert.coordinated-min-ips`, `--alert.jail-inactivity-hours`): `f2b_alert_high_ban_rate`, `f2b_alert_new_country_attack`, `f2b_alert_coordinated_attack`, `f2b_alert_jail_inactive`, `f2b_alert_repeat_offender_spike`
- Multi-tenant labels `customer_id`, `customer_name`, `tenant_id` on all metrics (`--customer.id`, `--customer.name`, `--tenant.id`)
- Collector self-metrics: `f2b_collection_duration_seconds`, `f2b_database_query_duration_seconds`, `f2b_geo_lookup_duration_seconds`, `f2b_metrics_exported_total`, `f2b_collection_errors_total`
- Per-IP series cap `--collector.f2b.max-ip-metrics` (default 500, most recent first, 0 = unlimited) to bound metric cardinality on busy hosts
- Database query cache `--collector.f2b.database-cache-ttl` (default 60s) so frequent Prometheus scrapes do not run full-table SQLite scans every time
- Unit tests for the database reader and pattern detectors; release workflow now runs tests before building
- Reworked example Grafana dashboard covering the new metric families
- `.gitattributes` enforcing LF line endings (repo syncs through Windows)

### Changed
- **Breaking/behavioral:** module path and repository moved from `github.com/Kvrnn/...` to `github.com/NightSquawk/fail2ban-prometheus-exporter`
- **Behavioral:** database-backed metrics are opt-in — `--collector.f2b.database` defaults to empty instead of `/var/lib/fail2ban/fail2ban.sqlite3`, so upgrading does not silently create hundreds of new per-IP series on hosts with a readable fail2ban database
- All metrics now carry the customer/tenant label set (empty strings when unset); dashboards matching on exact label sets may need updating

### Fixed
- Active-ban database queries compared an integer timestamp against a text value, so they never matched any rows; the timestamp is now cast correctly
- Attack-pattern detection rebuilt per scrape — previously bans were re-added to a persistent detector on every scrape, inflating pattern counts and growing memory

## [1.0.0-beta] - 2025-12-12

### Added
- Initial beta release of fail2ban-prometheus-exporter with geo-tagging support
- System name (hostname) label on all metrics
- Per-IP banned metrics (`f2b_banned_ip`) with geo-tagging support
- MaxMind GeoIP2 integration for location data (city, latitude, longitude, country, country_code)
- Support for reading banned IPs from fail2ban socket
- Comprehensive Prometheus metrics including:
  - Jail statistics (banned/failed counts)
  - Jail configuration (ban time, find time, max retries)
  - Error tracking
  - Version information
- GitHub Actions workflows for automated builds and releases
- Support for Linux (amd64) and Windows (amd64) builds

### Changed
- Forked from original GitLab repository and updated for GitHub
- Integrated geo-tagging functionality from fail2ban-geo-exporter
- Enhanced metrics with system labels for multi-instance monitoring