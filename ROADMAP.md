# Roadmap

Planned work, in rough priority order. Nothing here is scheduled; the intent is
that each item is specific enough to pick up without re-deriving the analysis.

Shipped work lives in [CHANGELOG-BETA.md](CHANGELOG-BETA.md).

## Geo improvements

The `geo` package works but is minimal. Four separate changes:

- **ASN support.** Add a GeoLite2-ASN reader alongside the City reader, exposing
  `asn` and `as_org` labels. For abuse triage, "which hosting provider is this"
  is usually a more actionable question than "which city", and it is what
  distinguishes a compromised residential host from bulletproof hosting.
- **Lookup cache.** `MaxMindProvider.Annotate` re-queries the mmdb for every
  banned IP on every scrape, and several collectors each look up the same
  addresses independently within one collection. An LRU keyed on the address
  would cut `f2b_geo_lookup_duration_seconds` substantially on hosts with
  hundreds of active bans.
- **Database reload.** `geoipupdate` replaces the mmdb file on a cron, but the
  exporter holds the reader it opened at startup until it is restarted, so the
  data silently goes stale. Watch the file's mtime and reopen.
- **Skip non-routable addresses.** Private, loopback and CGNAT ranges are never
  in the database, so each one logs a failed lookup on every scrape. Short-circuit
  them before the lookup.

## Structured logging

The exporter uses the standard library `log` package throughout. Move to
`log/slog` with `--log.level` and `--log.format=json` flags, matching the
convention other Prometheus exporters follow. `server/server.go` already
constructs an `slog.Logger` for exporter-toolkit, which would become the
process-wide logger.

This also fixes a specific annoyance: `geo/maxmind.go` logs a line per failed
lookup per scrape with no rate limiting, so a single unroutable address in the
ban list produces a log line every scrape interval, forever.

## Multiple fail2ban targets from one exporter

Today one exporter process reads one socket. Either accept a repeated
`--collector.f2b.socket` flag, or adopt the multi-target `/probe?target=`
pattern that `blackbox_exporter` uses. This is what makes the existing
`customer_id` / `tenant_id` labels genuinely useful: one exporter covering
several containers or namespaces on a host, rather than one process per target.

## Fail2ban configuration metrics

Expose the jail configuration that is already reachable over the socket but not
currently read: `ignoreip` entry count, `backend` type, `dbpurgeage`, and the
configured action names per jail. Cheap to collect and useful for detecting
config drift across a fleet of hosts.

## Honest ban-rate counter

`f2b_ban_history_total` is the row count of the fail2ban `bans` table, which
fail2ban purges according to `dbpurgeage` (24h by default). `rate()` over it
therefore reports a spurious drop at every purge. The same applies to
`f2b_attacks_by_country_total` and `f2b_attacks_by_city_total`.

Fix by tracking newly-seen `(jail, ip, timeofban)` tuples in-process and
exporting a genuinely monotonic counter, so the metric survives database purges.

## Packaging and supply chain

- `HEALTHCHECK` in the Dockerfile against `/health`
- cosign signatures and an SBOM in `.goreleaser.yml`
- `govulncheck` and `golangci-lint` in `.github/workflows/build.yml`, which
  currently runs only `go vet` and a `gofmt` check
- `.deb` and `.rpm` packages via goreleaser's nfpm support — the systemd unit in
  `_examples/systemd/` is already there

## Example Prometheus rules

The repository ships a Grafana dashboard but no alerting rules. Add
`_examples/prometheus/rules.yml`.

Related: the `f2b_alert_*` gauges bake their thresholds into the exporter, which
inverts the usual Prometheus split where the exporter reports facts and the
server evaluates policy. The same conditions expressed as PromQL over
`f2b_jail_banned_total` are more flexible and cost nothing at scrape time. The
gauges stay for compatibility, but the rules file should be presented as the
recommended path.
