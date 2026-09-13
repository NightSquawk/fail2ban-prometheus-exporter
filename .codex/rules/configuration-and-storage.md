# Configuration, optional features, and storage

- Define CLI/env options in `cfg/cfg.go`, carry them through `cfg/settings.go`,
  validate at startup, and document exact defaults and env names in `README.md`.
  Reuse existing settings; do not invent a parallel feature-flag registry.
- New expensive, high-cardinality, or experimental collection should be opt-in
  until its behavior and cost are verified. Gate resource initialization and work,
  not merely the final output. Ordinary bug fixes do not need a new feature flag.
- Preserve existing database-off and geo-off defaults, per-IP caps, cache TTL,
  socket timeout semantics, and auth-mode validation unless explicitly changing
  operator behavior with documentation and tests.
- Application settings are CLI/env driven. `--web.config-file` is the existing
  exception for exporter-toolkit TLS/auth configuration; do not claim there are
  no configuration files at all.
- Fail2Ban owns its SQLite schema and data. Exporter production queries should
  observe it, not create tables, migrate, purge, or modify bans. The current
  `sql.Open("sqlite", dbPath)` does not enforce read-only mode; do not claim it
  does. Any read-only DSN hardening needs compatibility and missing-file tests.
- Preserve the pure Go `modernc.org/sqlite` driver and `CGO_ENABLED=0` builds.
  Keep SQL in `collector/database/`, bind values, close rows, and test against
  temporary fixtures reflecting supported Fail2Ban schemas.
- Preserve graceful socket-only operation when optional database initialization
  fails. Account for query cost, cache freshness, Fail2Ban purging history, and
  retained database resources rather than adding scans per metric family.
- Deployment examples should mount the socket's parent directory because the
  daemon recreates the socket. Use synthetic paths/credentials in examples and
  preserve operator ownership of actual secrets and runtime configuration.
