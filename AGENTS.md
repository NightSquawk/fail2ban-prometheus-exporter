# Fail2Ban Prometheus Exporter

## Goal and architecture

Expose the state of one running Fail2Ban instance as Prometheus metrics and a
versioned JSON snapshot. Keep collection reliable, inexpensive, and compatible
with existing dashboards and pollers. Optional SQLite history, MaxMind geo data,
and textfile metrics enrich the socket-based view. This is an observability
process; it does not manage bans or own Fail2Ban's database schema.

- Go module: `github.com/NightSquawk/fail2ban-prometheus-exporter`.
- Toolchain baseline: `go.mod` (currently Go 1.25.0); GitHub CI selects Go 1.25.
- One binary, `fail2ban_exporter`; no frontend, queue, or application database.
- Default listener `:9191`; default socket `/var/run/fail2ban/fail2ban.sock`.
- Customer and tenant labels are metadata, not authorization or tenant isolation.

| Area | Source of truth |
|---|---|
| Startup, build metadata, collector registration | `exporter.go` |
| CLI/env parsing, validation, typed settings | `cfg/cfg.go`, `cfg/settings.go` |
| Collection, shared state, health probe | `collector/f2b/collector.go` |
| Domain snapshot and Prometheus rendering | `collector/f2b/snapshot.go`, `collector/f2b/flatten.go` |
| Metric descriptors, filtering, privacy, heuristics | `collector/f2b/socket.go`, `filter.go`, `patterns.go` in that directory |
| Fail2Ban Unix socket and pickle protocol | `socket/` |
| SQLite history, optional geo, textfile input | `collector/database/`, `geo/`, `collector/textfile/` |
| HTTP, authentication, TLS integration | `server/`, `auth/` |
| JSON compatibility contract | `docs/metrics-json-schema-v1.md` |
| Operator docs and examples | `README.md`, `_examples/` |
| Planned work and release evidence | `ROADMAP.md`, `CHANGELOG-BETA.md`, `RELEASE.md`, `.github/workflows/` |

## Rules and entry points

Read `.claude/rules/core-instructions.md`, `git-commit-workflow.md`, and
`validation-and-qa.md` before changing the project. Read the applicable domain
rules below before implementation. Paths in this paragraph are relative to
`.claude/rules/`. These are repository instructions even when a client does not
automatically load its rules directory.

| Rule | Apply when |
|---|---|
| `core-instructions` | All work; scope, evidence, architecture boundaries |
| `git-commit-workflow` | All changes; shared-tree protection, commits, stash handling |
| `validation-and-qa` | All changes; verification and completion evidence |
| `socket-connection-management` | Socket, HTTP, database, file, or goroutine lifecycle changes |
| `auth-and-privacy` | Endpoints, authentication, exported data, logs, labels |
| `data-interface-pattern` | Collectors, snapshots, Prometheus metrics, JSON schema |
| `configuration-and-storage` | Flags, environment variables, optional features, SQLite |
| `changelog-and-release` | Operator-visible changes, versioning, packaging, releases |
| `documentation-research` | Library APIs, configuration, documentation, investigation |
| `activity-logging` | Task handoff evidence and explicitly configured activity logging |

| Agent surface | Entry point | Rules |
|---|---|---|
| Claude | `CLAUDE.md` | `.claude/rules/*.md` (canonical) |
| Codex | `AGENTS.md` | `.codex/rules/*.md` (mirror; read explicitly) |
| Cursor | `AGENTS.md` | `.cursor/rules/*.mdc` (mirror) |
| Gemini | `GEMINI.md` | `.gemini/rules/*.md` (mirror; read explicitly) |

Edit canonical rules, then run `python3 scripts/sync-agent-rules.py --write`.
Run `python3 scripts/sync-agent-rules.py --check` to detect drift. Rule bodies
are identical across clients; Cursor adds rule metadata. Do not edit mirrors.

## Commands

```bash
go mod download
go test ./... -race
go vet ./...
gofmt -l .                      # Any output means formatting needs attention
CGO_ENABLED=0 go build -o /tmp/fail2ban-exporter-check .
python3 scripts/sync-agent-rules.py --check
```

Use a unique temporary output path when other work may run concurrently. Building
with `-o` avoids overwriting an existing local exporter binary. `make test`,
`make vet`, `make check/fmt`, `make build`, and `make build/docker` also exist;
`make fmt` runs `go mod tidy`, and `make update` upgrades dependencies, so neither
is a read-only check. See `docs/development.md` for task-specific validation.

## Critical contracts

- `/metrics` and `/metrics.json` use the same configured authentication. Both
  can be public when authentication is not configured; do not imply auth is on
  by default. Exporter-toolkit provides TLS/mTLS and web-config basic auth.
- `/health` bypasses legacy `AuthMiddleware`; exporter-toolkit still wraps the
  whole listener. Probes must close their socket and must not increment scrape
  error counters or consume alert state.
- Collect domain data through the shared snapshot, then render it. JSON polls
  must not consume Prometheus alert edges or honor exit-on-socket-error.
- Preserve jail filtering, IP anonymization/collapse, per-IP caps, and complete
  aggregate counts across output formats. Read the schema for JSON-specific
  ordering, truncation, and ETag behavior.
- Keep expensive optional collection opt-in and socket operations bounded. A
  request timeout returning to a client does not prove collection stopped.
- Confirm branch and release intent from local Git and workflows. Version-named
  branch pushes can publish releases; do not assume another branch model.

Adaptation rationale and known documentation discrepancies are recorded in
`docs/agent-guidance-adaptation.md`.
