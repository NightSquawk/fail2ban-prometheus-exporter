# Agent guidance adaptation review

Reviewed 2026-09-13 against this exporter checkout and a private agent-guidance
template from another project. That template is provenance only; the resulting
rules require no access to it.

## Project goal and implementation

The exporter turns one running Fail2Ban instance into monitoring data: live jail
state from its Unix socket, optional historical/heuristic enrichment from its
SQLite database, optional MaxMind geo labels, and independent textfile metrics.
Prometheus output supports dashboards and alerting. `/metrics.json` serves the
same Fail2Ban domain through a versioned, joined snapshot for programmatic pollers.

The important design constraints are compatibility, predictable scrape cost,
resource cleanup, optional enrichment, IP privacy, and consistent endpoint auth.
Customer/tenant labels are attribution metadata, not an isolation implementation.
Future multi-target support is planned, not present. The project is a single Go
module, not a multi-service application platform.

There were no `AGENTS.md`, `CLAUDE.md`, `GEMINI.md`, or agent rule directories in
the exporter at review time. Existing process material was the README, roadmap,
beta changelog, release instructions, schema, Makefile, and CI/packaging files.

## Source review and transposition

The source review covered the template's AGENTS/CLAUDE/GEMINI entry documents,
four mirrored rule inventories, the rule topics below, activity-hook replication
notes, and the skill-library catalog. Exporter source and tests determined which
requirements could be transferred. The template's specialized skills and machine
settings were not installed or copied.

| Template source | Exporter adaptation |
|---|---|
| Core instructions | Focused edits, existing patterns, clear evidence, briefing agents when delegated; Go package ownership replaces frontend/RLS constraints |
| Git workflow and stash/build gate | Shared-tree protection, explicit commit paths, conventional commits, Go build gate for specifically authorized stashes; actual exporter release branches retained |
| Socket/connection management | Deterministic close, bounded operations/concurrency, shared-state locking, stalled-socket tests; Node/SSH/BullMQ recipes omitted |
| Permission enforcement and auth/session security | Same auth on both metrics endpoints, toolkit/legacy modes, health exception, regression coverage; no invented roles, JWTs, sessions, or UI guards |
| Audit logging and form/RUM privacy | Actionable secret-safe diagnostics and IP privacy; no compliance certification claims, audit database, browser forms, or retention mandates |
| Backend route and service patterns | Thin Go HTTP handlers, shared collector logic, protocol/storage ownership; no Fastify or service singleton convention |
| Data-interface definition of done | Source-to-snapshot-to-output checklist, shared state, filtering/privacy/caps, schema/goldens/consumer updates; no device persistence or scheduling write targets |
| Feature-flag pattern and requirement | Existing CLI/env configuration, opt-in costly or experimental collection, startup validation; no flag for every ordinary fix or existing endpoint |
| Database migrations | Fail2Ban-owned schema and observational SQL access; no exporter migrations, PostgreSQL RLS, or application tables |
| Changelog generation | Operator-facing beta/stable notes, compatibility and dashboard impacts; no in-app changelog or assumed `develop` branch |
| Context7 | Verify pinned APIs using available documentation tools or official source; no required MCP installation |
| Activity logging and hook notes | Completion evidence; external billing only under an established project policy, no inferred client attribution or global hook installation |
| Worker, frontend, shadcn rules | Omitted: no job queue, SPA, component library, or theming system here |
| Skill-library catalog | Build-versus-runtime evidence and source-first investigation reflected in rules/development guide; no copied project-specific skills |
| Mirrored agent surfaces | One canonical Markdown rule set with a checked sync helper, small entry docs, and Cursor metadata; avoids manual four-way drift |

## Findings that shape the guidance

- At review time the checked-out branch was `1.1.0-beta`, while the beta changelog
  headed an unreleased `1.2.0-beta` section and `exporter.go` had a `1.0.0` fallback.
  CI injects metadata. Agents must establish release intent rather than infer it
  from any one of these strings.
- Release CI accepts version/release prefixes, dotted version branch patterns,
  and `v*` tags. Pushing a matching branch can create a tag and publish a release.
  The release guide's broad staging example was changed to explicit file paths.
- Stable release notes reference `CHANGELOG.md`, which does not yet exist. The
  beta changelog is the current release record; a stable release must supply its
  referenced notes.
- The README says there are no configuration files, but `--web.config-file`
  provides exporter-toolkit configuration. New guidance records the exception.
- SQLite queries are observational, but `NewDatabase` opens the supplied path
  without a read-only DSN. The rules distinguish intended ownership from enforced
  access mode; this task did not change database behavior.
- `/health` is outside the legacy auth middleware but inside exporter-toolkit's
  listener. Calling it unconditionally unauthenticated would be inaccurate.
- The roadmap includes a Docker healthcheck even though `Dockerfile` already has
  one. It also records historical counters backed by purged rows. Planned-work
  text must be checked against implementation before it becomes a requirement.
- JSON has deliberate endpoint-specific behavior: no request-scoped gather
  timeout, non-consuming alert reads, and time-stripped ETags that still change
  when outage error counters advance. Generic timeout/cache rules must preserve
  those contracts.

These findings informed the new guidance. Application code, deployment settings,
and product behavior were not changed by this adaptation.
