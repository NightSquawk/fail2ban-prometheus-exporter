# Development workflow

Read [AGENTS.md](../AGENTS.md) for the project map and rules. The exporter gathers
one Fail2Ban instance and exposes that state for monitoring; optional inputs must
not make ordinary socket collection dependent on a separate service.

## Starting a change

1. Inspect branch, working tree, and staged changes. Read the affected package,
   tests, [README](../README.md), and relevant schema contract.
2. State the expected behavior, failure behavior, compatibility impact, and
   evidence needed. For a bug, reproduce it with the smallest useful fixture.
3. Change the owning layer. For a new signal, follow protocol/query → snapshot →
   Prometheus/JSON output → documentation and consumers.
4. Run relevant tests, then the required gates. Inspect the final diff, including
   fixtures and generated rule mirrors. Report evidence and unresolved limits.

## Prerequisites and checks

Use the Go version required by `go.mod` or a compatible newer toolchain; CI
currently selects 1.25. Race tests need the platform's supported race/CGO toolchain
and a C compiler. Production binaries use the pure Go SQLite driver with CGO
disabled. Linux supports the project's Unix-socket fixtures and deployment model.
Python 3.9+ is only needed for the agent-rule synchronization helper.

```bash
go mod download
go test ./... -race
go vet ./...
gofmt -l .
```

Formatting succeeds only when `gofmt -l .` prints nothing. Format changed Go files
explicitly, and do not use `make fmt` merely as a check: it also runs `go mod tidy`.
`make update` upgrades dependencies and is not part of routine validation.

Build into a temporary directory to preserve existing local binaries:

```bash
build_dir=$(mktemp -d)
CGO_ENABLED=0 go build -o "$build_dir/fail2ban_exporter" .
"$build_dir/fail2ban_exporter" --version
"$build_dir/fail2ban_exporter" --help
```

A direct build uses fallback metadata in `exporter.go`. `make build` and CI inject
version, commit, date, and builder values; a successful direct build is not a
released artifact. Keep `build_dir` for inspection or remove that specific temporary
directory when finished.

| Change | Focused evidence |
|---|---|
| Socket framing, errors, deadlines | `go test ./socket -race`; fragmented, malformed, closed, and stalled responses |
| Metrics, snapshots, filtering, privacy, alerts | `go test ./collector/f2b -race`; golden output, lint, counters, caps, alert-state and concurrent access tests |
| SQLite history | `go test ./collector/database ./collector/f2b -race`; temporary DBs, active/expired bans, missing sources, cache behavior |
| HTTP or authentication | `go test ./server ./auth -race`; both metrics endpoints, health, toolkit and legacy auth, HEAD, invalid query, ETag and failure responses |
| Textfile parsing | `go test ./collector/textfile -race`; malformed/duplicate files and valid exposition |
| CLI/env options | Build, inspect `--help`, and exercise valid/invalid inputs; add targeted validation coverage for changed behavior |
| Geo provider | Fixture-backed provider tests and affected collector tests; distinguish fake-provider proof from an actual mmdb lookup |
| Agent guidance or docs | Local links/paths, commands against source, `python3 scripts/sync-agent-rules.py --check`, `git diff --check` |

Package tests complement the full Go gates for code changes. Use the existing fake
daemon, clock, database, and geo fixtures; tests should not touch a running host's
ban state. Read golden diffs against
[the JSON schema](metrics-json-schema-v1.md) before updating expected output.

## Packaging and release checks

GitHub currently builds Linux/amd64 and Windows/amd64 with `CGO_ENABLED=0`. When
changing dependencies, startup, or packaging, reproduce the relevant cross-builds
into a temporary directory. Windows build success does not verify a usable
Fail2Ban Unix socket deployment on Windows.

Review `Dockerfile`, `Dockerfile.goreleaser`, `.goreleaser.yml`, and `.gitlab-ci.yml`
when the change affects those paths. A successful GitHub binary build says nothing
about Docker image publication or the separate GitLab/GoReleaser workflow.

Follow [RELEASE.md](../RELEASE.md). Release-pattern branch pushes and tags can
publish immediately. Ordinary guidance maintenance does not require a release,
a version bump, or a product changelog entry.

## Maintaining agent rules

Edit `.claude/rules/*.md`, then:

```bash
python3 scripts/sync-agent-rules.py --write
python3 scripts/sync-agent-rules.py --check
```

The helper runs from any directory, creates `.codex` and `.gemini` Markdown copies
and Cursor `.mdc` copies with metadata, and exits nonzero on drift. Its default
mode is read-only checking. Unexpected rule files are reported and never deleted
automatically; review them explicitly when renaming/removing canonical rules.

Project guidance is shared through `AGENTS.md`; `CLAUDE.md` imports it and
`GEMINI.md` instructs readers to load it. No personal MCP settings, global hooks,
credentials, or billing destinations are installed by this workflow.
