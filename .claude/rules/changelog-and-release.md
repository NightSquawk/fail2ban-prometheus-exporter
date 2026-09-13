# Changelog and release workflow

- Read `RELEASE.md` and `.github/workflows/release.yml` before release-related
  actions. Pushing `version-*`, `release/*`, dotted version branch patterns, or
  `v*` tags can trigger publication; a branch name is not a harmless staging label.
- Do not adopt another project's branch/release policy or assume a stable version
  from `exporter.go`: CI injects build metadata with linker flags. Read the current
  branch, workflow, and changelog to establish the actual target version.
- Put unreleased beta operator-facing changes in the appropriate existing section
  of `CHANGELOG-BETA.md`. Stable releases need `CHANGELOG.md`, which the workflow
  references but which is absent at the time this guidance was introduced.
- Describe concrete operator behavior, prerequisites, and fixes. Call out changed
  metric names/types/labels, defaults, JSON schema behavior, and required dashboard
  or polling changes. Keep internal agent-rule maintenance out of product notes.
- Separate planned work in `ROADMAP.md` from implemented changes and released
  artifacts. Do not mark a version released or invent a date based on code alone.
- Validate Go tests with the race detector, vet, formatting, and the release build
  matrix before publication. Cross-compilation proves buildability, not that a
  Fail2Ban Unix socket is usable on the target operating system.
- Review Dockerfile, GoReleaser, GitHub, and GitLab paths independently when
  changing packaging; they are separate mechanisms, not interchangeable proof.
- Keep releases/tags/pushes within the user's requested scope. This rule does not
  authorize publication as a side effect of editing source or documentation.
