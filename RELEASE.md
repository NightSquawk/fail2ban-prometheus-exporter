# Release Process

This document describes how to create a new release of the fail2ban-prometheus-exporter.

Read [the development workflow](docs/development.md) and the actual
[release workflow](.github/workflows/release.yml) before publishing. Pushing a
matching branch (`version-*`, `release/*`, or the workflow's dotted version
patterns, including `1.2.0-beta`) or a `v*` tag can automatically publish a release.
Use an ordinary feature branch for work that is not ready for publication.

## Release Workflow

We use **branch-based versioning** where the version is determined by the branch name. This allows you to work on a specific version in isolation before releasing.

## Creating a Release

### Method 1: Version Branch (Recommended)

1. **Create a version branch from main:**
   ```bash
   git checkout main
   git pull origin main
   git checkout -b version-1.0.0
   ```

2. **Make any final adjustments and validate** using the Go test, vet, formatting,
   and build checks in [the development workflow](docs/development.md). Stable
   releases must create or update `CHANGELOG.md`; beta/alpha/rc releases use
   `CHANGELOG-BETA.md`. Confirm the intended version and linker-injected metadata.

3. **Commit and push the branch:**
   ```bash
   # Example for a stable release changing only CHANGELOG.md.
   # Substitute the explicit reviewed paths for your release on BOTH commands.
   release_message=$(mktemp)
   printf '%s\n' 'chore(release): prepare 1.0.0' > "$release_message"
   git add -- CHANGELOG.md
   git commit -F "$release_message" -- CHANGELOG.md
   git push origin version-1.0.0
   ```

4. **GitHub Actions will automatically:**
   - Build Linux and Windows binaries
   - Create a GitHub release with version `1.0.0`
   - Upload binaries with checksums

### Method 2: Release Branch (Alternative)

Same as above, but use `release/` prefix:
```bash
git checkout -b release/1.0.0
git push origin release/1.0.0
```

### Method 3: Git Tags (Traditional)

If you prefer traditional tag-based releases:
```bash
git tag v1.0.0
git push origin v1.0.0
```

## Version Format

- **Branch names**: `version-1.0.0`, `version-1.1.0`, `version-2.0.0`, etc.
- **Release branches**: `release/1.0.0`, `release/1.1.0`, etc.
- **Tags**: `v1.0.0`, `v1.1.0`, `v2.0.0`, etc.

The version number follows [Semantic Versioning](https://semver.org/):
- **MAJOR**: Breaking changes
- **MINOR**: New features (backward compatible)
- **PATCH**: Bug fixes (backward compatible)

## After Release

1. **Merge the version branch back to main** (optional, for history):
   ```bash
   git checkout main
   git merge version-1.0.0
   git push origin main
   ```

2. **Delete the version branch** (optional):
   ```bash
   git push origin --delete version-1.0.0
   ```

## Benefits of Branch-Based Versioning

- ✅ Work on a specific version in isolation
- ✅ Easy to see what's in each version
- ✅ Can make last-minute fixes before release
- ✅ Version is clear from branch name
- ✅ No need to update version in code for each release
- ✅ Supports multiple release candidates (version-1.0.0-rc1, etc.)

