# Git workflow and shared-tree protection

- Begin with `git status --short`, `git diff`, and `git diff --cached`; inspect
  the current branch before branch-dependent actions. Preserve existing work.
- Use the user's target branch or the repository's actual workflow. This repo
  has no established requirement for a `develop` / `vX.Y` branch model.
- Do not use `git stash`, including autostash or wrapper scripts, to clean up a
  verification or commit. It can remove another contributor's work. Use an
  isolated worktree when isolation is needed.
- A specifically user-authorized stash requires a passing
  `CGO_ENABLED=0 go build -o <temporary-binary> .` first. If that fails, preserve
  the work and report the failure; stashing the broken state needs explicit
  authorization covering that fact. Never revert someone else's work to pass.
- Never reset, clean, overwrite, or delete unrelated work or remove an active
  `.git/index.lock`. Do not amend published commits or force-push shared branches.
- When committing is in scope, use one logical change per commit. Prefer
  `<type>(<scope>): <description>` with scopes such as `collector`, `socket`,
  `server`, `auth`, `cfg`, `geo`, `docs`, or `ci`.
- Stage only at commit time, using explicit paths. Inspect whole files first:
  a path-scoped commit includes all changes in those files. If a file contains
  unrelated edits, resolve ownership or isolate your change before committing.
- Write the commit message to a temporary file. Scope both commands:
  `git add -- <owned-paths>` followed immediately by
  `git commit -F <message-file> -- <owned-paths>`. Never use `git add .`,
  `git add -A`, or a bare commit that sweeps the entire index.
- Keep unrelated staged files staged. Do not commit, push, tag, or publish just
  because a documentation task mentions a release procedure.
