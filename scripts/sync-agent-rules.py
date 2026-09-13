#!/usr/bin/env python3
"""Check or synchronize agent rule mirrors; canonical rules live under .claude."""

import argparse
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
SOURCE = ROOT / ".claude" / "rules"
MIRRORS = ((".codex", ".md"), (".cursor", ".mdc"), (".gemini", ".md"))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--check", action="store_true", help="check only (default)")
    mode.add_argument("--write", action="store_true", help="create/update mirrors")
    args = parser.parse_args()
    sources = sorted(SOURCE.glob("*.md"))
    if not sources:
        parser.error(f"no canonical rules found in {SOURCE}")

    issues = []
    for surface, suffix in MIRRORS:
        directory = ROOT / surface / "rules"
        expected_names = {p.stem + suffix for p in sources}
        # Report stale files; never delete a rule that may belong to another task.
        for path in sorted(directory.glob("*")):
            if path.suffix in (".md", ".mdc") and path.name not in expected_names:
                issues.append(f"unexpected rule: {path.relative_to(ROOT)}")
        for source in sources:
            body = source.read_text(encoding="utf-8")
            if suffix == ".mdc":
                title = body.splitlines()[0].removeprefix("# ")
                body = (
                    "---\n"
                    f"description: {title}\n"
                    "alwaysApply: true\n"
                    "---\n\n" + body
                )
            target = directory / (source.stem + suffix)
            matches = target.is_file() and target.read_bytes() == body.encode("utf-8")
            if matches:
                continue
            if args.write:
                directory.mkdir(parents=True, exist_ok=True)
                target.write_bytes(body.encode("utf-8"))
                print(f"updated: {target.relative_to(ROOT)}")
            else:
                issues.append(f"missing or different: {target.relative_to(ROOT)}")

    if issues:
        print("\n".join(issues))
        return 1
    print(f"Agent rules synchronized: {len(sources)} rules across 4 surfaces.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
