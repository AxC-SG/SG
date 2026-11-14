#!/usr/bin/env python3
"""Validate the append-only Flyway migration lines.

Always: every migration file is named V<n>__<name>.sql and contains SQL.
With a base revision (pull requests): applied migrations are never edited,
deleted or renamed, and an added version must not already exist in the same
line on the base branch. The platform and tenant lines are versioned
independently.

There is no migration-history reset exception. A reset needs its own
explicitly authorized change to this checker.
"""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
from pathlib import Path

LINES = (
    "prototype-app/backend/src/main/resources/db/migration/postgres_reset",
    "prototype-app/backend/src/main/resources/db/migration/tenant",
)
NAME = re.compile(r"^V([0-9]+)__[A-Za-z0-9][A-Za-z0-9_.-]*\.sql$")
VERSIONED = re.compile(r"^V\d+__.+\.sql$")
SQL = re.compile(r"\b(create|alter|drop|insert|update|delete|grant)\b", re.I)

# Historical repairs, each reviewed when it happened. They match only these exact paths.
RETIRED_COLLISIONS = {
    "prototype-app/backend/src/main/resources/db/migration/postgres_reset/V4__github_security_advisories_platform.sql",
    "prototype-app/backend/src/main/resources/db/migration/postgres_reset/V4__osv_supplement.sql",
    "prototype-app/backend/src/main/resources/db/migration/tenant/V4__github_security_advisories_tenant.sql",
}
REPAIRED_OSV_RENAME = (
    "prototype-app/backend/src/main/resources/db/migration/postgres_reset/V4__osv_supplement.sql",
    "prototype-app/backend/src/main/resources/db/migration/postgres_reset/V7__osv_supplement_platform.sql",
)


def git(root: Path, *args: str) -> list[str]:
    return subprocess.check_output(["git", *args], cwd=root, text=True).splitlines()


def versions(root: Path, ref: str, line: str) -> set[int]:
    found = set()
    for name in git(root, "ls-tree", "-r", "--name-only", ref, "--", line):
        match = NAME.match(Path(name).name)
        if match:
            found.add(int(match.group(1)))
    return found


def line_of(path: str) -> str | None:
    return next((line for line in LINES if path.startswith(line + "/")), None)


def file_failures(root: Path) -> list[str]:
    failures = []
    for line in LINES:
        for file in sorted((root / line).glob("*.sql")):
            text = file.read_text()
            if not NAME.match(file.name):
                failures.append(f"{line}/{file.name}: malformed migration filename")
            elif not text.split("--", 1)[0].strip() and not SQL.search(text):
                failures.append(f"{line}/{file.name}: migration has no substantive SQL")
    return failures


def change_failures(root: Path, base: str) -> list[str]:
    failures = []
    changed = git(root, "diff", "--name-status", "-M", f"{base}...HEAD", "--", *LINES)
    for entry in changed:
        status, *paths = entry.split("\t")
        if status.startswith("R") and tuple(paths) == REPAIRED_OSV_RENAME:
            if 7 in versions(root, base, LINES[0]):
                failures.append(f"{paths[-1]}: version V7 already exists in the base branch")
            continue
        if status == "D" and paths[0] in RETIRED_COLLISIONS:
            continue
        if status.startswith(("M", "D", "R")) and VERSIONED.match(Path(paths[0]).name):
            kind = {"M": "edited", "D": "deleted", "R": "renamed"}[status[0]]
            failures.append(f"{paths[0]}: applied migration {kind}; add a new version instead")
        if status.startswith(("A", "R", "C")):
            added = paths[-1]
            match = NAME.match(Path(added).name)
            line = line_of(added)
            if match and line and int(match.group(1)) in versions(root, base, line):
                failures.append(f"{added}: version V{match.group(1)} already exists in the base branch")
    return failures


def check(root: Path, base: str | None) -> list[str]:
    failures = file_failures(root)
    if base:
        failures += change_failures(root, base)
    return failures


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--base", default=os.environ.get("MIGRATION_BASE_SHA") or None,
                        help="base revision for change checks (default: $MIGRATION_BASE_SHA; omitted on pushes)")
    args = parser.parse_args()
    failures = check(Path(__file__).resolve().parents[2], args.base)
    if failures:
        print("Migration check failed:", file=sys.stderr)
        print("\n".join(f"  - {failure}" for failure in failures), file=sys.stderr)
        return 1
    print("Migration check passed." + ("" if args.base else " (no base revision: file checks only)"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
