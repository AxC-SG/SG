#!/usr/bin/env python3
"""Required jobs may only skip when selection explicitly says not applicable."""
import json
import os
import sys

APPLICATION_JOBS = {"frontend", "frontend-e2e", "backend", "backend-postgres"}
ALWAYS_JOBS = {"changes", "migration-validation", "migration-boundaries", "policy-packages", "secrets", "ci-contracts"}


def failures(needs):
    errors = []
    application = needs.get("changes", {}).get("outputs", {}).get("application")
    if application not in ("true", "false"):
        errors.append("change selection is missing or invalid")
    for name in ALWAYS_JOBS | APPLICATION_JOBS:
        result = needs.get(name, {}).get("result")
        allowed = {"success", "skipped"} if name in APPLICATION_JOBS and application == "false" else {"success"}
        if result not in allowed:
            errors.append(f"{name}: {result or 'missing'}")
    return errors


if __name__ == "__main__":
    errors = failures(json.loads(os.environ["NEEDS_JSON"]))
    print("Quality gate passed" if not errors else "Quality gate failed: " + "; ".join(errors))
    sys.exit(bool(errors))
