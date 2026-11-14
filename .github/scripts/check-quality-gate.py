#!/usr/bin/env python3
"""Required jobs may only skip when selection explicitly says their component is not applicable."""
import json
import os
import sys

# Job -> the change-selection output that decides whether it must run.
SELECTED_JOBS = {
    "frontend": "frontend",
    "frontend-e2e": "frontend",
    "backend": "backend",
    "backend-postgres": "backend",
    "terraform": "infrastructure",
}
ALWAYS_JOBS = {"changes", "static", "secrets"}
SELECTION_OUTPUTS = sorted(set(SELECTED_JOBS.values()))


def failures(needs):
    errors = []
    outputs = needs.get("changes", {}).get("outputs", {})
    for output in SELECTION_OUTPUTS:
        if outputs.get(output) not in ("true", "false"):
            errors.append(f"change selection output {output} is missing or invalid")
    for name in sorted(ALWAYS_JOBS | set(SELECTED_JOBS)):
        result = needs.get(name, {}).get("result")
        skippable = name in SELECTED_JOBS and outputs.get(SELECTED_JOBS[name]) == "false"
        allowed = {"success", "skipped"} if skippable else {"success"}
        if result not in allowed:
            errors.append(f"{name}: {result or 'missing'}")
    return errors


if __name__ == "__main__":
    errors = failures(json.loads(os.environ["NEEDS_JSON"]))
    print("Quality gate passed" if not errors else "Quality gate failed: " + "; ".join(errors))
    sys.exit(bool(errors))
