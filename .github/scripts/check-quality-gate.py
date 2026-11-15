#!/usr/bin/env python3
"""Every expected result must pass. A job may skip only when selection says its
component is not applicable, or, for a main-only job, on a pull request."""
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
# security: Trivy filesystem and the ECS image build, inspection and scan.
ALWAYS_JOBS = {"changes", "static", "secrets", "security", "semgrep"}
# Run on main pushes and must succeed there; pull requests skip them.
MAIN_ONLY_JOBS = {"performance"}
EVENTS = ("pull_request", "push")
SELECTION_OUTPUTS = sorted(set(SELECTED_JOBS.values()))


def failures(needs, event):
    errors = []
    if event not in EVENTS:
        errors.append(f"unexpected event {event}")
    outputs = needs.get("changes", {}).get("outputs", {})
    for output in SELECTION_OUTPUTS:
        if outputs.get(output) not in ("true", "false"):
            errors.append(f"change selection output {output} is missing or invalid")
    for name in sorted(ALWAYS_JOBS | set(SELECTED_JOBS) | MAIN_ONLY_JOBS):
        result = needs.get(name, {}).get("result")
        if name in MAIN_ONLY_JOBS:
            allowed = {"skipped"} if event == "pull_request" else {"success"}
        elif name in SELECTED_JOBS and outputs.get(SELECTED_JOBS[name]) == "false":
            allowed = {"success", "skipped"}
        else:
            allowed = {"success"}
        if result not in allowed:
            errors.append(f"{name}: {result or 'missing'}")
    return errors


if __name__ == "__main__":
    errors = failures(json.loads(os.environ["NEEDS_JSON"]), os.environ.get("EVENT_NAME"))
    print("Quality gate passed" if not errors else "Quality gate failed: " + "; ".join(errors))
    sys.exit(bool(errors))
