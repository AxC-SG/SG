"""Choose the main commit and Trivy run that the AWS publisher may publish.

A manual run names a Trivy run and fails unless every required check passed
for that run's commit. An automatic run (workflow_run, lab only) publishes once
all four required checks have passed for the commit, the commit is still the
head of main, and the lab has not already published it. Otherwise it skips
without failing, because another check's completion triggers it again.

Writes publish, target, source_sha and candidate_run to GITHUB_OUTPUT.
"""
import json
import os
import re
import subprocess
import sys

CHECKS = ("quality.yml", "semgrep.yml", "performance-governance.yml")
TRIVY = "trivy.yml"
AUTOMATIC_TARGET = "lab"


class Skip(Exception):
    pass


class Rejected(Exception):
    pass


def publication_name(target, sha):
    return f"aws-publication-{target}-{sha}"


def latest_push_run(api, repo, workflow, sha):
    runs = api(f"repos/{repo}/actions/workflows/{workflow}/runs",
               {"branch": "main", "event": "push", "head_sha": sha, "per_page": "1"})["workflow_runs"]
    if not runs:
        return None
    run = runs[0]
    if run["head_sha"] != sha or run["head_repository"]["full_name"] != repo:
        return None
    return run


def manual(api, repo, target, candidate_run):
    if not re.fullmatch(r"[0-9]+", candidate_run or ""):
        raise Rejected("candidate_run must be a workflow run ID")
    trivy_id = api(f"repos/{repo}/actions/workflows/{TRIVY}")["id"]
    run = api(f"repos/{repo}/actions/runs/{candidate_run}")
    if not (run["workflow_id"] == trivy_id and run["head_repository"]["full_name"] == repo
            and run["head_branch"] == "main" and run["event"] == "push" and run["conclusion"] == "success"):
        raise Rejected(f"run {candidate_run} is not a successful Trivy push run on main")
    sha = run["head_sha"]
    for workflow in CHECKS:
        check = latest_push_run(api, repo, workflow, sha)
        if check is None or check["conclusion"] != "success":
            raise Rejected(f"{workflow} has not passed for {sha}")
    return {"target": target, "source_sha": sha, "candidate_run": candidate_run}


def automatic(api, repo, target, trigger):
    if target != AUTOMATIC_TARGET:
        raise Rejected(f"automatic publication targets {AUTOMATIC_TARGET} only")
    if not (trigger["event"] == "push" and trigger["head_branch"] == "main"
            and trigger["head_repository"]["full_name"] == repo):
        raise Skip("the triggering run is not a push to main in this repository")
    sha = trigger["head_sha"]
    trivy = None
    for workflow in CHECKS + (TRIVY,):
        run = latest_push_run(api, repo, workflow, sha)
        if run is None or run["status"] != "completed":
            raise Skip(f"waiting for {workflow} on {sha}")
        if run["conclusion"] != "success":
            raise Skip(f"{workflow} concluded {run['conclusion']} on {sha}")
        if workflow == TRIVY:
            trivy = run
    head = api(f"repos/{repo}/commits/main")["sha"]
    if head != sha:
        raise Skip(f"{sha} is superseded by {head}")
    artifacts = api(f"repos/{repo}/actions/artifacts",
                    {"name": publication_name(target, sha), "per_page": "100"})["artifacts"]
    if any(not artifact["expired"] for artifact in artifacts):
        raise Skip(f"{sha} is already published to {target}")
    return {"target": target, "source_sha": sha, "candidate_run": str(trivy["id"])}


def select(api, repo, event_name, target, candidate_run=None, trigger=None):
    if event_name == "workflow_dispatch":
        result = manual(api, repo, target, candidate_run)
    elif event_name == "workflow_run":
        result = automatic(api, repo, target, trigger)
    else:
        raise Rejected(f"unsupported event {event_name}")
    if not re.fullmatch(r"[a-f0-9]{40}", result["source_sha"]):
        raise Rejected("source commit is not a full SHA")
    return result


def gh_api(path, params=None):
    command = ["gh", "api", "--method", "GET", path]
    for key, value in (params or {}).items():
        command += ["-f", f"{key}={value}"]
    return json.loads(subprocess.run(command, check=True, capture_output=True, text=True).stdout)


def main():
    event_name = os.environ["GITHUB_EVENT_NAME"]
    with open(os.environ["GITHUB_EVENT_PATH"], encoding="utf-8") as handle:
        event = json.load(handle)
    target = os.environ.get("TARGET") or AUTOMATIC_TARGET
    if target not in ("lab", "production"):
        raise Rejected(f"unknown target {target}")
    outputs = {"publish": "false", "target": target, "source_sha": "", "candidate_run": ""}
    try:
        outputs.update(select(gh_api, os.environ["GITHUB_REPOSITORY"], event_name, target,
                              os.environ.get("CANDIDATE_RUN"), event.get("workflow_run")))
        outputs["publish"] = "true"
        print(f"Publishing {outputs['source_sha']} from Trivy run {outputs['candidate_run']} to {target}.")
    except Skip as skip:
        print(f"::notice title=Not published::{skip}")
    with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as handle:
        for key, value in outputs.items():
            handle.write(f"{key}={value}\n")


if __name__ == "__main__":
    try:
        main()
    except Rejected as rejected:
        print(f"::error::{rejected}")
        sys.exit(1)
