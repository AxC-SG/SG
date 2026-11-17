"""Choose the main commit and Quality run that the AWS publisher may publish.

Both paths need a Quality push run on main whose `Quality gate` job succeeded.
That gate covers every required result for the run's commit, including the
image scan and main performance, and the run holds the image archive.

- Called (the main Quality run's publish job, lab only): the run is the current
  one. Publishes unless the commit is no longer the head of main or the lab
  already has it, in which case it skips without failing.
- Manual (workflow_dispatch): names a Quality run, possibly for an older commit
  or for production, and fails unless that run's gate passed.

Writes publish, target, source_sha and candidate_run to GITHUB_OUTPUT.
"""
import json
import os
import re
import subprocess
import sys
import importlib.util
from pathlib import Path

spec = importlib.util.spec_from_file_location("publication_provenance", Path(__file__).with_name("publication_provenance.py"))
provenance = importlib.util.module_from_spec(spec)
spec.loader.exec_module(provenance)

QUALITY = provenance.QUALITY
GATE_JOB = provenance.GATE_JOB
AUTOMATIC_TARGET = "lab"


class Skip(Exception):
    pass


class Rejected(Exception):
    pass


def publication_name(target, sha):
    return f"aws-publication-{target}-{sha}"


def quality_run(api, repo, run_id, expected_sha=None):
    try:
        return provenance.quality_run(api, repo, run_id, expected_sha)
    except ValueError as error:
        raise Rejected(str(error)) from error


def manual(api, repo, target, candidate_run):
    run = quality_run(api, repo, candidate_run)
    return {"target": target, "source_sha": run["head_sha"], "candidate_run": candidate_run}


def called(api, repo, target, run_id, sha):
    if target != AUTOMATIC_TARGET:
        raise Rejected(f"automatic publication targets {AUTOMATIC_TARGET} only")
    quality_run(api, repo, run_id, expected_sha=sha)
    head = api(f"repos/{repo}/commits/main")["sha"]
    if head != sha:
        raise Skip(f"{sha} is superseded by {head}")
    artifacts = api(f"repos/{repo}/actions/artifacts",
                    {"name": publication_name(target, sha), "per_page": "100"})["artifacts"]
    if provenance.trusted_artifacts(api, repo, artifacts, sha):
        raise Skip(f"{sha} is already published to {target}")
    return {"target": target, "source_sha": sha, "candidate_run": run_id}


def select(api, repo, event_name, target, candidate_run=None, sha=None):
    if event_name == "workflow_dispatch":
        result = manual(api, repo, target, candidate_run)
    elif event_name == "push":
        result = called(api, repo, target, candidate_run, sha)
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
    target = os.environ.get("TARGET") or AUTOMATIC_TARGET
    if target not in ("lab", "production"):
        raise Rejected(f"unknown target {target}")
    # A called run publishes its own run's archive; a manual run names one.
    if event_name == "push":
        candidate_run, sha = os.environ["GITHUB_RUN_ID"], os.environ["GITHUB_SHA"]
    else:
        candidate_run, sha = os.environ.get("CANDIDATE_RUN"), None
    outputs = {"publish": "false", "target": target, "source_sha": "", "candidate_run": ""}
    try:
        outputs.update(select(gh_api, os.environ["GITHUB_REPOSITORY"], event_name, target, candidate_run, sha))
        outputs["publish"] = "true"
        print(f"Publishing {outputs['source_sha']} from Quality run {outputs['candidate_run']} to {target}.")
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
