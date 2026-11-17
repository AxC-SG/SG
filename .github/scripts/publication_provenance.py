"""Authenticate publication producers independently of artifact names and contents."""
import re

QUALITY = "quality.yml"
QUALITY_PATH = f".github/workflows/{QUALITY}"
GATE_JOB = "Quality gate"


def quality_run(api, repo, run_id, expected_sha=None):
    """One candidate contract for the publisher and every publication consumer."""
    if not isinstance(run_id, str) or not re.fullmatch(r"[0-9]+", run_id):
        raise ValueError("candidate_run must be a workflow run ID")
    quality_id = api(f"repos/{repo}/actions/workflows/{QUALITY}")["id"]
    run = api(f"repos/{repo}/actions/runs/{run_id}")
    if not (run.get("workflow_id") == quality_id and run.get("path") == QUALITY_PATH
            and run.get("head_repository", {}).get("full_name") == repo
            and run.get("head_branch") == "main" and run.get("event") == "push"):
        raise ValueError(f"run {run_id} is not a Quality push run on main")
    if expected_sha is not None and run.get("head_sha") != expected_sha:
        raise ValueError(f"run {run_id} is for {run.get('head_sha')}, not {expected_sha}")
    jobs = api(f"repos/{repo}/actions/runs/{run_id}/jobs", {"filter": "latest", "per_page": "100"})["jobs"]
    gates = [job for job in jobs if job.get("name") == GATE_JOB]
    if len(gates) != 1 or gates[0].get("conclusion") != "success":
        raise ValueError(f"the {GATE_JOB} has not passed in run {run_id}")
    return run


def trusted_artifacts(api, repo, artifacts, sha):
    trusted = []
    for artifact in artifacts:
        if artifact.get('expired') or not artifact.get('id'):
            continue
        run_id = artifact.get('workflow_run', {}).get('id')
        if not run_id:
            continue
        run = api(f'repos/{repo}/actions/runs/{run_id}')
        if run.get('head_repository', {}).get('full_name') != repo or run.get('head_branch') != 'main':
            continue
        path = run.get('path', '').split('@')[0]
        if path == QUALITY_PATH and run.get('event') == 'push' and run.get('head_sha') == sha:
            name = 'publish / Publish verified candidate to ECR'
        elif path == '.github/workflows/aws-publish-candidate.yml' and run.get('event') == 'workflow_dispatch':
            name = 'Publish verified candidate to ECR'
        else:
            continue
        jobs = api(f'repos/{repo}/actions/runs/{run_id}/jobs', {'filter': 'latest', 'per_page': '100'})['jobs']
        matches = [job for job in jobs if job.get('name') == name]
        if len(matches) == 1 and matches[0].get('conclusion') == 'success':
            trusted.append(artifact)
    return sorted(trusted, key=lambda item: item['created_at'])


def validate_candidate(api, repo, record, sha):
    return quality_run(api, repo, str(record.get("candidate_run", "")), expected_sha=sha)
