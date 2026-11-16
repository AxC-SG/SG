"""Authenticate publication producers independently of artifact names and contents."""

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
        if path == '.github/workflows/quality.yml' and run.get('event') == 'push' and run.get('head_sha') == sha:
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
    run_id = str(record.get('candidate_run', ''))
    if not run_id.isdigit():
        raise ValueError('publication candidate_run is missing or invalid')
    run = api(f'repos/{repo}/actions/runs/{run_id}')
    if not (run.get('path') == '.github/workflows/quality.yml' and run.get('event') == 'push'
            and run.get('head_branch') == 'main' and run.get('head_sha') == sha
            and run.get('head_repository', {}).get('full_name') == repo):
        raise ValueError('publication does not identify a Quality push for the candidate')
    jobs = api(f'repos/{repo}/actions/runs/{run_id}/jobs', {'filter': 'latest', 'per_page': '100'})['jobs']
    gates = [job for job in jobs if job.get('name') == 'Quality gate']
    if len(gates) != 1 or gates[0].get('conclusion') != 'success':
        raise ValueError('publication candidate Quality gate did not succeed')
