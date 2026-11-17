"""Pure release qualification and recovery checks. No cloud calls."""
import datetime
import json
import re

from .errors import ReleaseError
from .settings import (DIGEST, REGION, REGISTRY, ECR_REPOSITORY, PHASES, PROGRESS_LINE, FINGERPRINT, SCHEMA_LINE, DEPLOYMENT_ID)


def utc_now():
    return datetime.datetime.now(datetime.timezone.utc)


def stamp(moment=None):
    return (moment or utc_now()).strftime("%Y-%m-%dT%H:%M:%SZ")


def release_id(sha, moment):
    # Lower case so it also forms a valid RDS snapshot identifier.
    return moment.strftime("%Y%m%dt%H%M%Sz") + "-" + sha[:7]


def short(digest):
    return digest.split(":", 1)[1][:12] if digest else "-"


def heads_valid(heads):
    return (isinstance(heads, dict) and set(heads) == {"platform", "tenant"} and
            all(isinstance(value, int) and not isinstance(value, bool) and value > 0 for value in heads.values()))


def schema_mode(database, candidate):
    """neutral: same schema, rolling release. forward: the migrator moves the schema ahead."""
    if not heads_valid(database) or not heads_valid(candidate):
        raise ReleaseError(f"migration heads must be positive platform and tenant versions: {database} {candidate}")
    if any(candidate[key] < database[key] for key in database):
        raise ReleaseError(f"candidate schema {candidate} is behind the database {database}; migrations only move forward")
    return "neutral" if candidate == database else "forward"


def check_plan(plan, phase):
    allowed = PHASES[phase]
    changes, refused = [], []
    for change in plan.get("resource_changes", []):
        actions = tuple(change["change"]["actions"])
        if actions in {("no-op",), ("read",)}:
            continue
        line = f"{'+'.join(actions):>14}  {change['address']}"
        changes.append(line)
        if actions not in allowed.get(change["address"], set()):
            refused.append(line)
    return changes, refused


def check_publication(record, sha):
    digest = record.get("image_digest", "")
    problems = []
    if record.get("source_sha") != sha:
        problems.append(f"source {record.get('source_sha')} is not {sha}")
    if record.get("target") != "lab" or record.get("aws_region") != REGION:
        problems.append(f"published to {record.get('target')} in {record.get('aws_region')}, not lab in {REGION}")
    if not DIGEST.fullmatch(digest):
        problems.append("image is not pinned by digest")
    if record.get("ecr_image") != f"{REGISTRY}/{ECR_REPOSITORY}@{digest}":
        problems.append(f"image {record.get('ecr_image')} is not in {REGISTRY}/{ECR_REPOSITORY}")
    if not heads_valid(record.get("migration_heads")):
        problems.append("migration heads are missing")
    if problems:
        raise ReleaseError("publication record rejected: " + "; ".join(problems))


def migrator_outcome(task):
    """None while running; otherwise (succeeded, detail)."""
    if task.get("lastStatus") != "STOPPED":
        return None
    container = task["containers"][0]
    succeeded = container.get("exitCode") == 0 and task.get("stopCode") == "EssentialContainerExited"
    return succeeded, f"exit {container.get('exitCode')}, {task.get('stopCode')}: {task.get('stoppedReason', '')}".strip()


def service_settled(service, task_definition):
    deployments = service.get("deployments", [])
    return (len(deployments) == 1 and deployments[0]["taskDefinition"] == task_definition and
            deployments[0].get("rolloutState") == "COMPLETED" and
            service["desiredCount"] >= 1 and service["runningCount"] == service["desiredCount"])


def task_definition_arns(state):
    """Current task-definition ARNs from `terraform show -json` state. Root outputs are not
    recomputed by a targeted apply, so they still name the revision a replacement retired."""
    arns = {}
    for resource in state.get("values", {}).get("root_module", {}).get("resources", []):
        if resource.get("type") == "aws_ecs_task_definition" and resource.get("name") == "backend":
            arns[resource["index"]] = resource["values"]["arn"]
    return arns


def progress_check(messages, required=True):
    """Worker progress over the bake: at least one cycle with succeeding tenant work, none where all failed."""
    outcomes = [match.group(1) for match in map(PROGRESS_LINE.search, messages) if match]
    counts = {outcome: outcomes.count(outcome) for outcome in sorted(set(outcomes))}
    if not outcomes:
        if required:
            return False, "no tenant_work_progress line from the worker"
        return True, "no tenant_work_progress line; the operator recorded that this image predates the signal"
    if "failing" in counts:
        return False, f"a cycle had tenant work failing and none succeeding: {json.dumps(counts)}"
    if not counts.get("healthy") and not counts.get("degraded"):
        return False, f"no cycle with succeeding tenant work: {json.dumps(counts)}"
    return True, json.dumps(counts)


def catalog_check(database, candidate):
    """same / changed / unverified: the packaged migration catalog against the one the database ran."""
    if not (isinstance(database, str) and FINGERPRINT.fullmatch(database)) or \
            not (isinstance(candidate, str) and FINGERPRINT.fullmatch(candidate)):
        return "unverified"
    return "same" if database == candidate else "changed"


def schema_state_check(messages, tenant_head, required=True):
    """The latest worker schema-state line: no unready tenant, and the supported range holds the head.

    Readiness stays UP while tenants are unready, so this is the evidence; the 2026-11-15 V23..V20
    range would fail here before a person found it.
    """
    states = [match for match in map(SCHEMA_LINE.search, messages) if match]
    if not states:
        if any("tenant_schema_state unavailable" in message for message in messages):
            return False, "the worker could not read the tenant schema control plane"
        if required:
            return False, "no tenant_schema_state line from the worker"
        return True, "no tenant_schema_state line; the operator recorded that this image predates the signal"
    unready, low, high, active = states[-1].groups()
    detail = f"unready_tenants={unready} supported=V{low}..V{high} active_versions={active} database tenant head=V{tenant_head}"
    if int(unready) != 0:
        return False, detail
    if not int(low) <= tenant_head <= int(high):
        return False, detail + " (outside the supported range)"
    return True, detail


def smoke_check(result):
    """The signed-in smoke's verdict. Unconfigured does not block a release; its detail records the detection gap."""
    if result is None:
        return True, "not configured (LAB_SMOKE_CONFIG unset): signed-in writes unverified, a recorded detection gap"
    failed = [f"{item.get('name')}: {item.get('detail')}" for item in result.get("checks", []) if not item.get("ok")]
    if result.get("passed") is True and result.get("checks") and not failed:
        return True, f"{len(result['checks'])} checks passed"
    return False, "; ".join(failed)[:600] or "the smoke reported no checks"


def fatal_check(messages):
    if not messages:
        return True, "none"
    return False, f"{len(messages)} line(s), first: {messages[0].strip()[:300]}"


def frontend_id(frontend):
    return (frontend or {}).get("deployment_id")


def live_differs(inputs, entry):
    """Whether the lab runs something other than entry's pair. A frontend counts once release.py tracks one."""
    if entry["runtime_image_digest"] != inputs["runtime_image_digest"]:
        return True
    live = frontend_id(inputs.get("frontend"))
    return bool(inputs.get("frontend_promoting")) or (live is not None and live != frontend_id(entry.get("frontend")))


def rollback_target(inputs):
    """The release to return to: the accepted one while a release is unfinished or the lab has
    left it (failed or rejected), otherwise the accepted release before it."""
    accepted = inputs.get("accepted")
    if accepted and (inputs.get("pending") or live_differs(inputs, accepted)):
        return accepted
    return inputs.get("previous_accepted")


def staged_reference(output):
    """The deployment `vercel deploy --json` created: its dpl_ ID, else its *.vercel.app host."""
    try:
        found = json.loads(output)
    except json.JSONDecodeError:
        found = None
    candidates = [found.get("id"), (found.get("deployment") or {}).get("id")] if isinstance(found, dict) else []
    for candidate in candidates:
        if isinstance(candidate, str) and DEPLOYMENT_ID.fullmatch(candidate):
            return candidate
    match = DEPLOYMENT_ID.search(output) or re.search(r"[a-z0-9-]+\.vercel\.app", output)
    if not match:
        raise ReleaseError(f"vercel deploy reported no deployment: {output.strip()[-300:]}")
    return match.group(0)
