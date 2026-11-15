#!/usr/bin/env python3
"""Lab backend release: move the Sydney lab to a published main commit, one checked step at a time.

  release.py status                      release inputs, lock, running images and the last release
  release.py init SHA PLATFORM TENANT    seed the release inputs from what the lab runs now (once)
  release.py deploy SHA [--no-progress-signal]
                                         release a published main commit to the lab
  release.py rollback [--no-progress-signal]
                                         return api and worker to the last accepted release, or the one before it
                                         (--no-progress-signal: the image predates the worker progress line, so its
                                         absence is recorded instead of failing the release)
  release.py check SHA                   read-only: would SHA be a proven schema-neutral, runtime-only release?
                                         (catalog fingerprint, live schema state, migrator drift; changes nothing)
  release.py accept [--answers yn… [--note TEXT]]
                                         record the browser checks for the live release (interactive, or
                                         answers the operator relayed, one y/n per check in order)
  release.py unlock                      remove a stale lock after showing its holder

A deploy, recorded step by step in s3://<state bucket>/standard/lab/release/records/<id>.json:
  1. qualify    the lab publication record for SHA, its ECR image, its schema heads and migration catalog
                fingerprint against the database, and the worker's live schema state
  2. stop       schema-changing releases only: stop api and worker, then snapshot RDS
  3. migrator   Terraform registers the candidate migrator task definition, and nothing else
  4. migrate    run the candidate migrator once; it must exit 0
  5. runtime    Terraform moves api and worker to the candidate, and nothing else
  6. verify     services settled, healthy targets, public 200 and protected 401, then a bake of one
                scheduler cycle: no defined failure in the api or worker log, and worker progress
                reported with no cycle where every tenant job failed, and the worker's schema state shows no
                unready tenant and a supported range that contains the database's tenant head
  7. accept     later, `release.py accept` records the browser checks; all passing makes it the
                accepted release, any failure rejects it (then roll back or deploy a fix)

Terraform renders images only from the release inputs object, which lab.sh reads too, and
lab.sh and this script share one lock, so a lab cycle never runs mid-release. A step that
fails leaves `pending` set: lab.sh then refuses, rerunning `deploy` for the same commit
resumes (every step is idempotent), and `rollback` recovers where the schema allows.

Environment: LAB_RELEASE_PROFILE (default sglab-release), TERRAFORM (Terraform 1.13.5).
Credentials go only to child processes and are never printed.
"""
import datetime
import json
import os
import re
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

ACCOUNT_ID = "736486260824"
REGION = "ap-southeast-2"
CLUSTER = "scoutgrid-lab"
SERVICES = ("api", "worker")
DB_ID = "scoutgrid-lab"
TARGET_GROUP = "scoutgrid-lab-api"
API_ORIGIN = "https://api-lab.scoutgrid.io"
ECR_REPOSITORY = "scoutgrid-lab-backend"
REGISTRY = f"{ACCOUNT_ID}.dkr.ecr.{REGION}.amazonaws.com"
REPO = "AxC-SG/SG"
STATE_BUCKET = f"scoutgrid-lab-tfstate-{ACCOUNT_ID}-{REGION}"
STATE_KMS_KEY = f"arn:aws:kms:{REGION}:{ACCOUNT_ID}:key/2731031f-d79e-4db9-afe6-94fb01cba15a"
PREFIX = "standard/lab/release"
INPUTS_KEY = f"{PREFIX}/inputs.json"
LOCK_KEY = f"{PREFIX}/lock.json"
RECORDS = f"{PREFIX}/records"
TF_REQUIRED = "1.13.5"
DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
FULL_SHA = re.compile(r"[0-9a-f]{40}")
# One five-minute scheduler cycle plus a minute of jitter, counted from when the services settle.
BAKE_SECONDS = 360
# The defined failures; keep in step with release_fatal_pattern in terraform/standard/release-alarms.tf.
FATAL_PATTERNS = (
    "outside this release's supported range",
    "violates row-level security policy",
    "Tenant-scoped background work failed",
    "Unhandled API error",
)
FATAL_FILTER = " ".join(f'?"{pattern}"' for pattern in FATAL_PATTERNS)
PROGRESS_FILTER = '"tenant_work_progress"'
PROGRESS_LINE = re.compile(r"tenant_work_progress outcome=(\w+) succeeded=(\d+) failed=(\d+)")
SCHEMA_FILTER = '"tenant_schema_state"'
SCHEMA_LINE = re.compile(r"tenant_schema_state unready_tenants=(\d+) supported=(\d+)\.\.(\d+) active_versions=(\S+)")
SCHEMA_LOOKBACK = datetime.timedelta(minutes=10)
FINGERPRINT = re.compile(r"[0-9a-f]{64}")

LAB_DIR = Path(__file__).resolve().parents[1]
CFG = LAB_DIR / "config"
TF_ROOT = (LAB_DIR / ".." / "terraform" / "standard").resolve()
BROWSER_CHECKS = CFG / "release-browser-checks.json"

TASK = 'aws_ecs_task_definition.backend["{}"]'
SERVICE = 'aws_ecs_service.backend["{}"]'
REPLACE = {("create",), ("delete", "create"), ("create", "delete")}
# Exactly what each Terraform step may change; anything else stops the release.
PHASES = {
    "migrator": {TASK.format("migrator"): REPLACE},
    "runtime": {**{TASK.format(role): REPLACE for role in SERVICES},
                **{SERVICE.format(role): {("update",)} for role in SERVICES}},
}
TARGETS = {
    "migrator": [TASK.format("migrator")],
    "runtime": [TASK.format(role) for role in SERVICES] + [SERVICE.format(role) for role in SERVICES],
}


class ReleaseError(Exception):
    pass


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


def fatal_check(messages):
    if not messages:
        return True, "none"
    return False, f"{len(messages)} line(s), first: {messages[0].strip()[:300]}"


def rollback_target(inputs):
    """The release to return to: the accepted one while a release is unfinished or the lab has
    left it (failed or rejected), otherwise the accepted release before it."""
    accepted = inputs.get("accepted")
    if accepted and (inputs.get("pending") or accepted["runtime_image_digest"] != inputs["runtime_image_digest"]):
        return accepted
    return inputs.get("previous_accepted")


class Release:
    def __init__(self, lab):
        self.lab = lab

    # ---- shared state -------------------------------------------------------------------
    def locked(self, operation):
        release = self

        class Lock:
            def __enter__(self):
                holder = {"holder": "release.py", "operation": operation, "started_at": stamp()}
                if not release.lab.s3_put(LOCK_KEY, holder, create_only=True):
                    raise ReleaseError(f"the lab is locked: {release.lab.s3_get(LOCK_KEY)}; "
                                       "wait for it, or clear a stale lock with release.py unlock")

            def __exit__(self, *_):
                release.lab.s3_delete(LOCK_KEY)
                return False

        return Lock()

    def inputs(self):
        inputs = self.lab.s3_get(INPUTS_KEY)
        if not inputs:
            raise ReleaseError("no release inputs yet; seed them with release.py init")
        return inputs

    def save(self, inputs, record):
        inputs["updated_at"] = stamp()
        inputs["last_release"] = {key: record[key] for key in ("release_id", "kind", "status")}
        self.lab.s3_put(f"{RECORDS}/{record['release_id']}.json", record)
        self.lab.s3_put(INPUTS_KEY, inputs)

    def mark(self, inputs, record, step, **detail):
        record["steps"].append({"step": step, "at": stamp(), **detail})
        inputs["pending"] = {"release_id": record["release_id"], "source_sha": record["candidate"]["source_sha"],
                             "kind": record["kind"], "phase": step}
        self.save(inputs, record)
        self.lab.log(f"{step}: done {json.dumps(detail) if detail else ''}".rstrip())

    @staticmethod
    def done(record, step):
        return any(item["step"] == step for item in record["steps"])

    # ---- commands -----------------------------------------------------------------------
    def status(self):
        inputs = self.lab.s3_get(INPUTS_KEY)
        lock = self.lab.s3_get(LOCK_KEY)
        live = self.lab.live_images()
        print(f"lock:      {json.dumps(lock) if lock else 'free'}")
        if not inputs:
            print("inputs:    none (run release.py init)")
        else:
            accepted = inputs.get("accepted") or {}
            print(f"runtime:   {short(inputs['runtime_image_digest'])} from {inputs['runtime']['source_sha'][:7]}")
            print(f"migrator:  {short(inputs['migrator_image_digest'])} from {inputs['migrator']['source_sha'][:7]}")
            print(f"database:  platform V{inputs['database_heads']['platform']}, tenant V{inputs['database_heads']['tenant']}")
            print(f"accepted:  {accepted.get('release_id', '-')} ({short(accepted.get('runtime_image_digest'))})")
            print(f"last:      {json.dumps(inputs.get('last_release'))}")
            print(f"pending:   {json.dumps(inputs.get('pending'))}")
            waiting = inputs.get("awaiting_acceptance")
            print(f"awaiting:  {waiting['release_id'] + ' (run release.py accept)' if waiting else '-'}")
            for role, digest in live.items():
                expected = inputs["migrator_image_digest" if role == "migrator" else "runtime_image_digest"]
                print(f"live {role:<9}{short(digest)}{'' if digest in (None, expected) else '  DIFFERS FROM INPUTS'}")

    def init(self, sha, platform, tenant):
        if not FULL_SHA.fullmatch(sha):
            raise ReleaseError("give the full 40-character commit the running image was built from")
        heads = {"platform": platform, "tenant": tenant}
        if not heads_valid(heads):
            raise ReleaseError("give positive platform and tenant schema versions")
        with self.locked("init"):
            if self.lab.s3_get(INPUTS_KEY):
                raise ReleaseError("release inputs already exist; nothing changed")
            live = self.lab.live_images()
            if None in live.values() or len(set(live.values())) != 1:
                raise ReleaseError(f"api, worker and migrator must run one image to seed from: {live}")
            digest = live["api"]
            meta = {"source_sha": sha, "migration_heads": heads}
            accepted = {"release_id": "baseline-" + utc_now().strftime("%Y%m%d"), "runtime_image_digest": digest, **meta}
            inputs = {"schema": 1, "runtime_image_digest": digest, "migrator_image_digest": digest,
                      "runtime": meta, "migrator": meta, "database_heads": heads, "accepted": accepted,
                      "previous_accepted": None, "pending": None, "awaiting_acceptance": None, "last_release": None,
                      "updated_at": stamp()}
            if not self.lab.s3_put(INPUTS_KEY, inputs, create_only=True):
                raise ReleaseError("release inputs appeared meanwhile; nothing changed")
            self.lab.log(f"Seeded release inputs: {short(digest)} from {sha[:7]}, platform V{platform}, tenant V{tenant}.")

    def deploy(self, ref, progress_required=True):
        sha = self.lab.resolve_sha(ref)
        with self.locked("deploy " + sha[:7]):
            inputs = self.inputs()
            pending = inputs.get("pending")
            if pending and (pending["kind"] != "deploy" or pending["source_sha"] != sha):
                raise ReleaseError(f"{pending['kind']} {pending['release_id']} stopped after {pending['phase']}; "
                                   f"rerun it, or run release.py rollback")
            if inputs.get("awaiting_acceptance"):
                raise ReleaseError(f"{inputs['awaiting_acceptance']['release_id']} is waiting for its browser checks; "
                                   "run release.py accept, or release.py rollback")
            publication = self.lab.publication(sha)
            check_publication(publication, sha)
            digest, heads = publication["image_digest"], publication["migration_heads"]
            fingerprint = publication.get("migration_catalog_sha256")
            if not self.lab.ecr_has(digest):
                raise ReleaseError(f"{digest} is not in the lab ECR repository")
            if not self.lab.services_present():
                raise ReleaseError("the lab is parked; run lab.sh up first (publication does not need it)")
            record = self.lab.s3_get(f"{RECORDS}/{pending['release_id']}.json") if pending else None
            if record:
                mode = record["mode"]
            else:
                mode = schema_mode(inputs["database_heads"], heads)
                record = {"release_id": release_id(sha, utc_now()), "kind": "deploy", "status": "started", "mode": mode,
                          "candidate": {"source_sha": sha, "image_digest": digest, "migration_heads": heads,
                                        "migration_catalog_sha256": fingerprint,
                                        "publication_run": publication.get("candidate_run")},
                          "from": {key: inputs[key] for key in ("runtime_image_digest", "migrator_image_digest", "database_heads")},
                          "steps": [], "checks": {}, "browser_checks": [], "started_at": stamp()}
            if not pending:
                self.qualify_schema(inputs, record, fingerprint)
            self.lab.log(f"Release {record['release_id']}: {short(inputs['runtime_image_digest'])} -> {short(digest)} "
                         f"({sha[:7]}), schema {mode}: {inputs['database_heads']} -> {heads}"
                         f"{' (resuming)' if pending else ''}.")
            if mode == "forward":
                self.lab.log("Schema-changing release: api and worker stop, RDS is snapshotted, the migrator runs, "
                             "then the candidate starts. Sign-in and the API are offline meanwhile (about 5-10 minutes). "
                             "The previous image cannot run on the new schema; recovery is the snapshot.")
            if not self.lab.confirm(f"Release {sha[:7]} to the lab?"):
                raise ReleaseError("not confirmed; nothing changed")
            meta = {"source_sha": sha, "migration_heads": heads, "migration_catalog_sha256": fingerprint}
            self.run(inputs, record, runtime=digest, migrator=digest, meta=meta, stop=(mode == "forward"),
                     progress_required=progress_required)

    def qualify_schema(self, inputs, record, fingerprint):
        """Refuse before any change when the catalog or the live schema state contradicts the heads."""
        catalog = catalog_check(inputs.get("database_catalog_sha256"), fingerprint)
        record["catalog"] = catalog
        if record["mode"] == "neutral" and catalog == "changed":
            raise ReleaseError("the migration heads are equal but the migration catalog differs from the one the "
                               "database ran (an applied migration was changed); nothing changed")
        if catalog == "unverified":
            self.lab.log("The migration catalog cannot be compared (the inputs or the publication predate the "
                         "fingerprint); this release is recorded as schema-unverified.")
        messages = self.lab.log_messages("worker", utc_now() - SCHEMA_LOOKBACK, SCHEMA_FILTER)
        passed, detail = schema_state_check(messages, inputs["database_heads"]["tenant"], required=False)
        record["schema_state_before"] = {"passed": passed, "detail": detail}
        if not passed and record["mode"] == "neutral":
            raise ReleaseError(f"the live tenant schema state is not ready ({detail}); nothing changed")

    def check(self, ref):
        """Read-only eligibility for a runtime-only release (CD plan section 4.3). Changes nothing."""
        sha = self.lab.resolve_sha(ref)
        inputs = self.inputs()
        publication = self.lab.publication(sha)
        check_publication(publication, sha)
        reasons = []
        if inputs.get("pending"):
            reasons.append(f"needs_operator: {inputs['pending']['kind']} {inputs['pending']['release_id']} stopped "
                           f"after {inputs['pending']['phase']}")
        if inputs.get("awaiting_acceptance"):
            reasons.append(f"awaiting_acceptance: {inputs['awaiting_acceptance']['release_id']}")
        if not self.lab.services_present():
            reasons.append("parked: the lab services are not running")
        if publication["migration_heads"] != inputs["database_heads"]:
            reasons.append(f"schema_changed: heads {publication['migration_heads']} against the database "
                           f"{inputs['database_heads']}")
        catalog = catalog_check(inputs.get("database_catalog_sha256"), publication.get("migration_catalog_sha256"))
        if catalog != "same":
            reasons.append(f"schema_{catalog}: migration catalog fingerprint is {catalog}")
        passed, detail = schema_state_check(
            self.lab.log_messages("worker", utc_now() - SCHEMA_LOOKBACK, SCHEMA_FILTER), inputs["database_heads"]["tenant"])
        if not passed:
            reasons.append(f"schema_unverified: {detail}")
        # The runtime-only path keeps the retained migrator. Rendering it from this checkout with that
        # digest must change nothing; any change means its configuration moved, which needs review.
        _, document = self.lab.plan("migrator-drift", {"runtime": inputs["runtime_image_digest"],
                                                        "migrator": inputs["migrator_image_digest"]}, TARGETS["migrator"])
        drift, _ = check_plan(document, "migrator")
        if drift:
            reasons.append("migrator_drift: " + "; ".join(line.strip() for line in drift))
        outcome = "eligible" if not reasons else (
            "needs_operator" if any(reason.startswith("needs_operator") for reason in reasons) else "blocked")
        result = {"source_sha": sha, "outcome": outcome, "reasons": reasons, "schema_state": detail, "catalog": catalog}
        print(json.dumps(result, indent=2))
        return result

    def rollback(self, progress_required=True):
        with self.locked("rollback"):
            inputs = self.inputs()
            target = rollback_target(inputs)
            if not target:
                raise ReleaseError("there is no earlier accepted release to return to")
            if target["migration_heads"] != inputs["database_heads"]:
                snapshots = [step.get("snapshot") for step in self.last_record_steps(inputs) if step.get("snapshot")]
                raise ReleaseError(f"{target['release_id']} needs schema {target['migration_heads']} but the database is at "
                                   f"{inputs['database_heads']}; its image cannot run here. Fix forward with deploy, or "
                                   f"restore the pre-migration snapshot {snapshots or '(none recorded)'} through the reviewed path")
            record = {"release_id": release_id(target["source_sha"], utc_now()), "kind": "rollback", "status": "started",
                      "mode": "neutral", "rolls_back_to": target["release_id"],
                      "candidate": {"source_sha": target["source_sha"], "image_digest": target["runtime_image_digest"],
                                    "migration_heads": target["migration_heads"]},
                      "from": {key: inputs[key] for key in ("runtime_image_digest", "migrator_image_digest", "database_heads")},
                      "steps": [], "checks": {}, "browser_checks": [], "started_at": stamp()}
            self.lab.log(f"Rollback {record['release_id']}: api and worker {short(inputs['runtime_image_digest'])} -> "
                         f"{short(target['runtime_image_digest'])} ({target['release_id']}); the migrator and schema stay.")
            if not self.lab.confirm("Roll back api and worker?"):
                raise ReleaseError("not confirmed; nothing changed")
            self.reject_waiting(inputs, "rolled back before acceptance")
            meta = {"source_sha": target["source_sha"], "migration_heads": target["migration_heads"]}
            self.run(inputs, record, runtime=target["runtime_image_digest"], migrator=None, meta=meta,
                     stop=False, restores=target, progress_required=progress_required)

    def unlock(self):
        lock = self.lab.s3_get(LOCK_KEY)
        if not lock:
            self.lab.log("No lock is held.")
            return
        if not self.lab.confirm(f"Remove the lab lock {json.dumps(lock)}? Only do this if that holder is no longer running."):
            raise ReleaseError("not confirmed; the lock stays")
        self.lab.s3_delete(LOCK_KEY)
        self.lab.log("Lock removed.")

    def last_record_steps(self, inputs):
        last = inputs.get("last_release")
        record = self.lab.s3_get(f"{RECORDS}/{last['release_id']}.json") if last else None
        return record["steps"] if record else []

    # ---- the release itself -----------------------------------------------------------
    def run(self, inputs, record, runtime, migrator, meta, stop, restores=None, progress_required=True):
        step = "start"
        try:
            if stop and not self.done(record, "stopped"):
                step = "stopped"
                self.lab.stop_services()
                self.mark(inputs, record, "stopped")
            if stop and not self.done(record, "snapshot"):
                step = "snapshot"
                snapshot = self.lab.snapshot(f"{CLUSTER}-release-{record['release_id']}", record["release_id"])
                self.mark(inputs, record, "snapshot", snapshot=snapshot)
            if migrator:
                step = "migrator"
                self.terraform("migrator", {"runtime": inputs["runtime_image_digest"], "migrator": migrator})
                inputs["migrator_image_digest"], inputs["migrator"] = migrator, meta
                self.mark(inputs, record, "migrator")
                step = "migrate"
                task = self.lab.run_migrator(self.lab.outputs())
                succeeded, detail = migrator_outcome(self.lab.wait_task(task))
                if not succeeded:
                    raise ReleaseError(f"the migrator failed ({detail}); api and worker were not changed")
                inputs["database_heads"] = meta["migration_heads"]
                inputs["database_catalog_sha256"] = meta.get("migration_catalog_sha256")
                self.mark(inputs, record, "migrated", task=task, detail=detail)
            step = "runtime"
            self.terraform("runtime", {"runtime": runtime, "migrator": inputs["migrator_image_digest"]})
            inputs["runtime_image_digest"], inputs["runtime"] = runtime, meta
            self.mark(inputs, record, "runtime")
            step = "verify"
            record["checks"] = self.verify(record, progress_required)
            failed = [name for name, check in record["checks"].items() if not check["passed"]]
            if failed:
                raise ReleaseError(f"automated checks failed: {', '.join(failed)}")
            self.mark(inputs, record, "verified")
        except BaseException as error:
            record.update(status="failed", failed_at=step, error=str(error) or type(error).__name__, ended_at=stamp())
            self.save(inputs, record)
            raise ReleaseError(f"{record['kind']} {record['release_id']} failed at {step}: {error}. "
                               f"The record is in s3://{STATE_BUCKET}/{RECORDS}/. lab.sh refuses until a deploy of the "
                               f"same commit resumes it or release.py rollback recovers.") from error
        # Terraform and the inputs agree again, so lab cycles may run; acceptance is the operator's.
        record["status"] = "verified"
        inputs["pending"] = None
        inputs["awaiting_acceptance"] = {"release_id": record["release_id"], "kind": record["kind"],
                                         "runtime_image_digest": runtime, **meta, "restores": restores}
        self.save(inputs, record)
        self.lab.log(f"{record['kind'].capitalize()} {record['release_id']} is live and passed the automated checks. "
                     "Run the browser checks, then record them with release.py accept.")

    def accept(self, answers=None, note=""):
        with self.locked("accept"):
            inputs = self.inputs()
            waiting = inputs.get("awaiting_acceptance")
            if not waiting:
                raise ReleaseError("no release is waiting for its browser checks")
            record = self.lab.s3_get(f"{RECORDS}/{waiting['release_id']}.json")
            checks = json.loads(BROWSER_CHECKS.read_text())["checks"]
            if answers is None:
                record["browser_checks"] = self.lab.browser_checks(checks)
            else:
                if not re.fullmatch(r"[yn]+", answers) or len(answers) != len(checks):
                    raise ReleaseError(f"give one y or n per check ({len(checks)}), in order")
                record["browser_checks"] = [{"check": check, "passed": answer == "y", "note": note if answer == "n" else "",
                                             "answered": "relayed by the operator"} for check, answer in zip(checks, answers)]
            self.conclude(inputs, record, waiting)

    def conclude(self, inputs, record, waiting):
        passed = all(check["passed"] for check in record["browser_checks"])
        record.update(status="accepted" if passed else "rejected", ended_at=stamp())
        inputs["awaiting_acceptance"] = None
        restores = waiting.get("restores")
        if passed and restores:
            same = inputs.get("accepted") and inputs["accepted"]["release_id"] == restores["release_id"]
            inputs["previous_accepted"] = inputs["previous_accepted"] if same else None
            inputs["accepted"] = restores
        elif passed:
            meta = {"source_sha": waiting["source_sha"], "migration_heads": waiting["migration_heads"],
                    "migration_catalog_sha256": waiting.get("migration_catalog_sha256")}
            inputs["previous_accepted"] = inputs.get("accepted")
            inputs["accepted"] = {"release_id": record["release_id"], "runtime_image_digest": waiting["runtime_image_digest"], **meta}
        self.save(inputs, record)
        if passed:
            self.lab.log(f"{record['kind'].capitalize()} {record['release_id']} accepted.")
        else:
            self.lab.log(f"{record['kind'].capitalize()} {record['release_id']} rejected by a browser check. The lab runs "
                         "it until you run release.py rollback (or deploy a fix).")

    def reject_waiting(self, inputs, reason):
        """A new deploy or rollback replaces a release nobody accepted: record it as rejected."""
        waiting = inputs.get("awaiting_acceptance")
        if not waiting:
            return
        record = self.lab.s3_get(f"{RECORDS}/{waiting['release_id']}.json")
        record["browser_checks"] = [{"check": reason, "passed": False, "note": ""}]
        self.conclude(inputs, record, waiting)

    def terraform(self, phase, images):
        plan, document = self.lab.plan(phase, images, TARGETS[phase])
        changes, refused = check_plan(document, phase)
        self.lab.log(f"{phase} plan:\n" + ("\n".join(changes) or "  (no changes)"))
        if refused:
            raise ReleaseError(f"the {phase} plan changes resources outside its step:\n" + "\n".join(refused))
        if changes:
            self.lab.apply(plan)

    def verify(self, record, progress_required=True):
        arns = self.lab.outputs()["task_definition_arns"]
        services = self.lab.settled_services({role: arns[role] for role in SERVICES})
        settled_at = utc_now()
        checks = {f"{role} settled": {"passed": service_settled(services[role], arns[role]),
                                      "detail": f"{services[role]['runningCount']}/{services[role]['desiredCount']} on "
                                                f"{arns[role].rsplit('/', 1)[-1]}"} for role in SERVICES}
        states = self.lab.target_states()
        checks["api targets healthy"] = {"passed": bool(states) and set(states) == {"healthy"}, "detail": ",".join(states)}
        for path, expected in (("/api/auth/csrf", 200), ("/api/me", 401)):
            status = self.lab.http_status(path)
            checks[f"GET {path} {expected}"] = {"passed": status == expected, "detail": str(status)}
        errors = self.lab.startup_errors(record["started_at"])
        # Informational: generic ERROR lines include expected ones; the defined failures below gate.
        checks["startup ERROR lines"] = {"passed": True, "detail": json.dumps(errors)}
        bake_end = settled_at + datetime.timedelta(seconds=BAKE_SECONDS)
        self.lab.log(f"Baking until {stamp(bake_end)}: one scheduler cycle on the new tasks.")
        self.lab.wait_until(bake_end)
        record["bake"] = {"from": stamp(settled_at), "to": stamp(utc_now())}
        for role in SERVICES:
            passed, detail = fatal_check(self.lab.log_messages(role, settled_at, FATAL_FILTER))
            checks[f"{role} defined failures"] = {"passed": passed, "detail": detail}
        passed, detail = progress_check(self.lab.log_messages("worker", settled_at, PROGRESS_FILTER), progress_required)
        checks["worker progress"] = {"passed": passed, "detail": detail}
        passed, detail = schema_state_check(self.lab.log_messages("worker", settled_at, SCHEMA_FILTER),
                                            record["candidate"]["migration_heads"]["tenant"], progress_required)
        checks["worker schema state"] = {"passed": passed, "detail": detail}
        for name, check in checks.items():
            self.lab.log(f"  {'ok  ' if check['passed'] else 'FAIL'} {name}: {check['detail']}")
        return checks


class AwsLab:
    """The real lab: AWS CLI, Terraform and GitHub CLI calls."""

    def __init__(self, profile, terraform):
        self.profile, self.terraform = profile, terraform
        self.work = Path(tempfile.mkdtemp(prefix="scoutgrid-release."))
        os.chmod(self.work, 0o700)
        self.initialised = False

    # ---- process helpers ----------------------------------------------------------------
    def log(self, message):
        print(f"{utc_now().strftime('%H:%M:%SZ')} {message}", file=sys.stderr)

    def run(self, command, env=None, capture=True):
        result = subprocess.run(command, env=env, text=True, capture_output=capture)
        if result.returncode != 0:
            raise ReleaseError(f"{command[0]} {command[1] if len(command) > 1 else ''} failed: "
                               f"{(result.stderr or '').strip()[-600:]}")
        return result.stdout

    def aws(self, *args):
        output = self.run(["aws", "--profile", self.profile, "--region", REGION, "--output", "json", *args])
        return json.loads(output) if output.strip() else None

    def credentials_env(self):
        exported = json.loads(self.run(["aws", "configure", "export-credentials", "--profile", self.profile, "--format", "process"]))
        env = {key: value for key, value in os.environ.items() if not key.startswith("AWS_")}
        env.update(AWS_ACCESS_KEY_ID=exported["AccessKeyId"], AWS_SECRET_ACCESS_KEY=exported["SecretAccessKey"],
                   AWS_SESSION_TOKEN=exported.get("SessionToken", ""), AWS_REGION=REGION)
        return env

    def tf(self, *args):
        return self.run([self.terraform, f"-chdir={TF_ROOT}", *args], env=self.credentials_env())

    def guard(self):
        account = self.aws("sts", "get-caller-identity")["Account"]
        if account != ACCOUNT_ID:
            raise ReleaseError(f"profile {self.profile} is account {account}, not the lab {ACCOUNT_ID}")
        version = json.loads(self.run([self.terraform, "version", "-json"]))["terraform_version"]
        if version != TF_REQUIRED:
            raise ReleaseError(f"Terraform {TF_REQUIRED} wrote the lab state; found {version}")

    # ---- S3 release objects -------------------------------------------------------------
    def s3_get(self, key):
        target = self.work / "get.json"
        result = subprocess.run(["aws", "--profile", self.profile, "--region", REGION, "s3api", "get-object",
                                 "--bucket", STATE_BUCKET, "--key", key, "--expected-bucket-owner", ACCOUNT_ID, str(target)],
                                text=True, capture_output=True)
        if result.returncode != 0:
            if "NoSuchKey" in result.stderr:
                return None
            raise ReleaseError(f"reading s3://{STATE_BUCKET}/{key} failed: {result.stderr.strip()[-400:]}")
        return json.loads(target.read_text())

    def s3_put(self, key, data, create_only=False):
        body = self.work / "put.json"
        body.write_text(json.dumps(data, indent=1, sort_keys=True) + "\n")
        command = ["aws", "--profile", self.profile, "--region", REGION, "s3api", "put-object", "--bucket", STATE_BUCKET,
                   "--key", key, "--expected-bucket-owner", ACCOUNT_ID, "--body", str(body), "--content-type", "application/json",
                   "--server-side-encryption", "aws:kms", "--ssekms-key-id", STATE_KMS_KEY]
        if create_only:
            command += ["--if-none-match", "*"]
        result = subprocess.run(command, text=True, capture_output=True)
        if result.returncode != 0:
            if create_only and "PreconditionFailed" in result.stderr:
                return False
            raise ReleaseError(f"writing s3://{STATE_BUCKET}/{key} failed: {result.stderr.strip()[-400:]}")
        return True

    def s3_delete(self, key):
        self.aws("s3api", "delete-object", "--bucket", STATE_BUCKET, "--key", key, "--expected-bucket-owner", ACCOUNT_ID)

    # ---- inputs to a release ------------------------------------------------------------
    def resolve_sha(self, ref):
        sha = self.run(["gh", "api", f"repos/{REPO}/commits/{ref}", "--jq", ".sha"]).strip()
        if not FULL_SHA.fullmatch(sha):
            raise ReleaseError(f"cannot resolve {ref} to a commit")
        return sha

    def publication(self, sha):
        name = f"aws-publication-lab-{sha}"
        artifacts = json.loads(self.run(["gh", "api", "--method", "GET", f"repos/{REPO}/actions/artifacts",
                                         "-f", f"name={name}", "-f", "per_page=100"]))["artifacts"]
        live = sorted((item for item in artifacts if not item["expired"]), key=lambda item: item["created_at"])
        if not live:
            raise ReleaseError(f"{sha[:7]} has no lab publication record; it is published once its main checks pass")
        target = self.work / f"publication-{sha[:7]}"
        self.run(["gh", "run", "download", str(live[-1]["workflow_run"]["id"]), "-R", REPO, "-n", name, "-D", str(target)])
        return json.loads((target / "aws-publication.json").read_text())

    def ecr_has(self, digest):
        try:
            found = self.aws("ecr", "describe-images", "--repository-name", ECR_REPOSITORY, "--image-ids", f"imageDigest={digest}")
        except ReleaseError as error:
            if "ImageNotFoundException" in str(error):
                return False
            raise
        return bool(found and found.get("imageDetails"))

    def services_present(self):
        found = self.aws("ecs", "describe-services", "--cluster", CLUSTER, "--services", *SERVICES)["services"]
        return len(found) == len(SERVICES) and all(service["status"] == "ACTIVE" for service in found)

    def image_of(self, task_definition):
        image = self.aws("ecs", "describe-task-definition", "--task-definition", task_definition)
        return image["taskDefinition"]["containerDefinitions"][0]["image"].rsplit("@", 1)[-1]

    def live_images(self):
        live = {}
        for service in self.aws("ecs", "describe-services", "--cluster", CLUSTER, "--services", *SERVICES)["services"]:
            live[service["serviceName"]] = self.image_of(service["taskDefinition"]) if service["status"] == "ACTIVE" else None
        arns = self.aws("ecs", "list-task-definitions", "--family-prefix", f"{CLUSTER}-migrator", "--status", "ACTIVE",
                        "--sort", "DESC")["taskDefinitionArns"]
        live["migrator"] = self.image_of(arns[0]) if arns else None
        return {role: live.get(role) for role in (*SERVICES, "migrator")}

    # ---- steps --------------------------------------------------------------------------
    def stop_services(self):
        for role in SERVICES:
            self.aws("ecs", "update-service", "--cluster", CLUSTER, "--service", role, "--desired-count", "0")
        self.log("Waiting for api and worker to stop.")
        self.aws("ecs", "wait", "services-stable", "--cluster", CLUSTER, "--services", *SERVICES)

    def snapshot(self, identifier, release):
        self.aws("rds", "create-db-snapshot", "--db-instance-identifier", DB_ID, "--db-snapshot-identifier", identifier,
                 "--tags", "Key=Application,Value=ScoutGrid", "Key=Environment,Value=lab", f"Key=ReleaseId,Value={release}")
        self.log(f"Waiting for snapshot {identifier}.")
        self.aws("rds", "wait", "db-snapshot-available", "--db-snapshot-identifier", identifier)
        return identifier

    def plan(self, phase, images, targets):
        if not self.initialised:
            self.tf("init", "-input=false", "-no-color", "-lockfile=readonly", f"-backend-config={CFG / 'sydney-lab.s3.tfbackend'}")
            self.initialised = True
        variables = self.work / f"{phase}-images.tfvars.json"
        variables.write_text(json.dumps({"backend_images": images}))
        plan = self.work / f"{phase}.tfplan"
        self.tf("plan", "-input=false", "-no-color", "-lock-timeout=60s", f"-out={plan}",
                f"-var-file={CFG / 'sydney-lab.foundation.tfvars'}", f"-var-file={CFG / 'runtime-running.tfvars'}",
                f"-var-file={variables}", *[f"-target={target}" for target in targets])
        return plan, json.loads(self.tf("show", "-json", str(plan)))

    def apply(self, plan):
        self.log("Applying the checked plan.")
        self.tf("apply", "-input=false", "-no-color", "-lock-timeout=60s", str(plan))

    def outputs(self):
        outputs = json.loads(self.tf("output", "-json", "backend_runtime"))
        outputs["task_definition_arns"] = task_definition_arns(json.loads(self.tf("show", "-json")))
        return outputs

    def run_migrator(self, outputs):
        network = {"awsvpcConfiguration": {"subnets": outputs["task_subnet_ids"], "assignPublicIp": "DISABLED",
                                           "securityGroups": [outputs["migrator_security_group_id"]]}}
        started = self.aws("ecs", "run-task", "--cluster", CLUSTER, "--launch-type", "FARGATE", "--platform-version", "1.4.0",
                           "--count", "1", "--task-definition", outputs["task_definition_arns"]["migrator"],
                           "--network-configuration", json.dumps(network), "--disable-execute-command",
                           "--tags", "key=Application,value=ScoutGrid", "key=Environment,value=lab",
                           "key=ReleasePurpose,value=Migration")
        if started.get("failures") or not started.get("tasks"):
            raise ReleaseError(f"the migrator did not start: {started.get('failures')}")
        task = started["tasks"][0]["taskArn"]
        self.log(f"Migrator running: {task.rsplit('/', 1)[-1]} (log group /ecs/{CLUSTER}/migrator).")
        return task

    def wait_task(self, task, timeout=1800):
        deadline = time.time() + timeout
        while time.time() < deadline:
            described = self.aws("ecs", "describe-tasks", "--cluster", CLUSTER, "--tasks", task)["tasks"][0]
            if migrator_outcome(described) is not None:
                return described
            time.sleep(15)
        raise ReleaseError("the migrator did not finish within 30 minutes; it was left running for inspection")

    def settled_services(self, arns, timeout=600):
        deadline = time.time() + timeout
        while True:
            services = {service["serviceName"]: service for service in
                        self.aws("ecs", "describe-services", "--cluster", CLUSTER, "--services", *SERVICES)["services"]}
            if all(service_settled(services[role], arn) for role, arn in arns.items()) or time.time() > deadline:
                return services
            time.sleep(15)

    def target_states(self, timeout=600):
        group = self.aws("elbv2", "describe-target-groups", "--names", TARGET_GROUP)["TargetGroups"][0]["TargetGroupArn"]
        deadline = time.time() + timeout
        while True:
            states = [item["TargetHealth"]["State"] for item in
                      self.aws("elbv2", "describe-target-health", "--target-group-arn", group)["TargetHealthDescriptions"]]
            if (states and set(states) == {"healthy"}) or time.time() > deadline:
                return states
            time.sleep(15)

    def http_status(self, path):
        request = urllib.request.Request(API_ORIGIN + path, headers={"User-Agent": "scoutgrid-lab-release"})
        try:
            with urllib.request.urlopen(request, timeout=15) as response:
                return response.status
        except urllib.error.HTTPError as error:
            return error.code
        except (urllib.error.URLError, TimeoutError) as error:
            return f"unreachable: {error}"

    def wait_until(self, moment):
        remaining = (moment - utc_now()).total_seconds()
        if remaining > 0:
            time.sleep(remaining)

    def log_messages(self, role, since, pattern):
        found = self.aws("logs", "filter-log-events", "--log-group-name", f"/ecs/{CLUSTER}/{role}",
                         "--start-time", str(int(since.timestamp() * 1000)), "--filter-pattern", pattern,
                         "--max-items", "200")
        return [event["message"] for event in (found or {}).get("events", [])]

    def startup_errors(self, since):
        start = int(datetime.datetime.strptime(since, "%Y-%m-%dT%H:%M:%SZ")
                    .replace(tzinfo=datetime.timezone.utc).timestamp() * 1000)
        counts = {}
        for role in SERVICES:
            found = self.aws("logs", "filter-log-events", "--log-group-name", f"/ecs/{CLUSTER}/{role}",
                             "--start-time", str(start), "--filter-pattern", "ERROR", "--max-items", "200")
            counts[role] = len(found.get("events", [])) if found else 0
        return counts

    # ---- the operator -------------------------------------------------------------------
    def confirm(self, question):
        return input(f"{question} Type yes to continue: ").strip() == "yes"

    def browser_checks(self, checks):
        print("\nBrowser checks. Answer y when it works, n when it does not.", file=sys.stderr)
        answers = []
        for check in checks:
            answer = ""
            while answer not in ("y", "n"):
                answer = input(f"  {check} [y/n] ").strip().lower()
            note = input("    What happened? ").strip() if answer == "n" else ""
            answers.append({"check": check, "passed": answer == "y", "note": note})
        return answers


def main(argv):
    lab = AwsLab(os.environ.get("LAB_RELEASE_PROFILE", "sglab-release"), os.environ.get("TERRAFORM", "terraform"))
    release = Release(lab)
    command, args = (argv[0], argv[1:]) if argv else ("", [])
    try:
        if command == "status" and not args:
            lab.guard()
            release.status()
        elif command == "init" and len(args) == 3:
            lab.guard()
            release.init(args[0], int(args[1]), int(args[2]))
        elif command == "deploy" and len(args) in (1, 2) and args[1:] in ([], ["--no-progress-signal"]):
            lab.guard()
            release.deploy(args[0], progress_required=len(args) == 1)
        elif command == "check" and len(args) == 1:
            lab.guard()
            release.check(args[0])
        elif command == "rollback" and args in ([], ["--no-progress-signal"]):
            lab.guard()
            release.rollback(progress_required=not args)
        elif command == "accept" and not args:
            lab.guard()
            release.accept()
        elif command == "accept" and len(args) in (2, 4) and args[0] == "--answers" and (len(args) == 2 or args[2] == "--note"):
            lab.guard()
            release.accept(args[1], args[3] if len(args) == 4 else "")
        elif command == "unlock" and not args:
            lab.guard()
            release.unlock()
        else:
            print(__doc__.split("\n\n", 2)[1], file=sys.stderr)
            return 2
    except ReleaseError as error:
        lab.log(f"ERROR: {error}")
        return 1
    except ValueError as error:
        lab.log(f"ERROR: {error}")
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
