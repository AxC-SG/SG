#!/usr/bin/env python3
"""Lab backend release: move the Sydney lab to a published main commit, one checked step at a time.

  release.py status                      release inputs, lock, running images and the last release
  release.py init SHA PLATFORM TENANT    seed the release inputs from what the lab runs now (once)
  release.py deploy SHA [--frontend] [--no-progress-signal]
                                         release a published main commit to the lab; with --frontend, as a pair:
                                         the frontend for SHA (built from this checkout, which must be SHA) is
                                         staged first, then promoted to scoutgrid.io under the same lock once the
                                         backend is verified, then the pair is checked and recorded together
  release.py rollback [--no-progress-signal] [--note TEXT]
                                         return the lab to the last accepted release (pair), or the one before it
                                         (--no-progress-signal: the image predates the worker progress line, so its
                                         absence is recorded instead of failing the release; --note: why)
  release.py adopt-frontend              record the frontend scoutgrid.io serves now as the accepted release's
                                         frontend, once, before the first paired release
  release.py check SHA                   read-only: would SHA be a proven schema-neutral, runtime-only release?
                                         (catalog fingerprint, live schema state, migrator drift; changes nothing)
  release.py reconcile [--frontend] [--yes]
                                         resume the interrupted runtime-only release, or release the main head
                                         through the runtime-only path when `check` would call it eligible: never
                                         plans, registers or runs the migrator. Run it from a clean checkout of the
                                         commit it releases. --yes skips the prompt, after every eligibility check
  release.py accept [--answers yn… [--note TEXT]]
                                         record the browser checks for the live release (interactive, or
                                         answers the operator relayed, one y/n per check in order)
  release.py accept --waive --note TEXT  accept the live release without its browser checks, on the owner's
                                         decision: every check is recorded as waived (not passed), with TEXT
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
                unready tenant and a supported range that contains the database's tenant head; then the
                signed-in smoke (frontend/e2e/lab-smoke.mjs) when LAB_SMOKE_CONFIG names its config
  7. accept     later, `release.py accept` records the browser checks; all passing makes it the
                accepted release, any failure rejects it (then roll back or deploy a fix). The owner
                may waive them instead (`--waive`); the record and the accepted entry say so

A paired release (--frontend) adds, after step 6:
  6a. frontend  promote the exact staged Vercel deployment (recorded before the lock) to scoutgrid.io
  6b. paired    scoutgrid.io serves that deployment and answers 200, then the signed-in smoke again
A failure at 6a is `failed` / `frontend_pending`: rerunning the same deploy promotes the recorded
deployment without repeating the migrator, runtime or bake. A failure at 6b enters recovery.

Terraform renders images only from the release inputs object, which lab.sh reads too, and
lab.sh and this script share one lock, so a lab cycle never runs mid-release. A step that
fails leaves `pending` set: lab.sh then refuses, rerunning `deploy` for the same commit
resumes (finished steps are skipped or idempotent), and `rollback` recovers where the schema allows.
Restoring the exact accepted release reuses its acceptance (CD plan 4.7), and the release it
replaced is marked `recovered`; returning to the release before it waits for `release.py accept`.

deploy, rollback and reconcile print a result (CD plan 4.4): outcome `verified`, `blocked` (nothing
live changed), `failed` (a live step or check failed) or `needs_operator`, with its reason. reconcile's
result also names the live pair, the acceptance state, the record and the next manual action; it exits 0
for `verified` and for `blocked` with a planned reason (nothing changed, by design), otherwise 1.

Environment: LAB_RELEASE_PROFILE (default sglab-release; set it empty to use the ambient credentials, as
on a GitHub runner), TERRAFORM (Terraform 1.13.5), LAB_SMOKE_CONFIG
(the signed-in smoke's config, outside the repo; unset records the smoke as not configured), CHROMIUM_PATH,
VERCEL_TOKEN (paired releases, adopt-frontend, and rollbacks that restore a frontend).
Credentials go only to child processes and API calls and are never printed.
"""
import datetime
import importlib.util
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

# Load only this checkout's sibling package, including under python -I.
spec = importlib.util.spec_from_file_location("release_lib", Path(__file__).resolve().parent / "release_lib/__init__.py")
release_lib = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = release_lib
spec.loader.exec_module(release_lib)

from release_lib.errors import ReleaseError
from release_lib.frontend import Frontend
from release_lib.publication import PublicationSource, provenance
from release_lib.runtime_config import runtime_config
from release_lib.settings import (
    ACCOUNT_ID,
    API_ORIGIN,
    APP_DOMAIN,
    APP_ORIGIN,
    BAKE_SECONDS,
    BROWSER_CHECKS,
    CFG,
    CLUSTER,
    DB_ID,
    DEPLOYMENT_ID,
    DIGEST,
    ECR_REPOSITORY,
    FATAL_FILTER,
    FATAL_PATTERNS,
    FINGERPRINT,
    FULL_SHA,
    INPUTS_KEY,
    LAB_DIR,
    LOCK_KEY,
    MIGRATOR_STEPS,
    NEXT_ACTION,
    PHASES,
    PREFIX,
    PROGRESS_FILTER,
    PROGRESS_LINE,
    RECONCILE_BLOCKED,
    RECORDS,
    REGION,
    REGISTRY,
    REPLACE,
    REPO,
    REPO_ROOT,
    SCHEMA_FILTER,
    SCHEMA_LINE,
    SCHEMA_LOOKBACK,
    SERVICE,
    SERVICES,
    SMOKE_SCRIPT,
    SMOKE_TIMEOUT_SECONDS,
    STATE_BUCKET,
    STATE_KMS_KEY,
    TARGETS,
    TARGET_GROUP,
    TASK,
    TF_REQUIRED,
    TF_ROOT,
    VERCEL_API,
    VERCEL_CLI,
    VERCEL_PROJECT,
    VERCEL_TEAM,
)
from release_lib.checks import (
    utc_now,
    stamp,
    release_id,
    short,
    heads_valid,
    schema_mode,
    check_plan,
    check_publication,
    migrator_outcome,
    service_settled,
    task_definition_arns,
    progress_check,
    catalog_check,
    schema_state_check,
    smoke_check,
    fatal_check,
    frontend_id,
    live_differs,
    rollback_target,
    staged_reference,
)


def parse_options(args, flags=(), valued=()):
    """{option: True or value} for each option given once; None for anything else."""
    parsed, rest = {}, list(args)
    while rest:
        item = rest.pop(0)
        if item in parsed:
            return None
        if item in flags:
            parsed[item] = True
        elif item in valued and rest:
            parsed[item] = rest.pop(0)
        else:
            return None
    return parsed


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
            waiver = ", browser checks waived" if accepted.get("browser_checks") == "waived" else ""
            print(f"accepted:  {accepted.get('release_id', '-')} ({short(accepted.get('runtime_image_digest'))}{waiver})")
            print(f"last:      {json.dumps(inputs.get('last_release'))}")
            print(f"pending:   {json.dumps(inputs.get('pending'))}")
            waiting = inputs.get("awaiting_acceptance")
            print(f"awaiting:  {waiting['release_id'] + ' (run release.py accept)' if waiting else '-'}")
            for role, digest in live.items():
                expected = inputs["migrator_image_digest" if role == "migrator" else "runtime_image_digest"]
                print(f"live {role:<9}{short(digest)}{'' if digest in (None, expected) else '  DIFFERS FROM INPUTS'}")
            frontend = inputs.get("frontend")
            if not frontend:
                print("frontend:  not tracked (release.py adopt-frontend records the live one)")
                return
            adopted = " (adopted from the live domain)" if frontend.get("adopted") else ""
            print(f"frontend:  {frontend['deployment_id']} from {(frontend.get('source_sha') or '-')[:7]}{adopted}; "
                  f"accepted {frontend_id(accepted.get('frontend')) or '-'}")
            if inputs.get("frontend_promoting"):
                print(f"promoting: {inputs['frontend_promoting']} (outcome unknown; rerun the deploy or roll back)")
            served = self.lab.frontend_live(required=False)
            print(f"live {APP_DOMAIN}: {served or 'not checked (VERCEL_TOKEN unset)'}"
                  f"{'  DIFFERS FROM INPUTS' if served and served != frontend['deployment_id'] else ''}")

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

    def refuse_unfinished(self, inputs, sha):
        pending = inputs.get("pending")
        if pending and (pending["kind"] != "deploy" or pending["source_sha"] != sha):
            raise ReleaseError(f"{pending['kind']} {pending['release_id']} stopped after {pending['phase']}; "
                               f"rerun it, or run release.py rollback", outcome="needs_operator", reason="unfinished")
        if inputs.get("awaiting_acceptance"):
            raise ReleaseError(f"{inputs['awaiting_acceptance']['release_id']} is waiting for its browser checks; "
                               "run release.py accept, or release.py rollback", reason="awaiting_acceptance")
        return pending

    def staged_frontend(self, sha):
        """The frontend for a paired release, staged outside the lock (CD plan 4.5). A resumed release
        reuses the deployment its record already names; a staging failure changes nothing live."""
        inputs = self.inputs()
        pending = self.refuse_unfinished(inputs, sha)
        record = self.lab.s3_get(f"{RECORDS}/{pending['release_id']}.json") if pending else None
        if record and record.get("frontend"):
            return record["frontend"]
        staged = self.lab.frontend_stage(sha)
        if not DEPLOYMENT_ID.fullmatch(staged.get("deployment_id") or "") or staged.get("source_sha") != sha:
            raise ReleaseError(f"the staged frontend is not a recorded deployment of {sha[:7]}: {json.dumps(staged)}")
        self.lab.log(f"Staged frontend {staged['deployment_id']} ({staged.get('url')}) for {sha[:7]}; not promoted yet.")
        return staged

    def deploy(self, ref, progress_required=True, frontend=False):
        sha = self.lab.resolve_sha(ref)
        staged = self.staged_frontend(sha) if frontend else None
        with self.locked("deploy " + sha[:7]):
            inputs = self.inputs()
            pending = self.refuse_unfinished(inputs, sha)
            publication = self.lab.publication(sha)
            check_publication(publication, sha)
            digest, heads = publication["image_digest"], publication["migration_heads"]
            fingerprint = publication.get("migration_catalog_sha256")
            if not self.lab.ecr_has(digest):
                raise ReleaseError(f"{digest} is not in the lab ECR repository")
            if not self.lab.services_present():
                raise ReleaseError("the lab is parked; run lab.sh up first (publication does not need it)", reason="parked")
            record = self.lab.s3_get(f"{RECORDS}/{pending['release_id']}.json") if pending else None
            if record:
                mode = record["mode"]
                if record.get("frontend") and not frontend:
                    raise ReleaseError(f"{record['release_id']} is a paired release; rerun it with --frontend",
                                       outcome="needs_operator", reason="unfinished")
                if staged and frontend_id(record.get("frontend")) not in (None, staged["deployment_id"]):
                    raise ReleaseError(f"{record['release_id']} names frontend {frontend_id(record['frontend'])}, "
                                       f"not {staged['deployment_id']}", outcome="needs_operator", reason="unfinished")
            else:
                mode = schema_mode(inputs["database_heads"], heads)
                record = {"release_id": release_id(sha, utc_now()), "kind": "deploy", "status": "started", "mode": mode,
                          "candidate": {"source_sha": sha, "image_digest": digest, "migration_heads": heads,
                                        "migration_catalog_sha256": fingerprint,
                                        "publication_run": publication.get("candidate_run")},
                          "from": {key: inputs[key] for key in ("runtime_image_digest", "migrator_image_digest", "database_heads")},
                          "steps": [], "checks": {}, "browser_checks": [], "started_at": stamp()}
                record["from"]["frontend"] = frontend_id(inputs.get("frontend"))
            if staged:
                record["frontend"] = staged
            if not pending:
                self.qualify_schema(inputs, record, fingerprint)
            self.lab.log(f"Release {record['release_id']}: {short(inputs['runtime_image_digest'])} -> {short(digest)} "
                         f"({sha[:7]}), schema {mode}: {inputs['database_heads']} -> {heads}"
                         f"{' (resuming)' if pending else ''}.")
            if mode == "forward":
                self.lab.log("Schema-changing release: api and worker stop, RDS is snapshotted, the migrator runs, "
                             "then the candidate starts. Sign-in and the API are offline meanwhile (about 5-10 minutes). "
                             "The previous image cannot run on the new schema; recovery is the snapshot.")
            if record.get("frontend"):
                self.lab.log(f"Paired release: after the backend verifies, {APP_DOMAIN} moves to "
                             f"{record['frontend']['deployment_id']}.")
            if not self.lab.confirm(f"Release {sha[:7]} to the lab?"):
                raise ReleaseError("not confirmed; nothing changed", reason="not_confirmed")
            meta = {"source_sha": sha, "migration_heads": heads, "migration_catalog_sha256": fingerprint}
            self.run(inputs, record, runtime=digest, migrator=digest, meta=meta, stop=(mode == "forward"),
                     progress_required=progress_required, frontend=record.get("frontend"))
            return self.result(inputs, record)

    def qualify_schema(self, inputs, record, fingerprint):
        """Refuse before any change when the catalog or the live schema state contradicts the heads."""
        catalog = catalog_check(inputs.get("database_catalog_sha256"), fingerprint)
        record["catalog"] = catalog
        if record["mode"] == "neutral" and catalog == "changed":
            raise ReleaseError("the migration heads are equal but the migration catalog differs from the one the "
                               "database ran (an applied migration was changed); nothing changed", reason="schema_changed")
        if catalog == "unverified":
            self.lab.log("The migration catalog cannot be compared (the inputs or the publication predate the "
                         "fingerprint); this release is recorded as schema-unverified.")
        messages = self.lab.log_messages("worker", utc_now() - SCHEMA_LOOKBACK, SCHEMA_FILTER)
        passed, detail = schema_state_check(messages, inputs["database_heads"]["tenant"], required=False)
        record["schema_state_before"] = {"passed": passed, "detail": detail}
        if not passed and record["mode"] == "neutral":
            raise ReleaseError(f"the live tenant schema state is not ready ({detail}); nothing changed",
                               reason="schema_unverified")

    def check(self, ref):
        """Read-only eligibility for a runtime-only release (CD plan section 4.3). Changes nothing."""
        sha = self.lab.resolve_sha(ref)
        inputs = self.inputs()
        publication = self.lab.publication(sha)
        check_publication(publication, sha)
        found = self.eligibility(inputs, publication)
        reasons = [f"{reason}: {detail}" for reason, detail in found["reasons"]]
        outcome = "eligible" if not reasons else (
            "needs_operator" if any(reason == "needs_operator" for reason, _ in found["reasons"]) else "blocked")
        result = {"source_sha": sha, "outcome": outcome, "reasons": reasons, "schema_state": found["schema_state"],
                  "catalog": found["catalog"]}
        print(json.dumps(result, indent=2))
        return result

    def eligibility(self, inputs, publication, first_only=False):
        """Why a published commit is not a proven schema-neutral, runtime-only release (CD plan 4.3), as
        (reason, detail) pairs; none when it is eligible. first_only stops at the first reason, before
        the slower checks. Reads only: logs and a migrator plan that is never applied."""
        found = {"reasons": [], "catalog": None, "schema_state": None}

        def stop(reason, detail):
            found["reasons"].append((reason, detail))
            return first_only

        pending = inputs.get("pending")
        if pending and stop("needs_operator", f"{pending['kind']} {pending['release_id']} stopped after {pending['phase']}"):
            return found
        waiting = inputs.get("awaiting_acceptance")
        if waiting and stop("awaiting_acceptance", f"{waiting['release_id']} is waiting for its browser checks"):
            return found
        if not self.lab.services_present() and stop("parked", "the lab services are not running"):
            return found
        if publication["migration_heads"] != inputs["database_heads"] and stop(
                "schema_changed", f"heads {publication['migration_heads']} against the database {inputs['database_heads']}"):
            return found
        catalog = found["catalog"] = catalog_check(inputs.get("database_catalog_sha256"),
                                                   publication.get("migration_catalog_sha256"))
        if catalog != "same" and stop(f"schema_{catalog}", f"migration catalog fingerprint is {catalog}"):
            return found
        passed, detail = schema_state_check(
            self.lab.log_messages("worker", utc_now() - SCHEMA_LOOKBACK, SCHEMA_FILTER), inputs["database_heads"]["tenant"])
        found["schema_state"] = detail
        if not passed and stop("schema_unverified", detail):
            return found
        # The runtime-only path keeps the retained migrator. Rendering it from this checkout with that
        # digest must change nothing; any change means its configuration moved, which needs review.
        _, document = self.lab.plan("migrator-drift", {"runtime": inputs["runtime_image_digest"],
                                                        "migrator": inputs["migrator_image_digest"]}, TARGETS["migrator"])
        drift, _ = check_plan(document, "migrator")
        if drift:
            stop("migrator_drift", "; ".join(line.strip() for line in drift))
        return found

    # ---- reconcile: the runtime-only path (CD plan 4.3, 4.4) ------------------------------
    def reconcile(self, frontend=False, assume_yes=False):
        """Resume the interrupted runtime-only release, or release main's head through the runtime-only
        path once it qualifies. Never plans, registers or runs the migrator, stops the services or takes a
        snapshot. Returns the result instead of raising, so every outcome carries the same fields."""
        state = {"sha": None, "record": None, "reason": None}
        try:
            self.reconcile_under_lock(frontend, assume_yes, state)
        except ReleaseError as error:
            return self.reconcile_result(state, error.outcome, error.reason, str(error))
        return self.reconcile_result(state, "verified", state["reason"])

    def reconcile_under_lock(self, frontend, assume_yes, state):
        inputs = self.inputs()
        sha, record, _ = self.reconcile_target(inputs)
        state["sha"], state["record"] = sha, record
        # Cheap refusals first, so a parked or waiting lab never builds a frontend.
        if not self.lab.services_present():
            raise ReleaseError("the lab is parked; nothing changed", reason="parked")
        staged = self.reconcile_frontend(inputs, sha, record) if frontend else None
        with self.locked("reconcile " + sha[:7]):
            inputs = self.inputs()
            again, record, publication = self.reconcile_target(inputs)
            state["record"] = record
            if again != sha:
                raise ReleaseError(f"the lab moved from {sha[:7]} to {again[:7]} meanwhile; nothing changed. "
                                   "Reconcile again", reason="superseded")
            if record:
                self.resume_runtime_only(inputs, record, frontend, staged, assume_yes)
            else:
                self.start_runtime_only(inputs, sha, publication, staged, assume_yes, state)

    def reconcile_target(self, inputs):
        """(commit, record to resume or None, publication or None): the interrupted runtime-only release
        first; otherwise main's head, once published. Nothing new is chosen while anything is unfinished."""
        pending, record, publication = inputs.get("pending"), None, None
        if pending:
            record = self.lab.s3_get(f"{RECORDS}/{pending['release_id']}.json")
            if not record or record.get("kind") != "reconcile" or record.get("path") != "runtime-only" or \
                    record.get("mode") != "neutral" or \
                    any(step["step"] in MIGRATOR_STEPS for step in record.get("steps", [])):
                raise ReleaseError(f"{pending['kind']} {pending['release_id']} stopped after {pending['phase']} and is not a "
                                   f"runtime-only release; resume it with release.py {pending['kind']} from a checkout of "
                                   f"{pending['source_sha'][:7]}, or run release.py rollback",
                                   outcome="needs_operator", reason="unfinished")
            sha = pending["source_sha"]
        else:
            waiting = inputs.get("awaiting_acceptance")
            if waiting:
                raise ReleaseError(f"{waiting['release_id']} is waiting for its browser checks; nothing changed",
                                   reason="awaiting_acceptance")
            sha = self.lab.resolve_sha("main")
            publication = self.lab.publication(sha, required=False)
            if publication is None:
                raise ReleaseError(f"main is at {sha[:7]}, which has no lab publication yet (its checks are still "
                                   "running, or failed); nothing changed", reason="superseded")
        head, clean = self.lab.checkout()
        if head != sha or not clean:
            where = f"this checkout is at {head[:7]}{'' if clean else ' with uncommitted changes'}"
            if record:
                raise ReleaseError(f"{record['release_id']} releases {sha[:7]} but {where}; resume it from a clean "
                                   f"checkout of {sha[:7]}, or run release.py rollback",
                                   outcome="needs_operator", reason="unfinished")
            raise ReleaseError(f"main is at {sha[:7]} but {where}; nothing changed. Reconcile again from main",
                               reason="superseded")
        return sha, record, publication

    def reconcile_frontend(self, inputs, sha, record):
        """The frontend a paired reconcile promotes, staged before the lock (CD plan 4.5); None when the
        tracked frontend already comes from this commit."""
        if record and record.get("frontend"):
            return record["frontend"]
        tracked = inputs.get("frontend") or {}
        if tracked.get("source_sha") == sha and not inputs.get("frontend_promoting"):
            return None
        staged = self.lab.frontend_stage(sha)
        if not DEPLOYMENT_ID.fullmatch(staged.get("deployment_id") or "") or staged.get("source_sha") != sha:
            raise ReleaseError(f"the staged frontend is not a recorded deployment of {sha[:7]}: {json.dumps(staged)}")
        self.lab.log(f"Staged frontend {staged['deployment_id']} ({staged.get('url')}) for {sha[:7]}; not promoted yet.")
        return staged

    def start_runtime_only(self, inputs, sha, publication, staged, assume_yes, state):
        check_publication(publication, sha)
        digest, heads = publication["image_digest"], publication["migration_heads"]
        if not self.lab.ecr_has(digest):
            raise ReleaseError(f"{digest} is not in the lab ECR repository")
        # Recheck everything under the lock, before the first mutation (CD plan 4.4).
        found = self.eligibility(inputs, publication, first_only=True)
        if found["reasons"]:
            reason, detail = found["reasons"][0]
            raise ReleaseError(f"{sha[:7]} is not a proven runtime-only release ({reason}: {detail}); nothing changed",
                               reason=reason)
        runtime = inputs.get("runtime") or {}
        if staged is None and inputs["runtime_image_digest"] == digest and runtime.get("source_sha") == sha:
            self.lab.log(f"The lab already runs {sha[:7]} ({short(digest)}); nothing to do.")
            state["reason"] = "no_change"
            return
        fingerprint = publication.get("migration_catalog_sha256")
        record = {"release_id": release_id(sha, utc_now()), "kind": "reconcile", "path": "runtime-only",
                  "status": "started", "mode": schema_mode(inputs["database_heads"], heads),
                  "candidate": {"source_sha": sha, "image_digest": digest, "migration_heads": heads,
                                "migration_catalog_sha256": fingerprint, "publication_run": publication.get("candidate_run")},
                  "from": {key: inputs[key] for key in ("runtime_image_digest", "migrator_image_digest", "database_heads")},
                  "catalog": found["catalog"], "schema_state_before": {"passed": True, "detail": found["schema_state"]},
                  "migrator_drift": "none", "steps": [], "checks": {}, "browser_checks": [], "started_at": stamp()}
        record["from"]["frontend"] = frontend_id(inputs.get("frontend"))
        if staged:
            record["frontend"] = staged
        state["record"] = record
        self.lab.log(f"Reconcile {record['release_id']}: api and worker {short(inputs['runtime_image_digest'])} -> "
                     f"{short(digest)} ({sha[:7]}), runtime-only: the migrator {short(inputs['migrator_image_digest'])} "
                     f"and the schema {heads} stay."
                     + (f" After the backend verifies, {APP_DOMAIN} moves to {staged['deployment_id']}." if staged else ""))
        if not self.confirmed(f"Release {sha[:7]} to the lab?", assume_yes):
            raise ReleaseError("not confirmed; nothing changed", reason="not_confirmed")
        meta = {"source_sha": sha, "migration_heads": heads, "migration_catalog_sha256": fingerprint}
        self.run(inputs, record, runtime=digest, migrator=None, meta=meta, stop=False, frontend=staged)

    def resume_runtime_only(self, inputs, record, frontend, staged, assume_yes):
        sha, digest = record["candidate"]["source_sha"], record["candidate"]["image_digest"]
        if not self.lab.services_present():
            raise ReleaseError("the lab is parked; nothing changed", reason="parked")
        if record.get("frontend") and not frontend:
            raise ReleaseError(f"{record['release_id']} is a paired release; reconcile with --frontend",
                               outcome="needs_operator", reason="unfinished")
        if staged and frontend_id(record.get("frontend")) not in (None, staged["deployment_id"]):
            raise ReleaseError(f"{record['release_id']} names frontend {frontend_id(record['frontend'])}, "
                               f"not {staged['deployment_id']}", outcome="needs_operator", reason="unfinished")
        publication = self.lab.publication(sha)
        check_publication(publication, sha)
        if publication["image_digest"] != digest:
            raise ReleaseError(f"{sha[:7]} is now published as {short(publication['image_digest'])}, but "
                               f"{record['release_id']} releases {short(digest)}", outcome="needs_operator", reason="unfinished")
        if staged:
            record["frontend"] = staged
        self.lab.log(f"Resuming reconcile {record['release_id']} ({sha[:7]}) after "
                     f"{record['steps'][-1]['step'] if record['steps'] else 'no step'}; runtime-only.")
        if not self.confirmed(f"Resume {record['release_id']}?", assume_yes):
            raise ReleaseError("not confirmed; nothing changed", reason="not_confirmed")
        meta = {"source_sha": sha, "migration_heads": record["candidate"]["migration_heads"],
                "migration_catalog_sha256": record["candidate"].get("migration_catalog_sha256")}
        self.run(inputs, record, runtime=digest, migrator=None, meta=meta, stop=False, frontend=record.get("frontend"))

    def confirmed(self, question, assume_yes):
        if assume_yes:
            self.lab.log(f"{question} Confirmed by --yes, after every eligibility check.")
            return True
        return self.lab.confirm(question)

    def reconcile_result(self, state, outcome, reason, error=None):
        """The reconcile result (CD plan 4.4): outcome, reason and phase, the candidate and release, the live
        pair and its acceptance as recorded now, the record, and the next manual action."""
        record = state.get("record")
        try:
            inputs = self.lab.s3_get(INPUTS_KEY) or {}
        except ReleaseError:
            inputs = {}
        waiting = (inputs.get("awaiting_acceptance") or {}).get("release_id")
        if record and record.get("status") == "failed":
            phase = record.get("failed_at")
        elif record and record.get("steps") and outcome == "verified":
            phase = record["steps"][-1]["step"]
        else:
            phase = "eligibility"
        result = {"outcome": outcome, "reason": reason, "phase": phase, "kind": "reconcile", "path": "runtime-only",
                  "source_sha": state.get("sha"), "release_id": record["release_id"] if record else None,
                  "backend": inputs.get("runtime_image_digest"), "frontend": frontend_id(inputs.get("frontend")),
                  "acceptance": "awaiting" if waiting else ("unfinished" if inputs.get("pending") else "accepted"),
                  "accepted": (inputs.get("accepted") or {}).get("release_id"), "awaiting_acceptance": waiting,
                  "record": f"s3://{STATE_BUCKET}/{RECORDS}/{record['release_id']}.json" if record else None,
                  "next": NEXT_ACTION.get((outcome, reason), "inspect release.py status and the record; resume or "
                                                             "roll back locally")}
        if error:
            result["error"] = error
        return result

    def rollback(self, progress_required=True, note=""):
        with self.locked("rollback"):
            inputs = self.inputs()
            target = rollback_target(inputs)
            if not target:
                raise ReleaseError("there is no earlier accepted release to return to", outcome="needs_operator",
                                   reason="no_target")
            if target["migration_heads"] != inputs["database_heads"]:
                snapshots = [step.get("snapshot") for step in self.last_record_steps(inputs) if step.get("snapshot")]
                raise ReleaseError(f"{target['release_id']} needs schema {target['migration_heads']} but the database is at "
                                   f"{inputs['database_heads']}; its image cannot run here. Fix forward with deploy, or "
                                   f"restore the pre-migration snapshot {snapshots or '(none recorded)'} through the reviewed path",
                                   outcome="needs_operator", reason="schema_changed")
            # The frontend comes back too when release.py moved it (or may have) away from the target's.
            restore_frontend = target.get("frontend") if (
                inputs.get("frontend_promoting") or frontend_id(inputs.get("frontend")) != frontend_id(target.get("frontend"))) else None
            moved = inputs.get("frontend_promoting") or (
                inputs.get("frontend") and not inputs["frontend"].get("adopted") and frontend_id(inputs["frontend"]))
            if moved and not target.get("frontend"):
                raise ReleaseError(f"{target['release_id']} has no recorded frontend, but a release moved {APP_DOMAIN} to "
                                   f"{moved}; restore the frontend by hand first", outcome="needs_operator",
                                   reason="frontend_unrecorded")
            replaced = self.replaced_release(inputs, target)
            record = {"release_id": release_id(target["source_sha"], utc_now()), "kind": "rollback", "status": "started",
                      "mode": "neutral", "rolls_back_to": target["release_id"], "replaces": replaced, "note": note,
                      "candidate": {"source_sha": target["source_sha"], "image_digest": target["runtime_image_digest"],
                                    "migration_heads": target["migration_heads"]},
                      "from": {key: inputs[key] for key in ("runtime_image_digest", "migrator_image_digest", "database_heads")},
                      "steps": [], "checks": {}, "browser_checks": [], "started_at": stamp()}
            record["from"]["frontend"] = frontend_id(inputs.get("frontend"))
            if restore_frontend:
                record["frontend"] = restore_frontend
            reuse = target["release_id"] == (inputs.get("accepted") or {}).get("release_id")
            self.lab.log(f"Rollback {record['release_id']}: api and worker {short(inputs['runtime_image_digest'])} -> "
                         f"{short(target['runtime_image_digest'])} ({target['release_id']}); the migrator and schema stay."
                         + (f" {APP_DOMAIN} returns to {restore_frontend['deployment_id']} first." if restore_frontend else ""))
            if not self.lab.confirm("Roll back api and worker?"):
                raise ReleaseError("not confirmed; nothing changed", reason="not_confirmed")
            self.reject_waiting(inputs, "rolled back before acceptance")
            meta = {"source_sha": target["source_sha"], "migration_heads": target["migration_heads"]}
            self.run(inputs, record, runtime=target["runtime_image_digest"], migrator=None, meta=meta,
                     stop=False, restores=target, progress_required=progress_required, frontend=restore_frontend,
                     reuse_acceptance=reuse)
            self.mark_replaced(replaced, record)
            return self.result(inputs, record)

    @staticmethod
    def replaced_release(inputs, target):
        """The release a rollback takes the lab away from."""
        for key in ("pending", "awaiting_acceptance"):
            if inputs.get(key):
                return inputs[key]["release_id"]
        if target == inputs.get("previous_accepted"):
            return (inputs.get("accepted") or {}).get("release_id")
        return (inputs.get("last_release") or {}).get("release_id")

    def mark_replaced(self, replaced, record):
        """Link a verified rollback to the release it replaced, so each record names the other."""
        key = f"{RECORDS}/{replaced}.json"
        old = self.lab.s3_get(key) if replaced else None
        if not old or old["release_id"] == record["release_id"]:
            return
        recovered = old["status"] in ("failed", "rejected")
        old["rolled_back"] = {"by": record["release_id"], "at": stamp(),
                              "reason": "recovered" if recovered else "rolled back by the operator",
                              "note": record.get("note", "")}
        if old["status"] == "failed":
            old["result"] = {**old.get("result", {}), "outcome": "failed", "reason": "recovered"}
        self.lab.s3_put(key, old)

    def adopt_frontend(self):
        """Record the deployment scoutgrid.io serves now as the accepted release's frontend, once. It was not
        promoted by release.py, so the entry says it was adopted; later paired releases replace it."""
        with self.locked("adopt-frontend"):
            inputs = self.inputs()
            if inputs.get("pending") or inputs.get("awaiting_acceptance") or inputs.get("frontend_promoting"):
                raise ReleaseError("finish or roll back the current release first; nothing changed")
            if inputs.get("frontend"):
                raise ReleaseError(f"the frontend is already tracked ({inputs['frontend']['deployment_id']}); nothing changed")
            live = self.lab.frontend_live()
            deployment = self.lab.frontend_deployment(live)
            if deployment.get("ready_state") != "READY" or deployment.get("target") != "production":
                raise ReleaseError(f"{APP_DOMAIN} serves {live}, which is not a ready production deployment: {deployment}")
            frontend = {"deployment_id": live, "url": deployment.get("url"), "source_sha": deployment.get("source_sha"),
                        "adopted": True, "adopted_at": stamp()}
            inputs["frontend"] = frontend
            inputs["accepted"]["frontend"] = frontend
            inputs["updated_at"] = stamp()
            self.lab.s3_put(INPUTS_KEY, inputs)
            self.lab.log(f"Adopted {live} ({deployment.get('url')}) as the frontend of {inputs['accepted']['release_id']}.")

    @staticmethod
    def result(inputs, record):
        """The machine-readable outcome of a deploy or rollback that finished (CD plan 4.4)."""
        return {"outcome": "verified", "reason": None, "phase": record["steps"][-1]["step"] if record["steps"] else None,
                "release_id": record["release_id"], "kind": record["kind"], "source_sha": record["candidate"]["source_sha"],
                "backend": inputs["runtime_image_digest"], "frontend": frontend_id(inputs.get("frontend")),
                "acceptance": "reused" if record["status"] == "accepted" else "awaiting",
                "replaces": record.get("replaces")}

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
    def run(self, inputs, record, runtime, migrator, meta, stop, restores=None, progress_required=True,
            frontend=None, reuse_acceptance=False):
        # The code half of the runtime-only guarantee; the GitHub release role denies the same actions.
        if record.get("path") == "runtime-only" and (migrator or stop):
            raise ReleaseError("a runtime-only release never stops the services, snapshots or touches the migrator",
                               outcome="needs_operator", reason="refused")
        step = "start"
        # Durable intent precedes every possible live mutation, including a partial stop/apply.
        inputs["pending"] = {"release_id": record["release_id"], "source_sha": record["candidate"]["source_sha"],
                             "kind": record["kind"], "phase": "started"}
        self.save(inputs, record)
        try:
            if stop and not self.done(record, "stopped"):
                step = "stopped"
                self.lab.stop_services()
                self.mark(inputs, record, "stopped")
            if stop and not self.done(record, "snapshot"):
                step = "snapshot"
                snapshot = self.lab.snapshot(f"{CLUSTER}-release-{record['release_id']}", record["release_id"])
                self.mark(inputs, record, "snapshot", snapshot=snapshot)
            # A resumed release never runs a migrator that already exited 0.
            if migrator and not self.done(record, "migrated"):
                step = "migrator"
                self.terraform("migrator", {"runtime": inputs["runtime_image_digest"], "migrator": migrator})
                inputs["migrator_image_digest"], inputs["migrator"] = migrator, meta
                self.mark(inputs, record, "migrator")
                step = "migrate"
                task = record.get("migrator_task")
                if not task:
                    # Stable identity also covers a lost RunTask response before the ARN can be saved.
                    if record.get("failed_at") == "migrate" and not record.get("migrator_client_token"):
                        raise ReleaseError("legacy migration has no durable task identity; inspect ECS before recovery",
                                           outcome="needs_operator", reason="unfinished")
                    attempted = record.get("migrator_attempted_at")
                    if attempted:
                        age = utc_now() - datetime.datetime.fromisoformat(attempted.replace("Z", "+00:00"))
                        if age.total_seconds() > 3000:
                            raise ReleaseError("migration launch outcome is unknown and its safe retry window expired; "
                                               "inspect ECS before recovery", outcome="needs_operator", reason="unfinished")
                    record.setdefault("migrator_attempted_at", stamp())
                    token = record.setdefault("migrator_client_token", record["release_id"])
                    self.save(inputs, record)
                    task = self.lab.run_migrator(self.lab.outputs(), token)
                    record["migrator_task"] = task
                    self.save(inputs, record)
                succeeded, detail = migrator_outcome(self.lab.wait_task(task))
                if not succeeded:
                    raise ReleaseError(f"the migrator failed ({detail}); api and worker were not changed")
                inputs["database_heads"] = meta["migration_heads"]
                inputs["database_catalog_sha256"] = meta.get("migration_catalog_sha256")
                self.mark(inputs, record, "migrated", task=task, detail=detail)
            # A rollback restores the frontend first: backend N serves frontend N-1 (CD plan 4.5).
            if frontend and record["kind"] == "rollback":
                step = "frontend"
                self.promote(inputs, record, frontend)
            # A frontend retry after a verified backend repeats neither the rollout nor the bake.
            if not self.done(record, "verified"):
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
            if frontend and record["kind"] != "rollback":
                step = "frontend"
                self.promote(inputs, record, frontend)
            if frontend:
                step = "paired"
                record["paired_checks"] = self.paired_checks(frontend)
                failed = [name for name, check in record["paired_checks"].items() if not check["passed"]]
                if failed:
                    raise ReleaseError(f"paired checks failed: {', '.join(failed)}")
                self.mark(inputs, record, "paired")
        except BaseException as error:
            if isinstance(error, ReleaseError) and error.outcome == "needs_operator":
                outcome, reason = error.outcome, error.reason
            elif record["kind"] == "rollback":
                outcome, reason = "needs_operator", "recovery_failed"
            elif step == "frontend":
                outcome, reason = "failed", "frontend_pending"
            else:
                outcome, reason = "failed", "check_failed" if step in ("verify", "paired") else "step_failed"
            record.update(status="failed", failed_at=step, error=str(error) or type(error).__name__, ended_at=stamp(),
                          result={"outcome": outcome, "reason": reason, "phase": step})
            self.save(inputs, record)
            retry = (f" The backend is verified: rerun the same {record['kind']} to promote the recorded frontend "
                     "without redeploying the backend, or run release.py rollback.") if reason == "frontend_pending" else (
                     f" lab.sh refuses until a {record['kind']} of the same commit resumes it or release.py rollback recovers.")
            raise ReleaseError(f"{record['kind']} {record['release_id']} failed at {step}: {error}. "
                               f"The record is in s3://{STATE_BUCKET}/{RECORDS}/.{retry}",
                               outcome=outcome, reason=reason) from error
        # Terraform and the inputs agree again, so lab cycles may run; acceptance is the operator's.
        record["status"] = "verified"
        record["result"] = {"outcome": "verified", "reason": None, "phase": record["steps"][-1]["step"]}
        inputs["pending"] = None
        if reuse_acceptance:
            # The exact accepted release is back and verified: its acceptance stands (CD plan 4.7).
            record.update(status="accepted", ended_at=stamp(),
                          acceptance=f"reuses the acceptance of {restores['release_id']}: restored exactly and verified")
            inputs["awaiting_acceptance"] = None
            self.save(inputs, record)
            self.lab.log(f"Rollback {record['release_id']} restored the accepted {restores['release_id']} and passed the "
                         "automated checks; its acceptance stands.")
            return
        inputs["awaiting_acceptance"] = {"release_id": record["release_id"], "kind": record["kind"],
                                         "runtime_image_digest": runtime, **meta, "frontend": inputs.get("frontend"),
                                         "restores": restores}
        self.save(inputs, record)
        self.lab.log(f"{record['kind'].capitalize()} {record['release_id']} is live and passed the automated checks. "
                     "Run the browser checks, then record them with release.py accept.")

    def promote(self, inputs, record, frontend):
        """Point the domain at the recorded deployment. Intent is saved first, because a failed call does not prove
        the domain did not move; a retry or rollback reads the domain before acting."""
        target = frontend["deployment_id"]
        inputs["frontend_promoting"] = target
        self.save(inputs, record)
        if self.lab.frontend_live() != target:
            self.lab.frontend_promote(target)
        served = self.lab.frontend_live()
        if served != target:
            raise ReleaseError(f"{APP_DOMAIN} serves {served}, not {target}")
        inputs["frontend"], inputs["frontend_promoting"] = frontend, None
        self.mark(inputs, record, "frontend", deployment=target)

    def paired_checks(self, frontend):
        """The pair on the canonical origin: the domain serves the recorded deployment, and the signed-in smoke passes."""
        served = self.lab.frontend_live()
        checks = {f"{APP_DOMAIN} serves {frontend['deployment_id']}": {"passed": served == frontend["deployment_id"],
                                                                         "detail": str(served)}}
        status = self.lab.app_status("/")
        checks[f"GET {APP_ORIGIN}/ 200"] = {"passed": status == 200, "detail": str(status)}
        passed, detail = smoke_check(self.lab.signed_in_smoke())
        checks["signed-in smoke on the pair"] = {"passed": passed, "detail": detail}
        for name, check in checks.items():
            self.lab.log(f"  {'ok  ' if check['passed'] else 'FAIL'} {name}: {check['detail']}")
        return checks

    def accept(self, answers=None, note="", waive=False):
        if waive and not note.strip():
            raise ReleaseError("a waiver needs --note saying who waived the browser checks and why")
        with self.locked("accept"):
            inputs = self.inputs()
            waiting = inputs.get("awaiting_acceptance")
            if not waiting:
                raise ReleaseError("no release is waiting for its browser checks")
            record = self.lab.s3_get(f"{RECORDS}/{waiting['release_id']}.json")
            checks = json.loads(BROWSER_CHECKS.read_text())["checks"]
            if waive:
                # Nobody ran these checks: record them as waived, never as passed.
                record["browser_checks"] = [{"check": check, "passed": None, "waived": True, "note": note}
                                            for check in checks]
            elif answers is None:
                record["browser_checks"] = self.lab.browser_checks(checks)
            else:
                if not re.fullmatch(r"[yn]+", answers) or len(answers) != len(checks):
                    raise ReleaseError(f"give one y or n per check ({len(checks)}), in order")
                record["browser_checks"] = [{"check": check, "passed": answer == "y", "note": note if answer == "n" else "",
                                             "answered": "relayed by the operator"} for check, answer in zip(checks, answers)]
            self.conclude(inputs, record, waiting)

    def conclude(self, inputs, record, waiting):
        waived = bool(record["browser_checks"]) and all(check.get("waived") for check in record["browser_checks"])
        passed = waived or all(check["passed"] for check in record["browser_checks"])
        record.update(status="accepted" if passed else "rejected", ended_at=stamp())
        if waived:
            record["acceptance"] = "browser checks waived by the owner"
        inputs["awaiting_acceptance"] = None
        restores = waiting.get("restores")
        if passed and restores:
            same = inputs.get("accepted") and inputs["accepted"]["release_id"] == restores["release_id"]
            inputs["previous_accepted"] = inputs["previous_accepted"] if same else None
            inputs["accepted"] = restores
        elif passed:
            meta = {"source_sha": waiting["source_sha"], "migration_heads": waiting["migration_heads"],
                    "migration_catalog_sha256": waiting.get("migration_catalog_sha256")}
            if waived:
                meta["browser_checks"] = "waived"
            if waiting.get("frontend"):
                meta["frontend"] = waiting["frontend"]
            inputs["previous_accepted"] = inputs.get("accepted")
            inputs["accepted"] = {"release_id": record["release_id"], "runtime_image_digest": waiting["runtime_image_digest"], **meta}
        self.save(inputs, record)
        if passed:
            how = " with its browser checks waived" if waived else ""
            self.lab.log(f"{record['kind'].capitalize()} {record['release_id']} accepted{how}.")
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
        # Sample current health again: earlier healthy observations cannot certify the bake's end.
        current = self.lab.settled_services({role: arns[role] for role in SERVICES})
        for role in SERVICES:
            checks[f"{role} settled after bake"] = {"passed": service_settled(current[role], arns[role]),
                                                      "detail": current[role].get("runningCount")}
        states = self.lab.target_states()
        checks["api targets healthy after bake"] = {"passed": bool(states) and set(states) == {"healthy"},
                                                   "detail": ",".join(states)}
        for path, expected in (("/api/auth/csrf", 200), ("/api/me", 401)):
            status = self.lab.http_status(path)
            checks[f"GET {path} {expected} after bake"] = {"passed": status == expected, "detail": str(status)}
        for role in SERVICES:
            passed, detail = fatal_check(self.lab.log_messages(role, settled_at, FATAL_FILTER))
            checks[f"{role} defined failures"] = {"passed": passed, "detail": detail}
        passed, detail = progress_check(self.lab.log_messages("worker", settled_at, PROGRESS_FILTER), progress_required)
        checks["worker progress"] = {"passed": passed, "detail": detail}
        passed, detail = schema_state_check(self.lab.log_messages("worker", settled_at, SCHEMA_FILTER),
                                            record["candidate"]["migration_heads"]["tenant"], progress_required)
        checks["worker schema state"] = {"passed": passed, "detail": detail}
        passed, detail = smoke_check(self.lab.signed_in_smoke())
        checks["signed-in smoke"] = {"passed": passed, "detail": detail}
        for name, check in checks.items():
            self.lab.log(f"  {'ok  ' if check['passed'] else 'FAIL'} {name}: {check['detail']}")
        return checks


class AwsLab(PublicationSource, Frontend):
    """The real lab: AWS CLI, Terraform and GitHub CLI calls."""

    def __init__(self, profile, terraform):
        # An empty profile uses the ambient credentials: a GitHub runner's short-lived OIDC session.
        self.profile, self.terraform = profile, terraform
        self.workspace = tempfile.TemporaryDirectory(prefix="scoutgrid-release.")
        self.work = Path(self.workspace.name)
        os.chmod(self.work, 0o700)
        self.initialised = False

    def close(self):
        self.workspace.cleanup()

    # ---- process helpers ----------------------------------------------------------------
    def log(self, message):
        print(f"{utc_now().strftime('%H:%M:%SZ')} {message}", file=sys.stderr)

    def run(self, command, env=None, capture=True, cwd=None):
        result = subprocess.run(command, env=env, text=True, capture_output=capture, cwd=cwd)
        if result.returncode != 0:
            raise ReleaseError(f"{command[0]} {command[1] if len(command) > 1 else ''} failed: "
                               f"{(result.stderr or '').strip()[-600:]}")
        return result.stdout

    def aws_command(self, *args):
        return ["aws", *(["--profile", self.profile] if self.profile else []), "--region", REGION, *args]

    def aws(self, *args):
        output = self.run(self.aws_command("--output", "json", *args))
        return json.loads(output) if output.strip() else None

    def credentials_env(self):
        """Terraform's environment: the profile's exported credentials, or the ambient ones. Never the Vercel token."""
        env = {key: value for key, value in os.environ.items()
               if key != "VERCEL_TOKEN" and not (self.profile and key.startswith("AWS_"))}
        if self.profile:
            exported = json.loads(self.run(["aws", "configure", "export-credentials", "--profile", self.profile,
                                            "--format", "process"]))
            env.update(AWS_ACCESS_KEY_ID=exported["AccessKeyId"], AWS_SECRET_ACCESS_KEY=exported["SecretAccessKey"],
                       AWS_SESSION_TOKEN=exported.get("SessionToken", ""))
        env["AWS_REGION"] = REGION
        return env

    def tf(self, *args):
        return self.run([self.terraform, f"-chdir={TF_ROOT}", *args], env=self.credentials_env())

    def guard(self):
        account = self.aws("sts", "get-caller-identity")["Account"]
        if account != ACCOUNT_ID:
            source = f"profile {self.profile}" if self.profile else "the ambient credentials"
            raise ReleaseError(f"{source} is account {account}, not the lab {ACCOUNT_ID}")
        version = json.loads(self.run([self.terraform, "version", "-json"]))["terraform_version"]
        if version != TF_REQUIRED:
            raise ReleaseError(f"Terraform {TF_REQUIRED} wrote the lab state; found {version}")

    # ---- S3 release objects -------------------------------------------------------------
    def s3_get(self, key):
        target = self.work / "get.json"
        result = subprocess.run(self.aws_command("s3api", "get-object", "--bucket", STATE_BUCKET, "--key", key,
                                                 "--expected-bucket-owner", ACCOUNT_ID, str(target)),
                                text=True, capture_output=True)
        if result.returncode != 0:
            if "NoSuchKey" in result.stderr:
                return None
            raise ReleaseError(f"reading s3://{STATE_BUCKET}/{key} failed: {result.stderr.strip()[-400:]}")
        return json.loads(target.read_text())

    def s3_put(self, key, data, create_only=False):
        body = self.work / "put.json"
        body.write_text(json.dumps(data, indent=1, sort_keys=True) + "\n")
        command = self.aws_command("s3api", "put-object", "--bucket", STATE_BUCKET, "--key", key,
                                   "--expected-bucket-owner", ACCOUNT_ID, "--body", str(body),
                                   "--content-type", "application/json",
                                   "--server-side-encryption", "aws:kms", "--ssekms-key-id", STATE_KMS_KEY)
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
        runtime = self.work / "runtime.tfvars.json"
        runtime.write_text(json.dumps(runtime_config("running", CFG)))
        plan = self.work / f"{phase}.tfplan"
        self.tf("plan", "-input=false", "-no-color", "-lock-timeout=60s", f"-out={plan}",
                f"-var-file={CFG / 'sydney-lab.foundation.tfvars'}", f"-var-file={runtime}",
                f"-var-file={variables}", *[f"-target={target}" for target in targets])
        return plan, json.loads(self.tf("show", "-json", str(plan)))

    def apply(self, plan):
        self.log("Applying the checked plan.")
        self.tf("apply", "-input=false", "-no-color", "-lock-timeout=60s", str(plan))

    def outputs(self):
        outputs = json.loads(self.tf("output", "-json", "backend_runtime"))
        outputs["task_definition_arns"] = task_definition_arns(json.loads(self.tf("show", "-json")))
        return outputs

    def run_migrator(self, outputs, client_token):
        network = {"awsvpcConfiguration": {"subnets": outputs["task_subnet_ids"], "assignPublicIp": "DISABLED",
                                           "securityGroups": [outputs["migrator_security_group_id"]]}}
        started = self.aws("ecs", "run-task", "--cluster", CLUSTER, "--launch-type", "FARGATE", "--platform-version", "1.4.0",
                           "--count", "1", "--client-token", client_token, "--task-definition", outputs["task_definition_arns"]["migrator"],
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

    def signed_in_smoke(self):
        """Run the signed-in smoke without AWS credentials; None when it is not configured."""
        config = os.environ.get("LAB_SMOKE_CONFIG")
        if not config:
            return None
        env = {key: value for key, value in os.environ.items() if not key.startswith("AWS_")}
        try:
            result = subprocess.run(["node", str(SMOKE_SCRIPT), "--config", config], env=env, text=True,
                                    capture_output=True, timeout=SMOKE_TIMEOUT_SECONDS, cwd=SMOKE_SCRIPT.parents[1])
            return json.loads(result.stdout)
        except (subprocess.TimeoutExpired, json.JSONDecodeError, OSError) as error:
            return {"passed": False, "checks": [{"name": "smoke run", "ok": False, "detail": type(error).__name__}]}

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


def reconcile_succeeded(result):
    """reconcile exits 0 when the lab verified, or when it refused for a planned reason and changed nothing."""
    return result["outcome"] == "verified" or (result["outcome"] == "blocked" and result["reason"] in RECONCILE_BLOCKED)


def main(argv):
    lab = AwsLab(os.environ.get("LAB_RELEASE_PROFILE", "sglab-release"), os.environ.get("TERRAFORM", "terraform"))
    release = Release(lab)
    command, args = (argv[0], argv[1:]) if argv else ("", [])
    deploy_options = parse_options(args[1:], flags=("--frontend", "--no-progress-signal")) \
        if args and not args[0].startswith("--") else None
    rollback_options = parse_options(args, flags=("--no-progress-signal",), valued=("--note",))
    reconcile_options = parse_options(args, flags=("--frontend", "--yes"))
    try:
        if command == "status" and not args:
            lab.guard()
            release.status()
        elif command == "init" and len(args) == 3:
            lab.guard()
            release.init(args[0], int(args[1]), int(args[2]))
        elif command == "deploy" and deploy_options is not None:
            lab.guard()
            print(json.dumps(release.deploy(args[0], progress_required="--no-progress-signal" not in deploy_options,
                                            frontend="--frontend" in deploy_options), indent=2))
        elif command == "reconcile" and reconcile_options is not None:
            lab.guard()
            result = release.reconcile(frontend="--frontend" in reconcile_options, assume_yes="--yes" in reconcile_options)
            print(json.dumps(result, indent=2))
            return 0 if reconcile_succeeded(result) else 1
        elif command == "check" and len(args) == 1:
            lab.guard()
            release.check(args[0])
        elif command == "rollback" and rollback_options is not None:
            lab.guard()
            print(json.dumps(release.rollback(progress_required="--no-progress-signal" not in rollback_options,
                                              note=rollback_options.get("--note", "")), indent=2))
        elif command == "adopt-frontend" and not args:
            lab.guard()
            release.adopt_frontend()
        elif command == "accept" and not args:
            lab.guard()
            release.accept()
        elif command == "accept" and len(args) in (2, 4) and args[0] == "--answers" and (len(args) == 2 or args[2] == "--note"):
            lab.guard()
            release.accept(args[1], args[3] if len(args) == 4 else "")
        elif command == "accept" and len(args) == 3 and args[0] == "--waive" and args[1] == "--note":
            lab.guard()
            release.accept(note=args[2], waive=True)
        elif command == "unlock" and not args:
            lab.guard()
            release.unlock()
        else:
            print(__doc__.split("\n\n", 2)[1], file=sys.stderr)
            return 2
    except ReleaseError as error:
        lab.log(f"ERROR: {error}")
        if command in ("deploy", "rollback", "reconcile"):
            print(json.dumps({"outcome": error.outcome, "reason": error.reason, "error": str(error)}, indent=2))
        return 1
    except ValueError as error:
        lab.log(f"ERROR: {error}")
        return 2
    finally:
        lab.close()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
