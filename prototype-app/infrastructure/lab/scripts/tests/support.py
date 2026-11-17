"""Offline lab fixtures shared by release and CI hardening tests."""
import copy

import datetime
import importlib.util
import json
from pathlib import Path

spec = importlib.util.spec_from_file_location("release", Path(__file__).resolve().parents[1] / "release.py")
release = importlib.util.module_from_spec(spec)
spec.loader.exec_module(release)

OLD_SHA, NEW_SHA = "0" * 40, "e" * 40
OLD, NEW = "sha256:" + "0" * 64, "sha256:" + "e" * 64
V20, V23 = {"platform": 15, "tenant": 20}, {"platform": 16, "tenant": 23}
CATALOG, OTHER_CATALOG = "c" * 64, "d" * 64
ARNS = {role: f"arn:aws:ecs:ap-southeast-2:736486260824:task-definition/scoutgrid-lab-{role}:9" for role in ("api", "worker", "migrator")}
LIVE_FRONTEND, STAGED_FRONTEND = "dpl_live", "dpl_staged"


def inputs(heads=V23, digest=OLD, sha=OLD_SHA, previous=None, pending=None, catalog=CATALOG):
    meta = {"source_sha": sha, "migration_heads": heads}
    return {"schema": 1, "runtime_image_digest": digest, "migrator_image_digest": digest, "runtime": meta, "migrator": meta,
            "database_heads": heads, "database_catalog_sha256": catalog, "accepted": {"release_id": "baseline", "runtime_image_digest": digest, **meta},
            "previous_accepted": previous, "pending": pending, "last_release": None}


def publication(heads=V23, digest=NEW, sha=NEW_SHA, catalog=CATALOG):
    return {"source_sha": sha, "target": "lab", "aws_region": "ap-southeast-2", "image_digest": digest,
            "migration_catalog_sha256": catalog,
            "ecr_image": f"{release.REGISTRY}/{release.ECR_REPOSITORY}@{digest}", "migration_heads": heads,
            "candidate_run": "43633506061"}


def plan(*changes):
    return {"resource_changes": [{"address": address, "change": {"actions": list(actions)}} for address, actions in changes]}


DEFAULT_PLANS = {
    "migrator": plan((release.TASK.format("migrator"), ("delete", "create"))),
    "runtime": plan(*[(release.TASK.format(role), ("delete", "create")) for role in release.SERVICES],
                    *[(release.SERVICE.format(role), ("update",)) for role in release.SERVICES]),
    "migrator-drift": plan(),
}


READY_SCHEMA = ["message=tenant_schema_state unready_tenants=0 supported=23..23 active_versions=23..23 packaged_target=23"]
HEALTHY_PROGRESS = ["2026-11-15T07:01:30.000Z level=INFO message=tenant_work_progress outcome=healthy succeeded=42 failed=0"]


def stopped_task(exit_code=0, stop_code="EssentialContainerExited"):
    return {"lastStatus": "STOPPED", "stopCode": stop_code, "stoppedReason": "done", "containers": [{"exitCode": exit_code}]}


class FakeLab:
    def __init__(self, store_inputs=None, pub=None, migrator=None, plans=None, browser_ok=True, confirmed=True,
                 present=True, live=None, unpublished=False):
        self.store = {} if store_inputs is None else {release.INPUTS_KEY: copy.deepcopy(store_inputs)}
        self.pub = None if unpublished else (pub or publication())
        self.migrator = migrator or stopped_task()
        self.plans = {**DEFAULT_PLANS, **(plans or {})}
        self.browser_ok, self.confirmed, self.present = browser_ok, confirmed, present
        self.live = live or {"api": OLD, "worker": OLD, "migrator": OLD}
        self.calls = []
        self.baked = []
        self.queried = []
        self.smoke = {"passed": True, "checks": [{"name": "platform write: reject a demo request", "ok": True, "detail": ""}]}
        self.logs = {("api", release.FATAL_FILTER): [], ("worker", release.FATAL_FILTER): [],
                     ("worker", release.PROGRESS_FILTER): list(HEALTHY_PROGRESS),
                     ("worker", release.SCHEMA_FILTER): list(READY_SCHEMA)}

    def log(self, message):
        pass

    def s3_get(self, key):
        return copy.deepcopy(self.store.get(key))

    def s3_put(self, key, data, create_only=False):
        if create_only and key in self.store:
            return False
        self.store[key] = copy.deepcopy(data)
        return True

    def s3_delete(self, key):
        self.store.pop(key, None)

    head, clean = NEW_SHA, True

    def resolve_sha(self, ref):
        return NEW_SHA

    def publication(self, sha, required=True):
        if self.pub is None and required:
            raise release.ReleaseError(f"{sha[:7]} has no lab publication record")
        return copy.deepcopy(self.pub)

    def checkout(self):
        return self.head, self.clean

    def ecr_has(self, digest):
        return True

    def services_present(self):
        return self.present

    def live_images(self):
        return dict(self.live)

    def confirm(self, question):
        self.calls.append("confirm")
        return self.confirmed

    def stop_services(self):
        self.calls.append("stop")

    def snapshot(self, identifier, release_id):
        self.calls.append("snapshot")
        return identifier

    def plan(self, phase, images, targets):
        self.calls.append(("plan", phase, images["runtime"], images["migrator"]))
        assert targets == release.TARGETS["migrator" if phase == "migrator-drift" else phase]
        return f"{phase}.tfplan", self.plans[phase]

    def apply(self, plan_file):
        self.calls.append(("apply", plan_file))

    def outputs(self):
        return {"task_definition_arns": ARNS, "task_subnet_ids": ["subnet-a"], "migrator_security_group_id": "sg-m"}

    def run_migrator(self, outputs, client_token):
        self.calls.append("migrate")
        return "arn:aws:ecs:ap-southeast-2:736486260824:task/scoutgrid-lab/1"

    def wait_task(self, task):
        return self.migrator

    def settled_services(self, arns):
        return {role: {"deployments": [{"taskDefinition": arn, "rolloutState": "COMPLETED"}], "desiredCount": 1,
                       "runningCount": 1} for role, arn in arns.items()}

    def target_states(self):
        return ["healthy"]

    def http_status(self, path):
        return {"/api/auth/csrf": 200, "/api/me": 401}[path]

    def startup_errors(self, since):
        return {"api": 0, "worker": 0}

    def wait_until(self, moment):
        self.baked.append(moment)

    def signed_in_smoke(self):
        return self.smoke

    def log_messages(self, role, since, pattern):
        self.queried.append((role, since, pattern))
        return list(self.logs[(role, pattern)])

    def browser_checks(self, checks):
        self.calls.append("browser")
        return [{"check": check, "passed": self.browser_ok, "note": ""} for check in checks]

    # ---- the frontend: a fake Vercel project whose domain serves self.alias ----------------
    alias = LIVE_FRONTEND
    staged_id = STAGED_FRONTEND
    stage_error = promote_error = None
    promote_moves_alias = True
    app_code = 200

    def frontend_stage(self, sha):
        self.calls.append(("stage", release.LOCK_KEY in self.store))
        if self.stage_error:
            raise release.ReleaseError(self.stage_error)
        return {"deployment_id": self.staged_id, "url": "scout-frontend-new.vercel.app", "source_sha": sha,
                "staged_at": "2026-11-16T07:00:00Z"}

    def frontend_live(self, required=True):
        return self.alias

    def frontend_deployment(self, deployment):
        return {"deployment_id": deployment, "url": "scout-frontend-live.vercel.app", "ready_state": "READY",
                "target": "production", "source_sha": OLD_SHA}

    def frontend_promote(self, deployment):
        self.calls.append(("promote", deployment))
        if self.promote_moves_alias:
            self.alias = deployment
        if self.promote_error:
            raise release.ReleaseError(self.promote_error)

    def app_status(self, path):
        return self.app_code

    @property
    def inputs(self):
        return self.store[release.INPUTS_KEY]

    def record(self):
        return next(value for key, value in self.store.items() if key.startswith(release.RECORDS))
