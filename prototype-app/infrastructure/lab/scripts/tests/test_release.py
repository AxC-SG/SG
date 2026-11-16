"""Offline tests for release.py: a fake lab replaces AWS, Terraform and GitHub.

    python3 prototype-app/infrastructure/lab/scripts/tests/test_release.py
"""
import copy
import datetime
import importlib.util
import re
import unittest
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
                 present=True, live=None):
        self.store = {} if store_inputs is None else {release.INPUTS_KEY: copy.deepcopy(store_inputs)}
        self.pub = pub or publication()
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

    def resolve_sha(self, ref):
        return NEW_SHA

    def publication(self, sha):
        return copy.deepcopy(self.pub)

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

    def run_migrator(self, outputs):
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


class PureTest(unittest.TestCase):
    def test_smoke_check_needs_reported_passing_checks(self):
        self.assertFalse(release.smoke_check({"passed": True, "checks": []})[0])
        self.assertFalse(release.smoke_check({"passed": True, "checks": [{"name": "x", "ok": False, "detail": "d"}]})[0])
        self.assertTrue(release.smoke_check({"passed": True, "checks": [{"name": "x", "ok": True}]})[0])

    def test_progress_check(self):
        line = "message=tenant_work_progress outcome={} succeeded=1 failed=0".format
        self.assertTrue(release.progress_check([line("healthy"), line("degraded")])[0])
        self.assertFalse(release.progress_check([line("idle"), line("idle")])[0])
        self.assertFalse(release.progress_check([line("healthy"), line("failing")])[0])
        self.assertFalse(release.progress_check(["unrelated"])[0])
        self.assertTrue(release.progress_check([], required=False)[0])

    def test_fatal_patterns_match_the_release_alarm_filter(self):
        terraform = (release.TF_ROOT / "release-alarms.tf").read_text()
        block = terraform[terraform.index("release_fatal_pattern = join"):terraform.index("release_log_metrics")]
        self.assertEqual(re.findall(r'\?\\"([^\\]+)\\"', block), list(release.FATAL_PATTERNS))

    def test_schema_mode(self):
        self.assertEqual(release.schema_mode(V23, V23), "neutral")
        self.assertEqual(release.schema_mode(V20, V23), "forward")
        for older in ({"platform": 16, "tenant": 22}, {"platform": 15, "tenant": 23}):
            with self.assertRaisesRegex(release.ReleaseError, "behind the database"):
                release.schema_mode(V23, older)
        for bad in ({"platform": 16}, {"platform": "16", "tenant": 23}, {"platform": True, "tenant": 23}, None):
            with self.assertRaisesRegex(release.ReleaseError, "positive"):
                release.schema_mode(V23, bad)

    def test_each_plan_may_change_only_its_own_resources(self):
        for phase in ("migrator", "runtime"):
            self.assertEqual(release.check_plan(DEFAULT_PLANS[phase], phase)[1], [])
        self.assertEqual(release.check_plan(plan(("aws_db_instance.standard", ("no-op",))), "runtime"), ([], []))
        cases = [
            ("migrator", (release.TASK.format("api"), ("delete", "create"))),
            ("migrator", (release.SERVICE.format("api"), ("update",))),
            ("runtime", (release.TASK.format("migrator"), ("delete", "create"))),
            ("runtime", (release.SERVICE.format("api"), ("delete",))),
            ("runtime", ("aws_iam_role.execution[\"api\"]", ("update",))),
            ("runtime", ("aws_lb.api[\"standard\"]", ("delete", "create"))),
        ]
        for phase, change in cases:
            self.assertEqual(len(release.check_plan(plan(change), phase)[1]), 1, (phase, change))

    def test_publication_must_be_the_lab_image_for_this_commit(self):
        release.check_publication(publication(), NEW_SHA)
        for change, message in [({"source_sha": OLD_SHA}, "is not"), ({"target": "production"}, "not lab"),
                                ({"image_digest": "latest"}, "digest"),
                                ({"ecr_image": "other.example/repo@" + NEW}, "is not in"),
                                ({"migration_heads": None}, "heads")]:
            with self.assertRaisesRegex(release.ReleaseError, message):
                release.check_publication({**publication(), **change}, NEW_SHA)

    def test_migrator_outcome(self):
        self.assertIsNone(release.migrator_outcome({"lastStatus": "RUNNING", "containers": [{}]}))
        self.assertTrue(release.migrator_outcome(stopped_task())[0])
        self.assertFalse(release.migrator_outcome(stopped_task(exit_code=1))[0])
        self.assertFalse(release.migrator_outcome(stopped_task(stop_code="TaskFailedToStart"))[0])

    def test_service_settled(self):
        good = {"deployments": [{"taskDefinition": "a", "rolloutState": "COMPLETED"}], "desiredCount": 1, "runningCount": 1}
        self.assertTrue(release.service_settled(good, "a"))
        self.assertFalse(release.service_settled(good, "b"))
        self.assertFalse(release.service_settled({**good, "runningCount": 0}, "a"))
        self.assertFalse(release.service_settled({**good, "desiredCount": 0, "runningCount": 0}, "a"))
        self.assertFalse(release.service_settled({**good, "deployments": good["deployments"] * 2}, "a"))
        self.assertFalse(release.service_settled({**good, "deployments": [{"taskDefinition": "a", "rolloutState": "FAILED"}]}, "a"))

    def test_release_ids_are_valid_snapshot_names(self):
        rid = release.release_id(NEW_SHA, datetime.datetime(2026, 11, 15, 3, 4, 5, tzinfo=datetime.timezone.utc))
        self.assertEqual(rid, "20261115t030405z-eeeeeee")
        self.assertRegex(f"scoutgrid-lab-release-{rid}", r"^[a-z][a-z0-9]*(-[a-z0-9]+)*$")

    def test_task_definition_arns_come_from_state_not_stale_outputs(self):
        state = {"values": {"outputs": {"backend_runtime": {"value": {"task_definition_arns": {"migrator": "old:2"}}}},
                            "root_module": {"resources": [
                                {"type": "aws_ecs_task_definition", "name": "backend", "index": role, "values": {"arn": arn}}
                                for role, arn in ARNS.items()] + [
                                {"type": "aws_ecs_service", "name": "backend", "index": "api", "values": {"arn": "svc"}}]}}}
        self.assertEqual(release.task_definition_arns(state), ARNS)

    def test_rollback_target(self):
        state = inputs(previous={"release_id": "older", "runtime_image_digest": NEW})
        self.assertEqual(release.rollback_target(state)["release_id"], "older")
        self.assertEqual(release.rollback_target({**state, "runtime_image_digest": NEW})["release_id"], "baseline")
        self.assertEqual(release.rollback_target({**state, "pending": {"phase": "stopped"}})["release_id"], "baseline")
        self.assertIsNone(release.rollback_target(inputs()))


class DeployTest(unittest.TestCase):
    def deploy(self, lab):
        release.Release(lab).deploy("main")

    def test_neutral_release_moves_migrator_then_runtime_and_waits_for_acceptance(self):
        lab = FakeLab(inputs())
        self.deploy(lab)
        self.assertEqual(lab.calls, [
            "confirm", ("plan", "migrator", OLD, NEW), ("apply", "migrator.tfplan"), "migrate",
            ("plan", "runtime", NEW, NEW), ("apply", "runtime.tfplan")])
        state = lab.inputs
        self.assertEqual((state["runtime_image_digest"], state["migrator_image_digest"]), (NEW, NEW))
        self.assertIsNone(state["pending"])
        self.assertEqual(state["awaiting_acceptance"]["release_id"], lab.record()["release_id"])
        self.assertEqual(state["accepted"]["release_id"], "baseline")
        self.assertEqual(lab.record()["status"], "verified")
        self.assertEqual([step["step"] for step in lab.record()["steps"]], ["migrator", "migrated", "runtime", "verified"])
        self.assertNotIn(release.LOCK_KEY, lab.store)

        release.Release(lab).accept()
        state = lab.inputs
        self.assertEqual(lab.calls[-1], "browser")
        self.assertEqual(state["accepted"]["runtime_image_digest"], NEW)
        self.assertEqual(state["previous_accepted"]["release_id"], "baseline")
        self.assertIsNone(state["awaiting_acceptance"])
        self.assertEqual(lab.record()["status"], "accepted")
        self.assertNotIn(release.LOCK_KEY, lab.store)

    def test_schema_change_stops_and_snapshots_before_migrating(self):
        lab = FakeLab(inputs(heads=V20))
        self.deploy(lab)
        self.assertEqual(lab.calls[:4], ["confirm", "stop", "snapshot", ("plan", "migrator", OLD, NEW)])
        self.assertEqual(lab.inputs["database_heads"], V23)
        self.assertEqual(lab.record()["mode"], "forward")
        self.assertTrue(lab.record()["steps"][1]["snapshot"].startswith("scoutgrid-lab-release-"))

    def test_failed_migrator_leaves_api_and_worker_and_marks_the_release_pending(self):
        lab = FakeLab(inputs(heads=V20), migrator=stopped_task(exit_code=1))
        with self.assertRaisesRegex(release.ReleaseError, "failed at migrate"):
            self.deploy(lab)
        self.assertNotIn(("plan", "runtime", NEW, NEW), lab.calls)
        state = lab.inputs
        self.assertEqual((state["runtime_image_digest"], state["database_heads"]), (OLD, V20))
        self.assertEqual(state["pending"]["phase"], "migrator")
        self.assertEqual((lab.record()["status"], lab.record()["failed_at"]), ("failed", "migrate"))
        self.assertNotIn(release.LOCK_KEY, lab.store)

    def test_a_plan_outside_its_step_is_never_applied(self):
        lab = FakeLab(inputs(), plans={"runtime": plan(("aws_lb.api[\"standard\"]", ("delete", "create")))})
        with self.assertRaisesRegex(release.ReleaseError, "outside its step"):
            self.deploy(lab)
        self.assertNotIn(("apply", "runtime.tfplan"), lab.calls)
        self.assertEqual(lab.inputs["runtime_image_digest"], OLD)

    def test_failed_automated_check_keeps_the_release_pending(self):
        lab = FakeLab(inputs())
        lab.http_status = lambda path: 503
        with self.assertRaisesRegex(release.ReleaseError, "automated checks failed"):
            self.deploy(lab)
        self.assertEqual(lab.inputs["pending"]["phase"], "runtime")
        self.assertIsNone(lab.inputs.get("awaiting_acceptance"))

    def test_verify_bakes_one_scheduler_cycle_after_the_services_settle(self):
        lab = FakeLab(inputs())
        self.deploy(lab)
        [bake_end] = lab.baked
        settled = min(since for _, since, pattern in lab.queried if pattern == release.FATAL_FILTER)
        self.assertGreaterEqual((bake_end - settled).total_seconds(), 5 * 60 + 60)
        checks = lab.record()["checks"]
        self.assertTrue(all(checks[name]["passed"] for name in ("api defined failures", "worker defined failures", "worker progress")))
        self.assertIn("bake", lab.record())

    def test_a_defined_failure_during_the_bake_fails_the_release(self):
        for role, line in (("worker", "WARN message=Tenant-scoped background work failed for tenant t: Tenant schema is "
                                      "outside this release's supported range V23..V20: tenant_x (current=V23)"),
                           ("api", "ERROR message=Unhandled API error org.springframework.orm.jpa.JpaSystemException: "
                                   "new row violates row-level security policy for table \"audit_events\"")):
            with self.subTest(role=role):
                lab = FakeLab(inputs())
                lab.logs[(role, release.FATAL_FILTER)] = [line]
                with self.assertRaisesRegex(release.ReleaseError, f"{role} defined failures"):
                    self.deploy(lab)
                self.assertEqual(lab.inputs["pending"]["phase"], "runtime")
                self.assertIsNone(lab.inputs.get("awaiting_acceptance"))

    def test_a_running_worker_whose_tenant_work_fails_fails_the_release(self):
        lab = FakeLab(inputs())
        lab.logs[("worker", release.PROGRESS_FILTER)] = [
            "message=tenant_work_progress outcome=failing succeeded=0 failed=12"]
        with self.assertRaisesRegex(release.ReleaseError, "worker progress"):
            self.deploy(lab)

    def test_missing_progress_fails_unless_the_operator_records_an_older_image(self):
        lab = FakeLab(inputs())
        lab.logs[("worker", release.PROGRESS_FILTER)] = []
        with self.assertRaisesRegex(release.ReleaseError, "worker progress"):
            self.deploy(lab)
        lab = FakeLab(inputs())
        lab.logs[("worker", release.PROGRESS_FILTER)] = []
        release.Release(lab).deploy("main", progress_required=False)
        self.assertIn("predates the signal", lab.record()["checks"]["worker progress"]["detail"])
        self.assertEqual(lab.record()["status"], "verified")

    def test_equal_heads_with_a_changed_catalog_change_nothing(self):
        lab = FakeLab(inputs(), pub=publication(catalog=OTHER_CATALOG))
        with self.assertRaisesRegex(release.ReleaseError, "migration catalog differs"):
            self.deploy(lab)
        self.assertEqual(lab.calls, [])
        self.assertIsNone(lab.inputs["pending"])

    def test_an_unknown_catalog_is_recorded_as_unverified(self):
        lab = FakeLab(inputs(catalog=None))
        self.deploy(lab)
        self.assertEqual(lab.record()["catalog"], "unverified")

    def test_migrating_records_the_catalog_the_database_ran(self):
        lab = FakeLab(inputs(heads=V20, catalog=None), pub=publication(heads=V23, catalog=OTHER_CATALOG))
        lab.logs[("worker", release.SCHEMA_FILTER)] = [
            "message=tenant_schema_state unready_tenants=0 supported=20..20 active_versions=20..20 packaged_target=20"]
        lab.logs[("worker", release.SCHEMA_FILTER)].append(READY_SCHEMA[0])
        self.deploy(lab)
        self.assertEqual(lab.inputs["database_catalog_sha256"], OTHER_CATALOG)
        release.Release(lab).accept()
        self.assertEqual(lab.inputs["accepted"]["migration_catalog_sha256"], OTHER_CATALOG)

    def test_unready_tenants_block_a_neutral_release_before_any_change(self):
        lab = FakeLab(inputs())
        lab.logs[("worker", release.SCHEMA_FILTER)] = [
            "message=tenant_schema_state unready_tenants=1 supported=23..23 active_versions=22..23 packaged_target=23"]
        with self.assertRaisesRegex(release.ReleaseError, "schema state is not ready"):
            self.deploy(lab)
        self.assertEqual(lab.calls, [])

    def test_a_supported_range_without_the_database_head_fails_the_bake(self):
        # The 2026-11-15 failure: the binary ran with a configured maximum below the database head.
        lab = FakeLab(inputs())
        lab.logs[("worker", release.SCHEMA_FILTER)] = []
        lab.log_messages = lambda role, since, pattern, original=lab.log_messages: (
            ["message=tenant_schema_state unready_tenants=0 supported=23..20 active_versions=23..23 packaged_target=23"]
            if pattern == release.SCHEMA_FILTER and since > release.utc_now() - datetime.timedelta(minutes=1)
            else original(role, since, pattern))
        with self.assertRaisesRegex(release.ReleaseError, "worker schema state"):
            self.deploy(lab)
        self.assertIn("V23..V20", lab.record()["checks"]["worker schema state"]["detail"])

    def test_check_reports_an_eligible_runtime_only_release(self):
        lab = FakeLab(inputs(), pub=publication())
        result = release.Release(lab).check("main")
        self.assertEqual((result["outcome"], result["reasons"]), ("eligible", []))
        self.assertEqual(lab.calls, [("plan", "migrator-drift", OLD, OLD)])
        self.assertEqual(lab.inputs, inputs())

    def test_check_blocks_with_each_reason(self):
        cases = {
            "schema_changed": dict(pub=publication(heads={"platform": 16, "tenant": 24})),
            "schema_unverified": dict(pub=publication(catalog=None)),
            "migrator_drift": dict(plans={"migrator-drift": plan((release.TASK.format("migrator"), ("delete", "create")))}),
            "parked": dict(present=False),
            "awaiting_acceptance": dict(store_inputs={**inputs(), "awaiting_acceptance": {"release_id": "r1"}}),
        }
        for reason, options in cases.items():
            with self.subTest(reason=reason):
                lab = FakeLab(options.pop("store_inputs", inputs()), **options)
                result = release.Release(lab).check("main")
                self.assertEqual(result["outcome"], "blocked")
                self.assertTrue(any(item.startswith(reason) for item in result["reasons"]), result["reasons"])
                self.assertNotIn(("apply", "migrator-drift.tfplan"), lab.calls)

    def test_check_needs_live_schema_evidence(self):
        lab = FakeLab(inputs())
        lab.logs[("worker", release.SCHEMA_FILTER)] = []
        result = release.Release(lab).check("main")
        self.assertTrue(any(item.startswith("schema_unverified") for item in result["reasons"]))

    def test_a_failed_signed_in_write_fails_the_release(self):
        lab = FakeLab(inputs())
        lab.smoke = {"passed": False, "checks": [
            {"name": "platform write: reject a demo request", "ok": False, "detail": "status 500"}]}
        with self.assertRaisesRegex(release.ReleaseError, "signed-in smoke"):
            self.deploy(lab)
        self.assertIn("status 500", lab.record()["checks"]["signed-in smoke"]["detail"])

    def test_an_unconfigured_smoke_is_recorded_as_a_detection_gap(self):
        lab = FakeLab(inputs())
        lab.smoke = None
        self.deploy(lab)
        self.assertIn("detection gap", lab.record()["checks"]["signed-in smoke"]["detail"])

    def test_rejected_browser_check_keeps_the_accepted_release(self):
        lab = FakeLab(inputs(), browser_ok=False)
        self.deploy(lab)
        release.Release(lab).accept()
        state = lab.inputs
        self.assertEqual(lab.record()["status"], "rejected")
        self.assertEqual((state["runtime_image_digest"], state["accepted"]["release_id"]), (NEW, "baseline"))
        self.assertIsNone(state["awaiting_acceptance"])
        self.assertEqual(release.rollback_target(state)["release_id"], "baseline")

    def test_relayed_answers_are_recorded_as_relayed(self):
        lab = FakeLab(inputs())
        self.deploy(lab)
        count = len(release.json.loads(release.BROWSER_CHECKS.read_text())["checks"])
        with self.assertRaisesRegex(release.ReleaseError, f"one y or n per check \\({count}\\)"):
            release.Release(lab).accept("y")
        release.Release(lab).accept("y" * (count - 1) + "n", "invite email did not arrive")
        checks = lab.record()["browser_checks"]
        self.assertEqual(lab.record()["status"], "rejected")
        self.assertTrue(all(check["answered"] == "relayed by the operator" for check in checks))
        self.assertEqual(checks[-1]["note"], "invite email did not arrive")
        self.assertNotIn("browser", lab.calls)

    def test_an_owner_waiver_accepts_without_claiming_the_checks_passed(self):
        lab = FakeLab(inputs(), browser_ok=False)
        self.deploy(lab)
        release.Release(lab).accept(note="owner deferred browser checks to a full-app test plan", waive=True)
        record, state = lab.record(), lab.inputs
        self.assertEqual(record["status"], "accepted")
        self.assertEqual(record["acceptance"], "browser checks waived by the owner")
        count = len(release.json.loads(release.BROWSER_CHECKS.read_text())["checks"])
        self.assertEqual(len(record["browser_checks"]), count)
        for check in record["browser_checks"]:
            self.assertIs(check["passed"], None)
            self.assertTrue(check["waived"])
            self.assertEqual(check["note"], "owner deferred browser checks to a full-app test plan")
        self.assertNotIn("browser", lab.calls)
        self.assertEqual((state["accepted"]["runtime_image_digest"], state["accepted"]["browser_checks"]), (NEW, "waived"))
        self.assertEqual(state["previous_accepted"]["release_id"], "baseline")
        self.assertIsNone(state["awaiting_acceptance"])
        # The waived release is accepted, so the next deploy may proceed and recovery can return to it.
        self.assertEqual(release.rollback_target(state)["release_id"], "baseline")

    def test_a_waiver_needs_a_note(self):
        lab = FakeLab(inputs())
        self.deploy(lab)
        for note in ("", "   "):
            with self.assertRaisesRegex(release.ReleaseError, "needs --note"):
                release.Release(lab).accept(note=note, waive=True)
        self.assertIsNotNone(lab.inputs["awaiting_acceptance"])

    def test_a_rejection_is_not_a_waiver(self):
        lab = FakeLab(inputs(), browser_ok=False)
        self.deploy(lab)
        release.Release(lab).accept()
        self.assertNotIn("acceptance", lab.record())
        self.assertNotIn("browser_checks", lab.inputs["accepted"])

    def test_accept_needs_a_waiting_release(self):
        with self.assertRaisesRegex(release.ReleaseError, "no release is waiting"):
            release.Release(FakeLab(inputs())).accept()

    def test_an_unaccepted_release_blocks_the_next_deploy(self):
        lab = FakeLab(inputs())
        self.deploy(lab)
        lab.calls = []
        with self.assertRaisesRegex(release.ReleaseError, "waiting for its browser checks"):
            self.deploy(lab)
        self.assertEqual(lab.calls, [])

    def test_rerunning_the_same_commit_resumes_after_finished_steps(self):
        lab = FakeLab(inputs(heads=V20), migrator=stopped_task(exit_code=1))
        with self.assertRaises(release.ReleaseError):
            self.deploy(lab)
        lab.migrator, lab.calls = stopped_task(), []
        self.deploy(lab)
        self.assertNotIn("stop", lab.calls)
        self.assertNotIn("snapshot", lab.calls)
        self.assertEqual(lab.record()["status"], "verified")
        self.assertEqual(lab.inputs["database_heads"], V23)

    def test_another_unfinished_release_blocks_a_new_commit(self):
        pending = {"release_id": "r1", "source_sha": OLD_SHA, "kind": "deploy", "phase": "migrator"}
        lab = FakeLab(inputs(pending=pending))
        with self.assertRaisesRegex(release.ReleaseError, "stopped after migrator"):
            self.deploy(lab)
        self.assertEqual(lab.calls, [])

    def test_refusals_change_nothing(self):
        cases = [
            (FakeLab(inputs(), pub=publication(heads={"platform": 16, "tenant": 22})), "behind the database"),
            (FakeLab(inputs(), present=False), "parked"),
            (FakeLab(inputs(), confirmed=False), "not confirmed"),
            (FakeLab(None), "no release inputs"),
            (FakeLab(inputs(), pub=publication(sha=OLD_SHA)), "publication record rejected"),
        ]
        for lab, message in cases:
            before = copy.deepcopy(lab.store)
            with self.assertRaisesRegex(release.ReleaseError, message):
                self.deploy(lab)
            self.assertEqual(lab.store, before, message)
            self.assertFalse([call for call in lab.calls if call != "confirm"], message)

    def test_a_held_lock_blocks_every_change(self):
        lab = FakeLab(inputs())
        lab.store[release.LOCK_KEY] = {"holder": "lab.sh", "operation": "up"}
        with self.assertRaisesRegex(release.ReleaseError, "locked"):
            self.deploy(lab)
        self.assertEqual(lab.calls, [])
        self.assertEqual(lab.store[release.LOCK_KEY]["holder"], "lab.sh")


class RollbackTest(unittest.TestCase):
    def deploy_and_accept(self, lab):
        release.Release(lab).deploy("main")
        release.Release(lab).accept()
        lab.calls = []

    def test_rollback_moves_only_api_and_worker_to_the_previous_release(self):
        lab = FakeLab(inputs())
        self.deploy_and_accept(lab)
        release.Release(lab).rollback()
        self.assertEqual(lab.calls, ["confirm", ("plan", "runtime", OLD, NEW), ("apply", "runtime.tfplan")])
        release.Release(lab).accept()
        state = lab.inputs
        self.assertEqual((state["runtime_image_digest"], state["migrator_image_digest"]), (OLD, NEW))
        self.assertEqual(state["accepted"]["release_id"], "baseline")
        self.assertIsNone(state["previous_accepted"])

    def test_rollback_of_an_unaccepted_release_rejects_it(self):
        lab = FakeLab(inputs())
        release.Release(lab).deploy("main")
        deployed = lab.inputs["awaiting_acceptance"]["release_id"]
        result = release.Release(lab).rollback()
        rejected = lab.store[f"{release.RECORDS}/{deployed}.json"]
        self.assertEqual(rejected["status"], "rejected")
        self.assertEqual(rejected["rolled_back"]["reason"], "recovered")
        self.assertEqual(lab.inputs["runtime_image_digest"], OLD)
        # The exact accepted release came back, so its acceptance stands (CD plan 4.7).
        self.assertIsNone(lab.inputs["awaiting_acceptance"])
        self.assertEqual((result["outcome"], result["acceptance"], result["replaces"]), ("verified", "reused", deployed))

    def test_rollback_after_a_failed_deploy_restores_the_accepted_release(self):
        lab = FakeLab(inputs(heads=V20), plans={"migrator": plan(("aws_lb.api[\"standard\"]", ("update",)))})
        lab.logs[("worker", release.SCHEMA_FILTER)] = [
            "message=tenant_schema_state unready_tenants=0 supported=20..20 active_versions=20..20 packaged_target=20"]
        with self.assertRaises(release.ReleaseError):
            release.Release(lab).deploy("main")
        self.assertEqual(lab.calls[:3], ["confirm", "stop", "snapshot"])
        lab.calls = []
        release.Release(lab).rollback()
        self.assertEqual(lab.calls[1], ("plan", "runtime", OLD, OLD))
        self.assertIsNone(lab.inputs["pending"])

    def test_rollback_across_a_schema_change_is_refused_with_the_snapshot(self):
        lab = FakeLab(inputs(heads=V20))
        self.deploy_and_accept(lab)
        with self.assertRaisesRegex(release.ReleaseError, "cannot run here.*scoutgrid-lab-release-"):
            release.Release(lab).rollback()
        self.assertEqual(lab.calls, [])

    def test_rollback_needs_an_earlier_release(self):
        with self.assertRaisesRegex(release.ReleaseError, "no earlier accepted release"):
            release.Release(FakeLab(inputs())).rollback()


def tracked(**options):
    """Inputs whose accepted release has the adopted live frontend."""
    state = inputs(**options)
    frontend = {"deployment_id": LIVE_FRONTEND, "url": "scout-frontend-live.vercel.app", "source_sha": OLD_SHA, "adopted": True}
    state["frontend"] = frontend
    state["accepted"]["frontend"] = frontend
    return state


BACKEND_CALLS = [("plan", "migrator", OLD, NEW), ("apply", "migrator.tfplan"), "migrate",
                 ("plan", "runtime", NEW, NEW), ("apply", "runtime.tfplan")]


class PairedReleaseTest(unittest.TestCase):
    def deploy(self, lab):
        return release.Release(lab).deploy("main", frontend=True)

    def test_the_frontend_is_staged_outside_the_lock_and_promoted_after_the_backend_verifies(self):
        lab = FakeLab(tracked())
        result = self.deploy(lab)
        self.assertEqual(lab.calls, [("stage", False), "confirm", *BACKEND_CALLS, ("promote", STAGED_FRONTEND)])
        record, state = lab.record(), lab.inputs
        self.assertEqual([step["step"] for step in record["steps"]],
                         ["migrator", "migrated", "runtime", "verified", "frontend", "paired"])
        self.assertEqual((record["frontend"]["deployment_id"], record["from"]["frontend"]), (STAGED_FRONTEND, LIVE_FRONTEND))
        self.assertTrue(all(check["passed"] for check in record["paired_checks"].values()))
        self.assertEqual((state["frontend"]["deployment_id"], state["awaiting_acceptance"]["frontend"]["deployment_id"]),
                         (STAGED_FRONTEND, STAGED_FRONTEND))
        self.assertIsNone(state["frontend_promoting"])
        self.assertEqual((result["outcome"], result["acceptance"], result["frontend"]), ("verified", "awaiting", STAGED_FRONTEND))
        self.assertNotIn(release.LOCK_KEY, lab.store)

        release.Release(lab).accept()
        state = lab.inputs
        self.assertEqual(state["accepted"]["frontend"]["deployment_id"], STAGED_FRONTEND)
        self.assertEqual(state["previous_accepted"]["frontend"]["deployment_id"], LIVE_FRONTEND)

    def test_a_staging_failure_changes_nothing(self):
        lab = FakeLab(tracked())
        lab.stage_error = "vercel build failed"
        before = copy.deepcopy(lab.store)
        with self.assertRaisesRegex(release.ReleaseError, "vercel build failed"):
            self.deploy(lab)
        self.assertEqual(lab.store, before)
        self.assertEqual(lab.calls, [("stage", False)])

    def test_a_failed_promotion_is_frontend_pending_and_the_retry_repeats_no_backend_step(self):
        lab = FakeLab(tracked())
        lab.promote_error, lab.promote_moves_alias = "Vercel POST returned 502", False
        with self.assertRaises(release.ReleaseError) as raised:
            self.deploy(lab)
        self.assertEqual((raised.exception.outcome, raised.exception.reason), ("failed", "frontend_pending"))
        record, state = lab.record(), lab.inputs
        self.assertEqual((record["failed_at"], record["result"]["reason"]), ("frontend", "frontend_pending"))
        self.assertEqual((state["pending"]["phase"], state["frontend_promoting"]), ("verified", STAGED_FRONTEND))
        self.assertEqual(state["frontend"]["deployment_id"], LIVE_FRONTEND)

        lab.promote_error, lab.promote_moves_alias, lab.calls = None, True, []
        self.deploy(lab)
        self.assertEqual(lab.calls, ["confirm", ("promote", STAGED_FRONTEND)])
        self.assertEqual(len(lab.baked), 1)
        self.assertEqual(lab.record()["status"], "verified")
        self.assertIsNone(lab.inputs["frontend_promoting"])

    def test_an_uncertain_promotion_is_read_from_the_domain_before_acting_again(self):
        lab = FakeLab(tracked())
        lab.promote_error = "timed out waiting for the alias"   # the call failed, but the domain moved
        with self.assertRaises(release.ReleaseError):
            self.deploy(lab)
        lab.promote_error, lab.calls = None, []
        self.deploy(lab)
        self.assertEqual(lab.calls, ["confirm"])
        self.assertEqual(lab.inputs["frontend"]["deployment_id"], STAGED_FRONTEND)

    def test_a_paired_release_resumes_only_as_a_paired_release(self):
        lab = FakeLab(tracked())
        lab.promote_error, lab.promote_moves_alias = "502", False
        with self.assertRaises(release.ReleaseError):
            self.deploy(lab)
        with self.assertRaisesRegex(release.ReleaseError, "rerun it with --frontend"):
            release.Release(lab).deploy("main")

    def test_a_failed_paired_check_recovers_the_accepted_pair_frontend_first(self):
        lab = FakeLab(tracked())
        lab.app_code = 503
        with self.assertRaises(release.ReleaseError) as raised:
            self.deploy(lab)
        self.assertEqual((raised.exception.outcome, raised.exception.reason), ("failed", "check_failed"))
        failed_id = lab.inputs["pending"]["release_id"]
        lab.app_code, lab.calls = 200, []

        result = release.Release(lab).rollback(note="paired check failed")
        self.assertEqual(lab.calls, ["confirm", ("promote", LIVE_FRONTEND), ("plan", "runtime", OLD, NEW),
                                     ("apply", "runtime.tfplan")])
        state = lab.inputs
        self.assertEqual((state["frontend"]["deployment_id"], state["runtime_image_digest"]), (LIVE_FRONTEND, OLD))
        self.assertIsNone(state["pending"])
        self.assertIsNone(state["awaiting_acceptance"])
        self.assertEqual(state["accepted"]["release_id"], "baseline")
        self.assertEqual((result["outcome"], result["acceptance"], result["replaces"]), ("verified", "reused", failed_id))

        failed = lab.store[f"{release.RECORDS}/{failed_id}.json"]
        rollback = lab.store[f"{release.RECORDS}/{result['release_id']}.json"]
        self.assertEqual((failed["status"], failed["result"]["reason"]), ("failed", "recovered"))
        self.assertEqual(failed["rolled_back"]["by"], rollback["release_id"])
        self.assertEqual((rollback["replaces"], rollback["note"], rollback["status"]), (failed_id, "paired check failed", "accepted"))
        self.assertIn("reuses the acceptance of baseline", rollback["acceptance"])
        self.assertTrue(all(check["passed"] for check in rollback["paired_checks"].values()))

    def test_an_operator_rollback_from_an_accepted_pair_waits_for_acceptance_and_marks_the_left_release(self):
        lab = FakeLab(tracked())
        self.deploy(lab)
        release.Release(lab).accept()
        left = lab.inputs["accepted"]["release_id"]
        lab.calls = []
        result = release.Release(lab).rollback(note="phase 3 drill")
        self.assertEqual(lab.calls[:2], ["confirm", ("promote", LIVE_FRONTEND)])
        self.assertEqual(result["acceptance"], "awaiting")
        self.assertEqual(lab.inputs["awaiting_acceptance"]["restores"]["release_id"], "baseline")
        marked = lab.store[f"{release.RECORDS}/{left}.json"]
        self.assertEqual((marked["status"], marked["rolled_back"]["reason"], marked["rolled_back"]["note"]),
                         ("accepted", "rolled back by the operator", "phase 3 drill"))

    def test_a_backend_only_rollback_leaves_the_frontend(self):
        lab = FakeLab(tracked())
        release.Release(lab).deploy("main")
        release.Release(lab).accept()
        lab.calls = []
        release.Release(lab).rollback()
        self.assertNotIn(("promote", LIVE_FRONTEND), lab.calls)
        self.assertNotIn("paired_checks", lab.record())

    def test_a_rollback_without_the_target_frontend_needs_the_operator(self):
        lab = FakeLab(inputs())   # the accepted release predates frontend tracking
        lab.app_code = 503
        with self.assertRaises(release.ReleaseError):
            self.deploy(lab)
        before, lab.calls = copy.deepcopy(lab.store), []
        with self.assertRaises(release.ReleaseError) as raised:
            release.Release(lab).rollback()
        self.assertEqual((raised.exception.outcome, raised.exception.reason), ("needs_operator", "frontend_unrecorded"))
        self.assertEqual(lab.store, before)
        self.assertEqual(lab.calls, [])

    def test_the_rollback_target_counts_the_frontend(self):
        state = tracked(previous={"release_id": "older", "runtime_image_digest": NEW})
        self.assertEqual(release.rollback_target(state)["release_id"], "older")
        self.assertEqual(release.rollback_target({**state, "frontend": {"deployment_id": STAGED_FRONTEND}})["release_id"],
                         "baseline")
        self.assertEqual(release.rollback_target({**state, "frontend_promoting": STAGED_FRONTEND})["release_id"], "baseline")

    def test_adopt_frontend_records_the_live_domain_once(self):
        lab = FakeLab(inputs())
        release.Release(lab).adopt_frontend()
        state = lab.inputs
        self.assertEqual((state["frontend"]["deployment_id"], state["accepted"]["frontend"]["deployment_id"]),
                         (LIVE_FRONTEND, LIVE_FRONTEND))
        self.assertTrue(state["frontend"]["adopted"])
        with self.assertRaisesRegex(release.ReleaseError, "already tracked"):
            release.Release(lab).adopt_frontend()
        busy = FakeLab({**inputs(), "awaiting_acceptance": {"release_id": "r1"}})
        with self.assertRaisesRegex(release.ReleaseError, "finish or roll back"):
            release.Release(busy).adopt_frontend()
        self.assertNotIn("frontend", busy.inputs)


class OutcomeTest(unittest.TestCase):
    def test_a_resumed_deploy_does_not_rerun_a_migrator_that_succeeded(self):
        lab = FakeLab(inputs(), plans={"runtime": plan(("aws_lb.api[\"standard\"]", ("update",)))})
        with self.assertRaises(release.ReleaseError) as raised:
            release.Release(lab).deploy("main")
        self.assertEqual((raised.exception.outcome, raised.exception.reason), ("failed", "step_failed"))
        lab.plans["runtime"], lab.calls = DEFAULT_PLANS["runtime"], []
        release.Release(lab).deploy("main")
        self.assertEqual(lab.calls, ["confirm", ("plan", "runtime", NEW, NEW), ("apply", "runtime.tfplan")])

    def test_refusals_name_their_reason(self):
        cases = [(FakeLab(inputs(), present=False), ("blocked", "parked")),
                 (FakeLab({**inputs(), "awaiting_acceptance": {"release_id": "r1"}}), ("blocked", "awaiting_acceptance")),
                 (FakeLab(inputs(pending={"release_id": "r1", "source_sha": OLD_SHA, "kind": "deploy", "phase": "migrator"})),
                  ("needs_operator", "unfinished")),
                 (FakeLab(inputs(), pub=publication(catalog=OTHER_CATALOG)), ("blocked", "schema_changed"))]
        for lab, expected in cases:
            with self.subTest(expected=expected), self.assertRaises(release.ReleaseError) as raised:
                release.Release(lab).deploy("main")
            self.assertEqual((raised.exception.outcome, raised.exception.reason), expected)

    def test_a_failed_rollback_needs_the_operator(self):
        lab = FakeLab(inputs())
        release.Release(lab).deploy("main")
        release.Release(lab).accept()
        lab.http_status = lambda path: 503
        with self.assertRaises(release.ReleaseError) as raised:
            release.Release(lab).rollback()
        self.assertEqual((raised.exception.outcome, raised.exception.reason), ("needs_operator", "recovery_failed"))

    def test_staged_reference_reads_the_deploy_output(self):
        # vercel@65.9.0 prints JSON when stdout is not a terminal; the last line alone is "}".
        self.assertEqual(release.staged_reference('{\n  "id": "dpl_AcWAF5",\n  "url": "x.vercel.app"\n}\n'), "dpl_AcWAF5")
        self.assertEqual(release.staged_reference('{"deployment": {"id": "dpl_Nested1"}}'), "dpl_Nested1")
        self.assertEqual(release.staged_reference("https://scout-frontend-abc-scoutgrid.vercel.app\n"),
                         "scout-frontend-abc-scoutgrid.vercel.app")
        with self.assertRaisesRegex(release.ReleaseError, "no deployment"):
            release.staged_reference("}\n")

    def test_parse_options(self):
        self.assertEqual(release.parse_options(["--frontend"], flags=("--frontend",)), {"--frontend": True})
        self.assertEqual(release.parse_options(["--note", "x"], valued=("--note",)), {"--note": "x"})
        for bad in (["--frontend", "--frontend"], ["--other"], ["--note"]):
            self.assertIsNone(release.parse_options(bad, flags=("--frontend",), valued=("--note",)))


class InitTest(unittest.TestCase):
    def test_init_seeds_from_the_running_image_once(self):
        lab = FakeLab(None)
        release.Release(lab).init(OLD_SHA, 15, 20)
        state = lab.inputs
        self.assertEqual((state["runtime_image_digest"], state["database_heads"]), (OLD, V20))
        self.assertTrue(re.fullmatch(r"baseline-\d{8}", state["accepted"]["release_id"]))
        with self.assertRaisesRegex(release.ReleaseError, "already exist"):
            release.Release(lab).init(OLD_SHA, 15, 20)

    def test_init_refuses_mixed_or_missing_images(self):
        for live in ({"api": OLD, "worker": NEW, "migrator": OLD}, {"api": OLD, "worker": OLD, "migrator": None}):
            lab = FakeLab(None, live=live)
            with self.assertRaisesRegex(release.ReleaseError, "one image"):
                release.Release(lab).init(OLD_SHA, 15, 20)
            self.assertNotIn(release.INPUTS_KEY, lab.store)

    def test_init_needs_a_full_commit_and_heads(self):
        with self.assertRaisesRegex(release.ReleaseError, "full 40-character"):
            release.Release(FakeLab(None)).init("0ae3de9", 15, 20)
        with self.assertRaisesRegex(release.ReleaseError, "positive"):
            release.Release(FakeLab(None)).init(OLD_SHA, 0, 20)


if __name__ == "__main__":
    unittest.main()
