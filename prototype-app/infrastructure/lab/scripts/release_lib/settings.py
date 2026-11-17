"""Fixed lab identity, release contracts and tool versions."""
import datetime
import json
import re
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

LAB_DIR = Path(__file__).resolve().parents[2]
CFG = LAB_DIR / "config"
TF_ROOT = (LAB_DIR / ".." / "terraform" / "standard").resolve()
BROWSER_CHECKS = CFG / "release-browser-checks.json"
SMOKE_SCRIPT = LAB_DIR.parents[1] / "frontend" / "e2e" / "lab-smoke.mjs"
SMOKE_TIMEOUT_SECONDS = 600
REPO_ROOT = LAB_DIR.parents[2]
# The lab frontend: Vercel project scout-frontend, production domain scoutgrid.io.
VERCEL_CLI = "vercel@65.9.0"
VERCEL_API = "https://api.vercel.com"
VERCEL_TEAM = "team_kaGUpiyT7rWaj2XZlCnsB7Mx"
VERCEL_PROJECT = "prj_BTTCC6KBOQSkBaihL6MZd07ezJn2"
APP_DOMAIN = "scoutgrid.io"
APP_ORIGIN = f"https://{APP_DOMAIN}"
DEPLOYMENT_ID = re.compile(r"dpl_[A-Za-z0-9]+")

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
# Steps that only a release with schema or migrator authority takes; a runtime-only release has none.
MIGRATOR_STEPS = {"stopped", "snapshot", "migrator", "migrated"}
# reconcile's planned refusals (CD plan 4.4): nothing changed, so the command succeeds and says why.
RECONCILE_BLOCKED = ("parked", "awaiting_acceptance", "superseded", "schema_changed", "schema_unverified",
                     "migrator_drift")
NEXT_ACTION = {
    ("verified", None): "run the browser checks, then record them locally with release.py accept",
    ("verified", "no_change"): "nothing to do: the lab already runs this pair",
    ("blocked", "parked"): "start the lab with lab.sh up, then reconcile again",
    ("blocked", "awaiting_acceptance"): "record the live release's browser checks with release.py accept "
                                        "(or roll it back), then reconcile again",
    ("blocked", "superseded"): "wait until main's head is published to the lab, then reconcile again",
    ("blocked", "schema_changed"): "a schema change: release it locally with release.py deploy (owner-run)",
    ("blocked", "schema_unverified"): "inspect the worker's tenant_schema_state line and the migration catalog, "
                                      "then reconcile again, or release locally with release.py deploy",
    ("blocked", "migrator_drift"): "review the migrator change, then release it locally with release.py deploy",
    ("failed", "frontend_pending"): "reconcile again to promote the recorded frontend, or run release.py rollback",
    ("failed", "check_failed"): "run release.py rollback, or fix forward",
    ("failed", "step_failed"): "inspect the record, then reconcile again to resume, or run release.py rollback",
}
TF_REQUIRED = json.loads((REPO_ROOT / ".github/tool-versions.json").read_text())["terraform"]["version"]
