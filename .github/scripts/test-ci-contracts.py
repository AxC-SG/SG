import importlib.util
import json
import re
import tomllib
from pathlib import Path
import unittest


def module(name):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(name + ".py"))
    loaded = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(loaded)
    return loaded


classifier = module("classify-changes")
gate = module("check-quality-gate")
workflow_yaml = module("workflow_contracts")
ROOT = Path(__file__).resolve().parents[2]


def workflow(name):
    return workflow_yaml.load((ROOT / ".github/workflows" / name).read_text())


def dependencies(value):
    return {value} if isinstance(value, str) else set(value)


class ContractsTest(unittest.TestCase):
    def test_signed_in_smoke_never_leaves_auth_state_in_public_artifacts(self):
        # The repository is public: the lab smoke signs in with real lab accounts, so it must not
        # record traces, screenshots, videos, HARs or storage state, and no workflow may run it.
        root = Path(__file__).resolve().parents[2]
        source = (root / 'prototype-app/frontend/e2e/lab-smoke.mjs').read_text()
        code = '\n'.join(line.split('//')[0] if line.lstrip().startswith('//') else line for line in source.splitlines())
        for forbidden in ('tracing', 'screenshot', 'recordVideo', 'recordHar', 'storageState', 'writeFile', 'video'):
            self.assertFalse(forbidden in code, f'lab-smoke.mjs must not use {forbidden}')
        for workflow_path in (root / '.github/workflows').glob('*.yml'):
            text = workflow_path.read_text()
            self.assertNotIn('lab-smoke', text, f'{workflow_path.name} must not run the credentialed lab smoke')
            self.assertNotIn('upload-artifact', text if workflow_path.name == 'lab-reconcile.yml' else '', workflow_path.name)
            if workflow_path.name == 'lab-reconcile.yml':
                continue
            self.assertNotIn('LAB_SMOKE_CONFIG', text, workflow_path.name)
        # The one exception: the manual lab reconcile hands release.py a tenant-only smoke config
        # (owner decision S1) in a private temporary file it removes, and never prints or uploads it.
        reconcile = workflow("lab-reconcile.yml")["jobs"]["reconcile"]
        release = next(step for step in reconcile["steps"] if step.get("id") == "reconcile")
        self.assertEqual(release["env"]["SMOKE_CONFIG_JSON"], "${{ secrets.LAB_SMOKE_TENANT_CONFIG }}")
        shell = (ROOT / ".github/scripts/run-lab-reconcile.sh").read_text()
        for leak in ('cat "$smoke', 'echo "$SMOKE_CONFIG_JSON', 'set -x', 'ACTIONS_STEP_DEBUG'):
            self.assertNotIn(leak, shell)

    def test_enforced_gate_contract_and_codeql_policy(self):
        root = Path(__file__).resolve().parents[2]
        ruleset = json.loads((root / '.github/required-main-ruleset.json').read_text())
        # One stable gate: the security, image and main performance results are inside it.
        expected = {'Quality gate'}
        status = next(rule['parameters'] for rule in ruleset['rules'] if rule['type'] == 'required_status_checks')
        self.assertEqual({item['context'] for item in status['required_status_checks']}, expected)
        self.assertEqual(len(status['required_status_checks']), len(expected))
        self.assertTrue(all(item['integration_id'] == 15368 for item in status['required_status_checks']))
        self.assertTrue(status['strict_required_status_checks_policy'])
        self.assertEqual(ruleset['conditions']['ref_name'], {'include': ['refs/heads/main'], 'exclude': []})
        self.assertEqual(ruleset['bypass_actors'], [])
        names = []
        for workflow_path in (root / '.github/workflows').glob('*.yml'):
            names.extend(job.get("name") for job in workflow_yaml.load(workflow_path.read_text())["jobs"].values())
        for name in expected:
            self.assertEqual(names.count(name), 1, f'{name}: coordinate workflow and ruleset changes')
        tools = next(rule['parameters']['code_scanning_tools'] for rule in ruleset['rules'] if rule['type'] == 'code_scanning')
        self.assertEqual(tools, [{'tool': 'CodeQL', 'alerts_threshold': 'errors', 'security_alerts_threshold': 'high_or_higher'}])

    def test_quality_is_the_only_pull_request_and_main_workflow(self):
        quality = workflow("quality.yml")
        self.assertEqual(set(quality["on"]), {"pull_request", "push"})
        self.assertEqual(quality["on"]["push"]["branches"], ["main"])
        for path in (ROOT / ".github/workflows").glob("*.yml"):
            if path.name != "quality.yml":
                self.assertFalse(set(workflow(path.name)["on"]) & {"pull_request", "pull_request_target", "push", "workflow_run"}, path.name)
        for job, name in (("security", "trivy.yml"), ("semgrep", "semgrep.yml"),
                          ("performance", "performance-governance.yml"), ("publish", "aws-publish-candidate.yml")):
            called = workflow(name)
            self.assertIn("workflow_call", called["on"])
            self.assertNotIn("concurrency", called)
            self.assertEqual(quality["jobs"][job]["uses"], f"./.github/workflows/{name}")

    def test_publication_comes_from_the_gated_main_run(self):
        quality = workflow("quality.yml")
        publish = quality["jobs"]["publish"]
        self.assertEqual(dependencies(publish["needs"]), {"required"})
        self.assertEqual(publish["if"], "github.event_name == 'push' && github.ref == 'refs/heads/main'")
        self.assertEqual(publish["permissions"]["id-token"], "write")
        self.assertEqual([name for name, job in quality["jobs"].items()
                          if job.get("permissions", {}).get("id-token") == "write"], ["publish"])
        selector = module("select-aws-candidate")
        self.assertEqual(quality["jobs"]["required"]["name"], selector.GATE_JOB)
        trivy_steps = workflow("trivy.yml")["jobs"]["aws-candidate"]["steps"]
        self.assertTrue(any(step.get("with", {}).get("name") == "aws-backend-candidate-${{ github.run_id }}" for step in trivy_steps))
        publisher = workflow("aws-publish-candidate.yml")["jobs"]["publish"]
        self.assertTrue(any(step.get("with", {}).get("name") == "aws-backend-candidate-${{ needs.qualify.outputs.candidate_run }}" for step in publisher["steps"]))
        self.assertEqual(publisher["if"], "needs.qualify.outputs.publish == 'true'")
        self.assertNotIn("inputs.", json.dumps(publisher))
        self.assertEqual(publisher["concurrency"], {"group": "aws-publish-${{ needs.qualify.outputs.target }}", "cancel-in-progress": False})

    def test_lab_reconcile_is_manual_main_only_and_runtime_only(self):
        document = workflow("lab-reconcile.yml")
        self.assertEqual(set(document["on"]), {"workflow_dispatch"})
        inputs = document["on"]["workflow_dispatch"]["inputs"]
        self.assertEqual({key: inputs["frontend"][key] for key in ("required", "type", "default")},
                         {"required": True, "type": "boolean", "default": True})
        self.assertTrue(inputs["confirm"]["required"])
        self.assertEqual(inputs["confirm"]["type"], "string")
        self.assertEqual(document["permissions"], {})
        self.assertEqual(document["concurrency"], {"group": "lab-release", "cancel-in-progress": False})
        self.assertEqual(set(document["jobs"]), {"reconcile"})
        job = document["jobs"]["reconcile"]
        self.assertEqual(job["if"], "github.ref == 'refs/heads/main'")
        self.assertEqual(job["environment"], "aws-standard-lab-release")
        self.assertEqual(job["permissions"], {"actions": "read", "contents": "read", "id-token": "write"})
        self.assertEqual(sum(other.get("permissions", {}).get("id-token") == "write" for other in document["jobs"].values()), 1)
        text = json.dumps(job)
        self.assertTrue(any('if [[ \"$CONFIRM\" != reconcile ]]; then' in step.get('run', '') for step in job['steps']))
        iam = (ROOT / "prototype-app/infrastructure/terraform/standard/release-iam.tf").read_text()
        self.assertIn(r"environment:aws-standard-lab-release:job_workflow_ref:AxC-SG/SG/\\.github/workflows/lab-reconcile\\.yml@refs/heads/main$", iam)
        self.assertIn("role/scoutgrid-lab-github-release", text)
        credentials = next(step for step in job["steps"] if step.get("uses", "").startswith("aws-actions/configure-aws-credentials@"))
        self.assertEqual(credentials["with"]["role-to-assume"], "${{ vars.AWS_LAB_RELEASE_ROLE_ARN }}")
        release = next(step for step in job["steps"] if step.get("id") == "reconcile")
        self.assertEqual(release["env"]["LAB_RELEASE_PROFILE"], "")
        self.assertEqual(release["run"].strip(), "bash .github/scripts/run-lab-reconcile.sh")
        for step in job["steps"]:
            if "uses" in step and not step["uses"].startswith("./"):
                self.assertRegex(step["uses"], r"^[a-z0-9-]+/[a-z0-9-]+@[0-9a-f]{40}$")
        for name, job_id in (("quality.yml", "terraform"), ("lab-reconcile.yml", "reconcile")):
            self.assertEqual(sum(step.get("uses") == "./.github/actions/setup-terraform" for step in workflow(name)["jobs"][job_id]["steps"]), 1)
        shell = (ROOT / ".github/scripts/run-lab-reconcile.sh").read_text()
        self.assertIn("args=(reconcile --yes)", shell)
        self.assertEqual(shell.count("scripts/release.py"), 1)
        for forbidden in ("release.py deploy", "rollback", "accept ", "unlock", "terraform apply", "run-task", "upload-artifact"):
            self.assertNotIn(forbidden, text + shell)

    def test_terraform_validation_is_required_and_offline(self):
        jobs = workflow("quality.yml")["jobs"]
        job = jobs["terraform"]
        self.assertEqual(gate.SELECTED_JOBS["terraform"], "infrastructure")
        self.assertIn("terraform", dependencies(jobs["required"]["needs"]))
        roots = sorted({path.parent for path in (ROOT / "prototype-app/infrastructure/terraform").rglob("*.tf") if ".terraform" not in path.parts})
        self.assertTrue(roots)
        for directory in roots:
            relative = directory.relative_to(ROOT).as_posix()
            step = next((step for step in job["steps"] if step.get("working-directory") == relative), None)
            self.assertIsNotNone(step, relative)
            for command in ("terraform init -backend=false", "terraform validate", "terraform test"):
                self.assertIn(command, step["run"], relative)
        lab = next(step for step in job["steps"] if step.get("working-directory") == "prototype-app/infrastructure/lab")
        for command in ("shellcheck scripts/*.sh scripts/tests/*.sh", "bash scripts/tests/lab.test.sh", "python3 -I scripts/tests/test_release.py"):
            self.assertIn(command, lab["run"])
        self.assertIn("terraform fmt -check -recursive prototype-app/infrastructure/terraform", json.dumps(job))
        self.assertNotIn("id-token", job.get("permissions", {}))
        for forbidden in ("configure-aws-credentials", "terraform apply"):
            self.assertNotIn(forbidden, json.dumps(job))

    def test_image_builds_use_explicit_dns_and_fail_closed_package_indexes(self):
        job = workflow("trivy.yml")["jobs"]["aws-candidate"]
        builder = next(step for step in job["steps"] if step.get("uses", "").startswith("docker/setup-buildx-action@"))
        self.assertEqual(builder["with"]["buildkitd-config"], ".github/buildkitd.toml")
        config = tomllib.loads((ROOT / ".github/buildkitd.toml").read_text())
        self.assertEqual(config["dns"]["nameservers"], ["1.1.1.1", "8.8.8.8"])
        dockerfile = (ROOT / "prototype-app/backend/Dockerfile").read_text()
        self.assertIn("APT::Update::Error-Mode=any update", dockerfile)
        self.assertIn("Acquire::Retries=3", dockerfile)

    def test_selection(self):
        none = dict(frontend=False, backend=False, infrastructure=False)
        everything = dict(frontend=True, backend=True, infrastructure=True)
        cases = [
            (["README.md"], none),
            (["prototype-app/docs/frontend.md"], none),
            (["prototype-app/Working Knowledge/CI Pipeline/plan.md", "prototype-app/Working Knowledge/AWS/cost.json"], none),
            (["prototype-app/backend/CLAUDE.md", ".gitleaks.toml"], none),
            (["prototype-app/frontend/src/App.tsx"], dict(none, frontend=True)),
            ([".nvmrc"], dict(none, frontend=True)),
            (["prototype-app/backend/src/main/java/A.java"], dict(none, backend=True)),
            (["prototype-app/scripts/run-performance-governance.sh"], dict(none, backend=True)),
            (["prototype-app/policy-packages/agcf/p.json"], dict(none, backend=True)),
            (["prototype-app/infrastructure/terraform/standard/main.tf"], dict(none, infrastructure=True)),
            (["prototype-app/frontend/src/App.tsx", "prototype-app/backend/pom.xml"],
             dict(none, frontend=True, backend=True)),
            # Conservative cases: no list, workflow or script changes, unknown paths.
            ([], everything),
            ([".github/workflows/quality.yml"], everything),
            ([".github/scripts/check-quality-gate.py"], everything),
            (["prototype-app/docs/data.json"], everything),
            (["package.json"], everything),
            (["README.md", "some/new/top-level/file.txt"], everything),
        ]
        for files, expected in cases:
            self.assertEqual(classifier.classify(files, "pull_request"), expected, files)
        for files, _ in cases:
            self.assertEqual(classifier.classify(files, "push"), everything, files)

    def test_each_trivy_scan_runs_once_and_enforces(self):
        jobs = workflow("trivy.yml")["jobs"]
        scans = [step for job in jobs.values() for step in job["steps"]
                 if step.get("uses", "").startswith("aquasecurity/trivy-action@")]
        self.assertEqual(len(scans), 2)
        for scan in scans:
            self.assertEqual(scan["with"]["exit-code"], "1")
            self.assertTrue(scan["with"]["limit-severities-for-sarif"])
            self.assertEqual(scan["with"]["severity"], "CRITICAL")
        self.assertFalse(any(re.search(r"(?m)^trivy (fs|image) ", step.get("run", ""))
                             for job in jobs.values() for step in job["steps"]))
        self.assertNotIn("schedule", jobs["aws-candidate"].get("if", ""))

    def needs(self, event="push", **selected):
        outputs = {name: "true" for name in gate.SELECTION_OUTPUTS}
        outputs.update(selected)
        result = {key: dict(result="success") for key in set(gate.SELECTED_JOBS) | gate.ALWAYS_JOBS | gate.MAIN_ONLY_JOBS}
        if event == "pull_request":
            for job in gate.MAIN_ONLY_JOBS:
                result[job]["result"] = "skipped"
        result["changes"]["outputs"] = outputs
        return result

    def test_required_results(self):
        self.assertEqual(gate.failures(self.needs(), "push"), [])
        self.assertEqual(gate.failures(self.needs("pull_request"), "pull_request"), [])
        for event in gate.EVENTS:
            for job in gate.ALWAYS_JOBS | set(gate.SELECTED_JOBS) | gate.MAIN_ONLY_JOBS:
                for state in ["failure", "cancelled", "skipped", None]:
                    needs = self.needs(event)
                    if needs[job]["result"] == "skipped" and state == "skipped":
                        continue
                    needs[job]["result"] = state
                    self.assertTrue(gate.failures(needs, event), (event, job, state))

    def test_security_and_semgrep_never_skip(self):
        self.assertLessEqual({"security", "semgrep"}, gate.ALWAYS_JOBS)
        for event in gate.EVENTS:
            for job in ("security", "semgrep"):
                needs = self.needs(event)
                needs[job]["result"] = "skipped"
                self.assertTrue(gate.failures(needs, event), (event, job))

    def test_main_performance_is_required_on_push_and_skipped_on_pull_requests(self):
        for job in gate.MAIN_ONLY_JOBS:
            needs = self.needs()
            needs[job]["result"] = "skipped"
            self.assertTrue(gate.failures(needs, "push"), job)
            needs = self.needs("pull_request")
            needs[job]["result"] = "success"
            self.assertTrue(gate.failures(needs, "pull_request"), job)
            needs = self.needs()
            del needs[job]
            self.assertTrue(gate.failures(needs, "push"), job)

    def test_unknown_events_fail(self):
        for event in ("schedule", "workflow_dispatch", None):
            self.assertTrue(gate.failures(self.needs(), event), event)

    def test_only_explicit_skips_are_allowed(self):
        needs = self.needs(frontend="false", backend="false", infrastructure="false")
        for job in gate.SELECTED_JOBS:
            needs[job]["result"] = "skipped"
        self.assertEqual(gate.failures(needs, "push"), [])
        needs["secrets"]["result"] = "skipped"
        self.assertTrue(gate.failures(needs, "push"))
        for output in gate.SELECTION_OUTPUTS:
            for bad in ["invalid", None]:
                needs = self.needs()
                needs["changes"]["outputs"][output] = bad
                self.assertTrue(gate.failures(needs, "push"), (output, bad))

    def test_skips_follow_their_own_component(self):
        for output in gate.SELECTION_OUTPUTS:
            jobs = {job for job, selected_by in gate.SELECTED_JOBS.items() if selected_by == output}
            others = set(gate.SELECTED_JOBS) - jobs
            needs = self.needs(**{output: "false"})
            for job in jobs:
                needs[job]["result"] = "skipped"
            self.assertEqual(gate.failures(needs, "push"), [], output)
            for job in others:
                needs = self.needs(**{output: "false"})
                needs[job]["result"] = "skipped"
                self.assertTrue(gate.failures(needs, "push"), (output, job))

    def test_workflow_selects_jobs_by_the_gate_mapping(self):
        jobs = workflow("quality.yml")["jobs"]
        for output in gate.SELECTION_OUTPUTS:
            self.assertEqual(jobs["changes"]["outputs"][output], "${{ steps.select.outputs." + output + " }}")
        for name, output in gate.SELECTED_JOBS.items():
            self.assertEqual(dependencies(jobs[name]["needs"]), {"changes"})
            self.assertEqual(jobs[name]["if"], f"needs.changes.outputs.{output} == 'true'")

    def test_quality_gate_waits_for_exactly_the_accounted_jobs(self):
        jobs = workflow("quality.yml")["jobs"]
        accounted = gate.ALWAYS_JOBS | set(gate.SELECTED_JOBS) | gate.MAIN_ONLY_JOBS
        self.assertEqual(dependencies(jobs["required"]["needs"]), accounted)
        self.assertEqual(set(jobs) - {"required", "publish"}, accounted)

if __name__ == "__main__":
    unittest.main()
