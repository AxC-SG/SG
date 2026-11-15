import importlib.util
import json
import re
from pathlib import Path
import unittest


def module(name):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(name + ".py"))
    loaded = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(loaded)
    return loaded


classifier = module("classify-changes")
gate = module("check-quality-gate")


class ContractsTest(unittest.TestCase):
    def test_signed_in_smoke_never_leaves_auth_state_in_public_artifacts(self):
        # The repository is public: the lab smoke signs in with real lab accounts, so it must not
        # record traces, screenshots, videos, HARs or storage state, and no workflow may run it.
        root = Path(__file__).resolve().parents[2]
        source = (root / 'prototype-app/frontend/e2e/lab-smoke.mjs').read_text()
        code = '\n'.join(line.split('//')[0] if line.lstrip().startswith('//') else line for line in source.splitlines())
        for forbidden in ('tracing', 'screenshot', 'recordVideo', 'recordHar', 'storageState', 'writeFile', 'video'):
            self.assertFalse(forbidden in code, f'lab-smoke.mjs must not use {forbidden}')
        for workflow in (root / '.github/workflows').glob('*.yml'):
            text = workflow.read_text()
            self.assertNotIn('lab-smoke', text, f'{workflow.name} must not run the credentialed lab smoke')
            self.assertNotIn('LAB_SMOKE_CONFIG', text, workflow.name)

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
        for workflow in (root / '.github/workflows').glob('*.yml'):
            names.extend(re.findall(r'^    name: (.+)$', workflow.read_text(), re.MULTILINE))
        for name in expected:
            self.assertEqual(names.count(name), 1, f'{name}: coordinate workflow and ruleset changes')
        tools = next(rule['parameters']['code_scanning_tools'] for rule in ruleset['rules'] if rule['type'] == 'code_scanning')
        self.assertEqual(tools, [{'tool': 'CodeQL', 'alerts_threshold': 'errors', 'security_alerts_threshold': 'high_or_higher'}])

    def test_quality_is_the_only_pull_request_and_main_workflow(self):
        root = Path(__file__).resolve().parents[2]
        workflows = root / '.github/workflows'
        quality = (workflows / 'quality.yml').read_text()
        events = quality.split('on:\n', 1)[1].split('\npermissions:', 1)[0]
        self.assertRegex(events, r'(?m)^  pull_request:')
        self.assertRegex(events, r'(?m)^  push:\n    branches:\n      - main\n')
        self.assertNotIn('merge_group', events)
        for workflow in workflows.glob('*.yml'):
            if workflow.name == 'quality.yml':
                continue
            other = workflow.read_text().split('on:\n', 1)[1].split('\npermissions:', 1)[0]
            # A second PR or push trigger would run checks outside the gate.
            self.assertNotRegex(other, r'(?m)^  (pull_request|pull_request_target|push|workflow_run):', workflow.name)
        for job, name in (('security', 'trivy.yml'), ('semgrep', 'semgrep.yml'),
                          ('performance', 'performance-governance.yml'), ('publish', 'aws-publish-candidate.yml')):
            called = (workflows / name).read_text()
            self.assertRegex(called.split('\npermissions:', 1)[0], r'(?m)^  workflow_call:', name)
            # A called workflow sees the caller's github.workflow, so its own
            # workflow-level concurrency group would collide with Quality's.
            self.assertIsNone(re.search(r'(?m)^concurrency:', called), name)
            self.assertIn(f'uses: ./.github/workflows/{name}\n', self.job(quality, job), job)

    def test_publication_comes_from_the_gated_main_run(self):
        root = Path(__file__).resolve().parents[2]
        workflows = root / '.github/workflows'
        quality = (workflows / 'quality.yml').read_text()
        publish = self.job(quality, 'publish')
        self.assertIn('needs: required\n', publish)
        self.assertIn("if: github.event_name == 'push' && github.ref == 'refs/heads/main'\n", publish)
        self.assertNotIn('always()', publish)
        self.assertIn('id-token: write', publish)
        # The OIDC grant belongs to the publish call only.
        self.assertEqual(quality.count('id-token: write'), 1)
        selector = module('select-aws-candidate')
        self.assertEqual(selector.QUALITY, 'quality.yml')
        self.assertIn(f'    name: {selector.GATE_JOB}\n', self.job(quality, 'required'))
        # The image archive the publisher downloads is the one this run's security job made.
        trivy = (workflows / 'trivy.yml').read_text()
        self.assertIn('name: aws-backend-candidate-${{ github.run_id }}', trivy)
        publisher = (workflows / 'aws-publish-candidate.yml').read_text()
        self.assertIn('name: aws-backend-candidate-${{ needs.qualify.outputs.candidate_run }}', publisher)
        job = publisher.split('\n  publish:\n', 1)[1]
        self.assertIn("if: needs.qualify.outputs.publish == 'true'", job)
        self.assertNotIn('inputs.', job)
        self.assertIn('group: aws-publish-${{ needs.qualify.outputs.target }}', job)
        self.assertIn('cancel-in-progress: false', job)

    @staticmethod
    def job(workflow, name):
        return re.split(r'(?m)^  [a-z][a-z0-9-]*:\n', workflow.split(f'\n  {name}:\n', 1)[1], maxsplit=1)[0]

    def test_terraform_validation_is_required_and_offline(self):
        root = Path(__file__).resolve().parents[2]
        workflow = (root / '.github/workflows/quality.yml').read_text()
        job = re.split(r'(?m)^  [a-z][a-z0-9-]*:\n', workflow.split('\n  terraform:\n', 1)[1], maxsplit=1)[0]
        required = workflow.split('  required:\n', 1)[1]
        self.assertEqual(gate.SELECTED_JOBS['terraform'], 'infrastructure')
        self.assertRegex(required, r'needs: \[[^\n]*\bterraform\b')
        # Every Terraform root is initialised without a backend, validated and tested.
        terraform = root / 'prototype-app/infrastructure/terraform'
        roots = sorted({path.parent for path in terraform.rglob('*.tf') if '.terraform' not in path.parts})
        self.assertTrue(roots)
        steps = job.split('\n      - ')
        for directory in roots:
            relative = directory.relative_to(root).as_posix()
            step = next((step for step in steps if f'working-directory: {relative}\n' in step), None)
            self.assertIsNotNone(step, f'{relative} is not validated in CI')
            for command in ('terraform init -backend=false', 'terraform validate', 'terraform test'):
                self.assertIn(command, step, relative)
        # The lab cycle scripts are linted and tested offline in the same job.
        lab_step = next((step for step in steps if 'working-directory: prototype-app/infrastructure/lab\n' in step), None)
        self.assertIsNotNone(lab_step, 'lab scripts are not tested in CI')
        self.assertIn('shellcheck scripts/*.sh scripts/tests/*.sh', lab_step)
        self.assertIn('bash scripts/tests/lab.test.sh', lab_step)
        self.assertIn('python3 -I scripts/tests/test_release.py', lab_step)
        self.assertIn('terraform fmt -check -recursive prototype-app/infrastructure/terraform', job)
        for forbidden in ('id-token:', 'configure-aws-credentials', 'terraform apply'):
            self.assertNotIn(forbidden, job)

    def test_image_builds_use_explicit_dns_and_fail_closed_package_indexes(self):
        root = Path(__file__).resolve().parents[2]
        workflow = (root / '.github/workflows/trivy.yml').read_text()
        job = workflow.split('  aws-candidate:\n', 1)[1]
        self.assertIn('buildkitd-config: .github/buildkitd.toml', job)
        config = (root / '.github/buildkitd.toml').read_text()
        self.assertIn('[dns]', config)
        self.assertIn('nameservers = ["1.1.1.1", "8.8.8.8"]', config)
        dockerfile = (root / 'prototype-app/backend/Dockerfile').read_text()
        self.assertIn('APT::Update::Error-Mode=any update', dockerfile)
        self.assertIn('Acquire::Retries=3', dockerfile)

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
        root = Path(__file__).resolve().parents[2]
        workflow = (root / '.github/workflows/trivy.yml').read_text()
        scans = [step.split('\n      - ', 1)[0] for step in workflow.split('uses: aquasecurity/trivy-action@')[1:]]
        self.assertEqual(len(scans), 2)
        for scan in scans:
            self.assertIn("exit-code: '1'", scan)
            self.assertIn("limit-severities-for-sarif: true", scan)
            self.assertIn("severity: CRITICAL", scan)
        self.assertNotRegex(workflow, r"(?m)^\s*(run: )?trivy (fs|image) ")
        self.assertNotIn("schedule'", workflow.split('  aws-candidate:', 1)[1].split('steps:', 1)[0])

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
        root = Path(__file__).resolve().parents[2]
        workflow = (root / '.github/workflows/quality.yml').read_text()
        for output in gate.SELECTION_OUTPUTS:
            self.assertIn(f"{output}: ${{{{ steps.select.outputs.{output} }}}}", workflow)
        for job, output in gate.SELECTED_JOBS.items():
            body = re.split(r'(?m)^  [a-z][a-z0-9-]*:\n', workflow.split(f'\n  {job}:\n', 1)[1], maxsplit=1)[0]
            self.assertIn("needs: changes", body, job)
            self.assertIn(f"if: needs.changes.outputs.{output} == 'true'", body, job)

    def test_quality_gate_waits_for_exactly_the_accounted_jobs(self):
        root = Path(__file__).resolve().parents[2]
        workflow = (root / '.github/workflows/quality.yml').read_text()
        # publish runs after the gate, so the gate does not wait for it.
        jobs = set(re.findall(r'(?m)^  ([a-z][a-z0-9-]*):\n', workflow.split('\njobs:\n', 1)[1])) - {'required', 'publish'}
        needs = re.search(r'(?m)^    needs: \[([^\]]*)\]', workflow.split('\n  required:\n', 1)[1]).group(1)
        accounted = gate.ALWAYS_JOBS | set(gate.SELECTED_JOBS) | gate.MAIN_ONLY_JOBS
        self.assertEqual({name.strip() for name in needs.split(',')}, accounted)
        self.assertEqual(jobs, accounted)

if __name__ == "__main__":
    unittest.main()
