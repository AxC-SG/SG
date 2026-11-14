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
    def test_enforced_gate_contract_and_codeql_policy(self):
        root = Path(__file__).resolve().parents[2]
        ruleset = json.loads((root / '.github/required-main-ruleset.json').read_text())
        expected = {'Quality gate', 'Semgrep SAST gate', 'Trivy filesystem gate', 'Performance gate', 'AWS backend candidate'}
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

    def test_main_only_event_contract(self):
        root = Path(__file__).resolve().parents[2]
        for name in ['quality.yml', 'semgrep.yml', 'trivy.yml', 'performance-governance.yml']:
            workflow = (root / '.github/workflows' / name).read_text()
            events = workflow.split('on:\n', 1)[1].split('\npermissions:', 1)[0]
            self.assertRegex(events, r'(?m)^  pull_request:')
            self.assertRegex(events, r'(?m)^  push:')
            self.assertNotIn('merge_group', events)
            self.assertNotIn('master', events)
            self.assertIn('main', events)

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
        none = dict(frontend=False, backend=False, infrastructure=False, performance=False)
        everything = dict(frontend=True, backend=True, infrastructure=True, performance=True)
        cases = [
            (["README.md"], none),
            (["prototype-app/docs/frontend.md"], none),
            (["prototype-app/Working Knowledge/CI Pipeline/plan.md", "prototype-app/Working Knowledge/AWS/cost.json"], none),
            (["prototype-app/backend/CLAUDE.md", ".gitleaks.toml"], none),
            (["prototype-app/frontend/src/App.tsx"], dict(none, frontend=True)),
            ([".nvmrc"], dict(none, frontend=True)),
            (["prototype-app/backend/src/main/java/A.java"], dict(none, backend=True, performance=True)),
            (["prototype-app/scripts/run-performance-governance.sh"], dict(none, backend=True, performance=True)),
            (["prototype-app/policy-packages/agcf/p.json"], dict(none, backend=True, performance=True)),
            (["prototype-app/infrastructure/terraform/standard/main.tf"], dict(none, infrastructure=True)),
            (["prototype-app/frontend/src/App.tsx", "prototype-app/backend/pom.xml"],
             dict(none, frontend=True, backend=True, performance=True)),
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

    def needs(self, **selected):
        outputs = {name: "true" for name in gate.SELECTION_OUTPUTS}
        outputs.update(selected)
        result = {key: dict(result="success") for key in set(gate.SELECTED_JOBS) | gate.ALWAYS_JOBS}
        result["changes"]["outputs"] = outputs
        return result

    def test_required_results(self):
        self.assertEqual(gate.failures(self.needs()), [])
        for job in gate.ALWAYS_JOBS | set(gate.SELECTED_JOBS):
            for state in ["failure", "cancelled", "skipped", None]:
                needs = self.needs()
                needs[job]["result"] = state
                self.assertTrue(gate.failures(needs), (job, state))

    def test_only_explicit_skips_are_allowed(self):
        needs = self.needs(frontend="false", backend="false", infrastructure="false")
        for job in gate.SELECTED_JOBS:
            needs[job]["result"] = "skipped"
        self.assertEqual(gate.failures(needs), [])
        needs["secrets"]["result"] = "skipped"
        self.assertTrue(gate.failures(needs))
        for output in gate.SELECTION_OUTPUTS:
            for bad in ["invalid", None]:
                needs = self.needs()
                needs["changes"]["outputs"][output] = bad
                self.assertTrue(gate.failures(needs), (output, bad))

    def test_skips_follow_their_own_component(self):
        for output in gate.SELECTION_OUTPUTS:
            jobs = {job for job, selected_by in gate.SELECTED_JOBS.items() if selected_by == output}
            others = set(gate.SELECTED_JOBS) - jobs
            needs = self.needs(**{output: "false"})
            for job in jobs:
                needs[job]["result"] = "skipped"
            self.assertEqual(gate.failures(needs), [], output)
            for job in others:
                needs = self.needs(**{output: "false"})
                needs[job]["result"] = "skipped"
                self.assertTrue(gate.failures(needs), (output, job))

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
        jobs = set(re.findall(r'(?m)^  ([a-z][a-z0-9-]*):\n', workflow.split('\njobs:\n', 1)[1])) - {'required'}
        needs = re.search(r'(?m)^    needs: \[([^\]]*)\]', workflow.split('\n  required:\n', 1)[1]).group(1)
        accounted = gate.ALWAYS_JOBS | set(gate.SELECTED_JOBS)
        self.assertEqual({name.strip() for name in needs.split(',')}, accounted)
        self.assertEqual(jobs, accounted)

if __name__ == "__main__":
    unittest.main()
