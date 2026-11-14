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
        job = workflow.split('  terraform:\n', 1)[1].split('\n  migration-validation:', 1)[0]
        required = workflow.split('  required:\n', 1)[1]
        self.assertEqual(gate.SELECTED_JOBS['terraform'], 'infrastructure')
        self.assertRegex(required, r'needs: \[[^\n]*\bterraform\b')
        self.assertEqual(job.count('terraform init -backend=false -lockfile=readonly -input=false'), 2)
        self.assertEqual(job.count('terraform test -no-color'), 2)
        self.assertIn('cp ../../standard/.terraform.lock.hcl .terraform.lock.hcl', job)
        self.assertNotIn('id-token:', job)
        self.assertNotIn('configure-aws-credentials', job)
        self.assertNotIn('terraform apply', job)

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

    def test_every_trivy_job_checks_spring_applicability_before_scanning(self):
        root = Path(__file__).resolve().parents[2]
        workflow = (root / '.github/workflows/trivy.yml').read_text()
        jobs = re.split(r'(?m)^  [a-z][a-z-]*:\n', workflow.split('jobs:\n', 1)[1])[1:]
        self.assertEqual(len(jobs), 2)
        for job in jobs:
            check = job.index('python3 .github/scripts/check-spring-advisory-applicability.py')
            controls = job.index('python3 .github/scripts/test-spring-advisory-applicability.py')
            scan = job.index('uses: aquasecurity/trivy-action@')
            self.assertLess(controls, check)
            self.assertLess(check, scan)

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
            body = re.split(r'(?m)^  [a-z][a-z-]*:\n', workflow.split(f'\n  {job}:\n', 1)[1], maxsplit=1)[0]
            self.assertIn("needs: changes", body, job)
            self.assertIn(f"if: needs.changes.outputs.{output} == 'true'", body, job)

if __name__ == "__main__":
    unittest.main()
