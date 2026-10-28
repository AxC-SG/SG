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
        expected = {'Quality gate', 'Semgrep SAST gate', 'Trivy filesystem gate', 'Trivy images gate', 'Performance gate'}
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

    def test_selection(self):
        for files in [["README.md"], ["prototype-app/docs/frontend.md"]]:
            self.assertEqual(classifier.classify(files, "pull_request"), dict(application=False, performance=False))
            self.assertTrue(classifier.classify(files, "push")["application"])
        for files in [[], ["prototype-app/docs/data.json"], ["prototype-app/frontend/src/App.tsx"], [".github/workflows/quality.yml"], ["README.md", "package.json"]]:
            self.assertTrue(classifier.classify(files, "pull_request")["application"])
        self.assertTrue(classifier.classify([".github/scripts/check-quality-gate.py"], "pull_request")["performance"])

    def needs(self, application="true"):
        result = {key: dict(result="success") for key in gate.APPLICATION_JOBS | gate.ALWAYS_JOBS}
        result["changes"]["outputs"] = dict(application=application, routes="NONE")
        result["frontend-sweep"] = dict(result="skipped")
        return result

    def test_required_results(self):
        self.assertEqual(gate.failures(self.needs()), [])
        for job in gate.ALWAYS_JOBS | gate.APPLICATION_JOBS:
            for state in ["failure", "cancelled", "skipped", None]:
                needs = self.needs()
                needs[job]["result"] = state
                self.assertTrue(gate.failures(needs), (job, state))

    def test_full_sweep_is_required_when_selected(self):
        needs = self.needs()
        needs["changes"]["outputs"]["routes"] = "FULL_SWEEP"
        self.assertTrue(gate.failures(needs))
        needs["frontend-sweep"]["result"] = "success"
        self.assertEqual(gate.failures(needs), [])

    def test_only_explicit_skips_are_allowed(self):
        needs = self.needs("false")
        for job in gate.APPLICATION_JOBS:
            needs[job]["result"] = "skipped"
        self.assertEqual(gate.failures(needs), [])
        needs["secrets"]["result"] = "skipped"
        self.assertTrue(gate.failures(needs))
        needs = self.needs("invalid")
        self.assertTrue(gate.failures(needs))


if __name__ == "__main__":
    unittest.main()
