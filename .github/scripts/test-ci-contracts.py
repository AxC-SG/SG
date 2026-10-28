import importlib.util
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
    def test_selection(self):
        for files in [["README.md"], ["prototype-app/docs/frontend.md"]]:
            self.assertEqual(classifier.classify(files, "pull_request"), dict(application=False, performance=False))
            self.assertTrue(classifier.classify(files, "push")["application"])
        for files in [[], ["prototype-app/docs/data.json"], ["prototype-app/frontend/src/App.tsx"], [".github/workflows/quality.yml"], ["README.md", "package.json"]]:
            self.assertTrue(classifier.classify(files, "pull_request")["application"])
        self.assertTrue(classifier.classify([".github/scripts/check-quality-gate.py"], "pull_request")["performance"])

    def needs(self, application="true"):
        result = {key: dict(result="success") for key in gate.APPLICATION_JOBS | gate.ALWAYS_JOBS}
        result["changes"]["outputs"] = dict(application=application)
        return result

    def test_required_results(self):
        self.assertEqual(gate.failures(self.needs()), [])
        for job in gate.ALWAYS_JOBS | gate.APPLICATION_JOBS:
            for state in ["failure", "cancelled", "skipped", None]:
                needs = self.needs()
                needs[job]["result"] = state
                self.assertTrue(gate.failures(needs), (job, state))

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
