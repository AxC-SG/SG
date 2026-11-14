import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location("select", Path(__file__).with_name("select-aws-candidate.py"))
selector = importlib.util.module_from_spec(spec)
spec.loader.exec_module(selector)

REPO = "AxC-SG/SG"
SHA = "a" * 40
NEWER = "b" * 40
WORKFLOWS = selector.CHECKS + (selector.TRIVY,)


def run(workflow, sha=SHA, status="completed", conclusion="success", run_id=None, event="push",
        branch="main", repo=REPO):
    return {"id": run_id or 100 + WORKFLOWS.index(workflow), "workflow_id": WORKFLOWS.index(workflow),
            "head_sha": sha, "status": status, "conclusion": conclusion, "event": event,
            "head_branch": branch, "head_repository": {"full_name": repo}}


class FakeApi:
    def __init__(self, runs=None, head=SHA, published=()):
        self.runs = {workflow: run(workflow) for workflow in WORKFLOWS}
        self.runs.update(runs or {})
        self.head = head
        self.published = published

    def __call__(self, path, params=None):
        prefix = f"repos/{REPO}/"
        assert path.startswith(prefix), path
        path = path[len(prefix):]
        for workflow in WORKFLOWS:
            if path == f"actions/workflows/{workflow}":
                return {"id": WORKFLOWS.index(workflow)}
            if path == f"actions/workflows/{workflow}/runs":
                assert params["event"] == "push" and params["branch"] == "main", params
                found = self.runs.get(workflow)
                return {"workflow_runs": [found] if found and found["head_sha"] == params["head_sha"] else []}
        if path.startswith("actions/runs/"):
            wanted = int(path.rsplit("/", 1)[1])
            return next(item for item in self.runs.values() if item and item["id"] == wanted)
        if path == "commits/main":
            return {"sha": self.head}
        if path == "actions/artifacts":
            return {"artifacts": [item for item in self.published if item["name"] == params["name"]]}
        raise AssertionError(path)


TRIGGER = run(selector.TRIVY)


class AutomaticTest(unittest.TestCase):
    def select(self, api, trigger=TRIGGER, target="lab"):
        return selector.select(api, REPO, "workflow_run", target, trigger=trigger)

    def test_publishes_when_every_check_passed_on_the_main_head(self):
        self.assertEqual(self.select(FakeApi()), {"target": "lab", "source_sha": SHA, "candidate_run": "103"})

    def test_waits_until_every_check_completed(self):
        for workflow in WORKFLOWS:
            for missing in (None, run(workflow, status="in_progress", conclusion=None)):
                with self.assertRaisesRegex(selector.Skip, "waiting for " + workflow):
                    self.select(FakeApi({workflow: missing}))

    def test_skips_when_a_check_did_not_pass(self):
        for workflow in WORKFLOWS:
            for conclusion in ("failure", "cancelled", "skipped"):
                with self.assertRaisesRegex(selector.Skip, conclusion):
                    self.select(FakeApi({workflow: run(workflow, conclusion=conclusion)}))

    def test_ignores_runs_from_other_repositories(self):
        with self.assertRaisesRegex(selector.Skip, "waiting for quality.yml"):
            self.select(FakeApi({"quality.yml": run("quality.yml", repo="fork/SG")}))

    def test_skips_triggers_that_are_not_pushes_to_main(self):
        for trigger in (run(selector.TRIVY, event="pull_request"), run(selector.TRIVY, event="schedule"),
                        run(selector.TRIVY, branch="feature"), run(selector.TRIVY, repo="fork/SG")):
            with self.assertRaisesRegex(selector.Skip, "not a push to main"):
                self.select(FakeApi(), trigger)

    def test_skips_superseded_commits(self):
        with self.assertRaisesRegex(selector.Skip, "superseded"):
            self.select(FakeApi(head=NEWER))

    def test_publishes_each_commit_once(self):
        name = selector.publication_name("lab", SHA)
        with self.assertRaisesRegex(selector.Skip, "already published"):
            self.select(FakeApi(published=[{"name": name, "expired": False}]))
        # An expired record or another commit's record does not block publication.
        self.assertTrue(self.select(FakeApi(published=[{"name": name, "expired": True},
                                                       {"name": selector.publication_name("lab", NEWER),
                                                        "expired": False}])))

    def test_never_publishes_production_automatically(self):
        with self.assertRaisesRegex(selector.Rejected, "lab only"):
            self.select(FakeApi(), target="production")


class ManualTest(unittest.TestCase):
    def select(self, api, candidate_run="103", target="lab"):
        return selector.select(api, REPO, "workflow_dispatch", target, candidate_run=candidate_run)

    def test_publishes_a_qualified_trivy_run_to_either_target(self):
        for target in ("lab", "production"):
            self.assertEqual(self.select(FakeApi(), target=target),
                             {"target": target, "source_sha": SHA, "candidate_run": "103"})

    def test_publishes_an_older_commit_on_request(self):
        self.assertEqual(self.select(FakeApi(head=NEWER))["source_sha"], SHA)

    def test_rejects_a_check_that_did_not_pass(self):
        for workflow in selector.CHECKS:
            for replacement in (None, run(workflow, conclusion="failure"), run(workflow, status="in_progress", conclusion=None)):
                with self.assertRaisesRegex(selector.Rejected, workflow):
                    self.select(FakeApi({workflow: replacement}))

    def test_rejects_runs_that_are_not_successful_trivy_pushes_on_main(self):
        for replacement in (run(selector.TRIVY, conclusion="failure"), run(selector.TRIVY, event="pull_request"),
                            run(selector.TRIVY, branch="feature"), run(selector.TRIVY, repo="fork/SG")):
            with self.assertRaisesRegex(selector.Rejected, "not a successful Trivy push"):
                self.select(FakeApi({selector.TRIVY: replacement}))
        with self.assertRaisesRegex(selector.Rejected, "not a successful Trivy push"):
            self.select(FakeApi(), candidate_run="100")

    def test_rejects_malformed_run_ids(self):
        for candidate in ("", None, "12a", "1;2"):
            with self.assertRaisesRegex(selector.Rejected, "workflow run ID"):
                self.select(FakeApi(), candidate_run=candidate)


class EventTest(unittest.TestCase):
    def test_rejects_other_events(self):
        with self.assertRaises(selector.Rejected):
            selector.select(FakeApi(), REPO, "push", "lab")


if __name__ == "__main__":
    unittest.main()
