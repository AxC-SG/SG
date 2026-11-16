import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location("select", Path(__file__).with_name("select-aws-candidate.py"))
selector = importlib.util.module_from_spec(spec)
spec.loader.exec_module(selector)

REPO = "AxC-SG/SG"
SHA = "a" * 40
NEWER = "b" * 40
QUALITY_ID = 7
RUN = "103"


def run(sha=SHA, workflow_id=QUALITY_ID, event="push", branch="main", repo=REPO):
    return {"id": int(RUN), "workflow_id": workflow_id, "head_sha": sha, "event": event,
            "head_branch": branch, "head_repository": {"full_name": repo}}


def gate(conclusion="success", name=selector.GATE_JOB):
    return {"name": name, "conclusion": conclusion}


class FakeApi:
    def __init__(self, quality_run=None, jobs=None, head=SHA, published=()):
        self.run = quality_run or run()
        self.jobs = [gate(), {"name": "security / AWS backend candidate", "conclusion": "success"}] if jobs is None else jobs
        self.head = head
        self.published = published

    def __call__(self, path, params=None):
        prefix = f"repos/{REPO}/"
        assert path.startswith(prefix), path
        path = path[len(prefix):]
        if path == "actions/runs/200":
            return {**run(), "path": ".github/workflows/quality.yml"}
        if path == "actions/runs/200/jobs":
            return {"jobs": [{"name": "publish / Publish verified candidate to ECR", "conclusion": "success"}]}
        if path == f"actions/workflows/{selector.QUALITY}":
            return {"id": QUALITY_ID}
        if path == f"actions/runs/{RUN}":
            return self.run
        if path == f"actions/runs/{RUN}/jobs":
            assert params["filter"] == "latest", params
            return {"jobs": self.jobs}
        if path == "commits/main":
            return {"sha": self.head}
        if path == "actions/artifacts":
            return {"artifacts": [item for item in self.published if item["name"] == params["name"]]}
        raise AssertionError(path)


NOT_QUALITY_PUSHES = (run(workflow_id=QUALITY_ID + 1), run(event="pull_request"), run(event="schedule"),
                      run(branch="feature"), run(repo="fork/SG"))
GATE_NOT_PASSED = ([], [gate("failure")], [gate("cancelled")], [gate("skipped")], [gate(None)],
                   [gate(), gate()], [gate(name="Performance gate")])


class CalledTest(unittest.TestCase):
    def select(self, api, target="lab", run_id=RUN, sha=SHA):
        return selector.select(api, REPO, "push", target, run_id, sha)

    def test_publishes_its_own_run_when_the_gate_passed_on_the_main_head(self):
        self.assertEqual(self.select(FakeApi()), {"target": "lab", "source_sha": SHA, "candidate_run": RUN})

    def test_rejects_a_gate_that_did_not_pass(self):
        for jobs in GATE_NOT_PASSED:
            with self.assertRaisesRegex(selector.Rejected, "has not passed"):
                self.select(FakeApi(jobs=jobs))

    def test_rejects_runs_that_are_not_quality_pushes_on_main(self):
        for replacement in NOT_QUALITY_PUSHES:
            with self.assertRaisesRegex(selector.Rejected, "not a Quality push run on main"):
                self.select(FakeApi(replacement))

    def test_rejects_a_run_for_another_commit(self):
        with self.assertRaisesRegex(selector.Rejected, "not " + SHA):
            self.select(FakeApi(run(sha=NEWER)))

    def test_skips_superseded_commits(self):
        with self.assertRaisesRegex(selector.Skip, "superseded"):
            self.select(FakeApi(head=NEWER))

    def test_publishes_each_commit_once(self):
        name = selector.publication_name("lab", SHA)
        with self.assertRaisesRegex(selector.Skip, "already published"):
            self.select(FakeApi(published=[{"id": 1, "name": name, "expired": False, "created_at": "2026-11-16", "workflow_run": {"id": 200}}]))
        # An expired record or another commit's record does not block publication.
        self.assertTrue(self.select(FakeApi(published=[{"name": name, "expired": True},
                                                       {"name": selector.publication_name("lab", NEWER),
                                                        "expired": False}])))

    def test_never_publishes_production_automatically(self):
        with self.assertRaisesRegex(selector.Rejected, "lab only"):
            self.select(FakeApi(), target="production")


class ManualTest(unittest.TestCase):
    def select(self, api, candidate_run=RUN, target="lab"):
        return selector.select(api, REPO, "workflow_dispatch", target, candidate_run)

    def test_publishes_a_qualified_quality_run_to_either_target(self):
        for target in ("lab", "production"):
            self.assertEqual(self.select(FakeApi(), target=target),
                             {"target": target, "source_sha": SHA, "candidate_run": RUN})

    def test_publishes_an_older_commit_on_request(self):
        self.assertEqual(self.select(FakeApi(head=NEWER))["source_sha"], SHA)

    def test_rejects_a_gate_that_did_not_pass(self):
        for jobs in GATE_NOT_PASSED:
            with self.assertRaisesRegex(selector.Rejected, "has not passed"):
                self.select(FakeApi(jobs=jobs))

    def test_rejects_runs_that_are_not_quality_pushes_on_main(self):
        for replacement in NOT_QUALITY_PUSHES:
            with self.assertRaisesRegex(selector.Rejected, "not a Quality push run on main"):
                self.select(FakeApi(replacement))

    def test_rejects_malformed_run_ids(self):
        for candidate in ("", None, "12a", "1;2"):
            with self.assertRaisesRegex(selector.Rejected, "workflow run ID"):
                self.select(FakeApi(), candidate_run=candidate)


class EventTest(unittest.TestCase):
    def test_rejects_other_events(self):
        for event in ("workflow_run", "pull_request", "schedule"):
            with self.assertRaises(selector.Rejected):
                selector.select(FakeApi(), REPO, event, "lab", RUN, SHA)


if __name__ == "__main__":
    unittest.main()
