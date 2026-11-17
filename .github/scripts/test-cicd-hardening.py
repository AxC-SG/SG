"""One offline regression suite for publication trust and release recovery."""
import copy
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import unittest
from unittest import mock
import zipfile

ROOT = Path(__file__).resolve().parents[2]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


support = load('release_support', ROOT / 'prototype-app/infrastructure/lab/scripts/tests/support.py')
r = support.release
p = r.provenance
SHA = support.NEW_SHA


class ProvenanceTest(unittest.TestCase):
    def setUp(self):
        self.runs = {
            1: {'id': 1, 'workflow_id': 7, 'path': '.github/workflows/quality.yml', 'event': 'push', 'head_branch': 'main',
                'head_sha': SHA, 'head_repository': {'full_name': r.REPO}},
            2: {'path': '.github/workflows/aws-publish-candidate.yml', 'event': 'workflow_dispatch',
                'head_branch': 'main', 'head_sha': support.OLD_SHA, 'head_repository': {'full_name': r.REPO}}}
        self.artifacts = [{'id': i, 'expired': False, 'created_at': str(i), 'workflow_run': {'id': i}}
                          for i in (1, 2)]
        self.jobs = {1: [{'name': 'publish / Publish verified candidate to ECR', 'conclusion': 'success'},
                         {'name': 'Quality gate', 'conclusion': 'success'}],
                     2: [{'name': 'Publish verified candidate to ECR', 'conclusion': 'success'}]}

    def api(self, path, params=None):
        if path.endswith("/actions/workflows/quality.yml"):
            return {"id": 7}
        if path.endswith('/artifacts'):
            return {'artifacts': self.artifacts}
        parts = path.split('/')
        run_id = int(parts[5])
        return {'jobs': self.jobs[run_id]} if parts[-1] == 'jobs' else self.runs[run_id]

    def test_both_trusted_producers_and_manual_older_candidate_remain_valid(self):
        self.assertEqual([a['id'] for a in p.trusted_artifacts(self.api, r.REPO, self.artifacts, SHA)], [1, 2])
        p.validate_candidate(self.api, r.REPO, {'candidate_run': '1'}, SHA)

    def test_rejects_untrusted_producers_and_failed_publications(self):
        for change in ({'event': 'pull_request'}, {'event': 'schedule'}, {'head_branch': 'topic'},
                       {'head_repository': {'full_name': 'fork/SG'}}, {'head_sha': support.OLD_SHA},
                       {'path': '.github/workflows/unrelated.yml'}, {'workflow_id': 8}):
            with self.subTest(change=change):
                self.runs[1] = {**self.runs[1], **change}
                if 'workflow_id' not in change:
                    self.assertEqual(p.trusted_artifacts(self.api, r.REPO, self.artifacts[:1], SHA), [])
                with self.assertRaises(ValueError):
                    p.validate_candidate(self.api, r.REPO, {'candidate_run': '1'}, SHA)
                self.setUp()
        self.jobs[1][0]['conclusion'] = 'failure'
        self.assertEqual(p.trusted_artifacts(self.api, r.REPO, self.artifacts[:1], SHA), [])
        self.assertEqual(p.trusted_artifacts(self.api, r.REPO, [{'expired': False}], SHA), [])

    def test_rejects_forged_candidate_binding_and_missing_gate(self):
        with self.assertRaises(ValueError):
            p.validate_candidate(self.api, r.REPO, {'candidate_run': '2'}, SHA)
        self.jobs[1][1]['conclusion'] = 'failure'
        with self.assertRaises(ValueError):
            p.validate_candidate(self.api, r.REPO, {'candidate_run': '1'}, SHA)

    def test_consumer_ignores_newer_pr_artifact_and_downloads_verified_id_repeatedly(self):
        self.runs[2]['event'] = 'pull_request'
        lab = r.AwsLab('', 'terraform')
        self.addCleanup(lab.close)
        lab.github_api = self.api
        lab.run = lambda *args, **kwargs: json.dumps({'artifacts': self.artifacts})
        payload = io.BytesIO()
        record = support.publication()
        record['candidate_run'] = '1'
        with zipfile.ZipFile(payload, 'w') as archive:
            archive.writestr('aws-publication.json', json.dumps(record))
        with mock.patch.object(r.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, payload.getvalue())) as download:
            self.assertEqual(lab.publication(SHA), record)
            self.assertEqual(lab.publication(SHA), record)
            self.assertTrue(all(call.args[0][-1].endswith('/artifacts/1/zip') for call in download.call_args_list))


class RecoveryTest(unittest.TestCase):
    def test_partial_first_mutations_keep_pending(self):
        for operation in ('reconcile', 'neutral', 'forward', 'rollback'):
            with self.subTest(operation=operation):
                lab = support.FakeLab(support.inputs(heads=support.V20 if operation == 'forward' else support.V23))
                runner = r.Release(lab)
                if operation == 'rollback':
                    runner.deploy('main')
                    runner.accept()
                def fail(*args):
                    lab.live['api'] = support.NEW
                    raise r.ReleaseError('partial mutation')
                lab.apply = fail
                lab.stop_services = fail
                if operation == 'reconcile':
                    self.assertEqual(runner.reconcile(assume_yes=True)['outcome'], 'failed')
                else:
                    with self.assertRaises(r.ReleaseError):
                        runner.rollback() if operation == 'rollback' else runner.deploy('main')
                self.assertIsNotNone(lab.inputs['pending'])
                self.assertNotIn(r.LOCK_KEY, lab.store)

    def test_initial_state_write_failure_changes_nothing(self):
        lab = support.FakeLab(support.inputs())
        original = lab.s3_put
        def fail(key, data, create_only=False):
            if key == r.INPUTS_KEY:
                raise r.ReleaseError('state unavailable')
            return original(key, data, create_only)
        lab.s3_put = fail
        self.assertEqual(r.Release(lab).reconcile(assume_yes=True)['outcome'], 'blocked')
        self.assertFalse(any(isinstance(call, tuple) and call[0] == 'apply' for call in lab.calls))

    def test_interrupted_migration_resumes_existing_task(self):
        lab = support.FakeLab(support.inputs())
        runner = r.Release(lab)
        original = lab.wait_task
        lab.wait_task = mock.Mock(side_effect=r.ReleaseError('task still running'))
        with self.assertRaises(r.ReleaseError):
            runner.deploy('main')
        task = lab.record()['migrator_task']
        lab.wait_task = mock.Mock(side_effect=original)
        runner.deploy('main')
        self.assertEqual(lab.calls.count('migrate'), 1)
        lab.wait_task.assert_called_once_with(task)

    def test_lost_run_task_response_reuses_stable_token(self):
        lab = support.FakeLab(support.inputs())
        runner = r.Release(lab)
        tokens = []
        def launch(outputs, token):
            tokens.append(token)
            if len(tokens) == 1:
                raise r.ReleaseError('lost response')
            return 'existing-task'
        lab.run_migrator = launch
        with self.assertRaises(r.ReleaseError):
            runner.deploy('main')
        runner.deploy('main')
        self.assertEqual(len(tokens), 2)
        self.assertEqual(tokens[0], tokens[1])

    def test_ambiguous_launch_after_token_window_requires_operator(self):
        lab = support.FakeLab(support.inputs())
        runner = r.Release(lab)
        lab.run_migrator = mock.Mock(side_effect=r.ReleaseError('lost response'))
        with self.assertRaises(r.ReleaseError):
            runner.deploy('main')
        record = lab.record()
        record['migrator_attempted_at'] = '2020-01-01T00:00:00Z'
        lab.store[f"{r.RECORDS}/{record['release_id']}.json"] = record
        with self.assertRaisesRegex(r.ReleaseError, 'safe retry window expired'):
            runner.deploy('main')
        self.assertEqual(lab.run_migrator.call_count, 1)

    def test_quiet_failure_during_bake_is_rejected_without_smoke(self):
        lab = support.FakeLab(support.inputs())
        lab.smoke = None
        def die(moment):
            lab.http_status = lambda path: 503
            lab.target_states = lambda: ['unhealthy']
        lab.wait_until = die
        with self.assertRaisesRegex(r.ReleaseError, 'automated checks failed'):
            r.Release(lab).deploy('main')
        self.assertFalse(lab.record()['checks']['api targets healthy after bake']['passed'])


if __name__ == '__main__':
    unittest.main()
