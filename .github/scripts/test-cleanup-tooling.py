"""Offline behavior checks for shared configuration, installation and credential cleanup."""
import contextlib
import io
import importlib.util
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
import zipfile
import hashlib

ROOT = Path(__file__).resolve().parents[2]
LAB = ROOT / "prototype-app/infrastructure/lab"


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


release = load("cleanup_release", LAB / "scripts/release.py")
runtime = load("runtime_config", LAB / "scripts/release_lib/runtime_config.py")


class RuntimeConfigTest(unittest.TestCase):
    def test_all_modes_keep_common_references_and_isolate_enrollment(self):
        common = json.loads((LAB / "config/runtime-common.json").read_text())["backend_candidate"]
        for mode in runtime.MODES:
            with self.subTest(mode=mode):
                config = runtime.runtime_config(mode, LAB / "config")
                candidate = config["backend_candidate"]
                for key, value in common.items():
                    self.assertEqual(candidate[key], value, key)
                self.assertEqual(candidate["start_services"], mode == "running")
                self.assertEqual(config["runtime_ingress_enabled"], mode != "down")
                self.assertEqual(config["nat_gateway_mode"], "none" if mode == "down" else "single")
                self.assertEqual("managed_installation" in candidate, mode == "stopped")
        with self.assertRaises(ValueError):
            runtime.runtime_config("../running", LAB / "config")

    def test_cycle_and_release_render_identical_running_configuration(self):
        shell = f'source "{LAB}/scripts/lab.sh"; file="$(runtime_file up)"; cat "$file"'
        result = subprocess.run(["bash", "-ec", shell], text=True, capture_output=True, check=True)
        self.assertEqual(json.loads(result.stdout), runtime.runtime_config("running", LAB / "config"))
        self.assertEqual(release.runtime_config("running", release.CFG), json.loads(result.stdout))


class WorkspaceTest(unittest.TestCase):
    def test_cli_removes_workspace_on_success_refusal_invalid_command_and_interrupt(self):
        for outcome in (None, release.ReleaseError("fixture refusal"), ValueError("fixture error"), KeyboardInterrupt()):
            with self.subTest(outcome=type(outcome).__name__):
                lab = release.AwsLab("", "terraform")
                self.addCleanup(lab.close)
                work = lab.work
                (work / "fixture.tfplan").write_text("disposable plan")
                self.assertEqual(stat.S_IMODE(work.stat().st_mode), 0o700)
                with contextlib.redirect_stderr(io.StringIO()), mock.patch.object(release, "AwsLab", return_value=lab), mock.patch.object(lab, "guard", side_effect=outcome), mock.patch.object(release.Release, "status"):
                    if isinstance(outcome, KeyboardInterrupt):
                        with self.assertRaises(KeyboardInterrupt):
                            release.main(["status"])
                    else:
                        self.assertEqual(release.main(["status"]), 0 if outcome is None else 1 if isinstance(outcome, release.ReleaseError) else 2)
                self.assertFalse(work.exists())
        lab = release.AwsLab("", "terraform")
        self.addCleanup(lab.close)
        with contextlib.redirect_stderr(io.StringIO()), mock.patch.object(release, "AwsLab", return_value=lab):
            self.assertEqual(release.main(["unknown"]), 2)
        self.assertFalse(lab.work.exists())


class InstallerTest(unittest.TestCase):
    def test_checksum_mismatch_never_installs_or_updates_path(self):
        for valid in (True, False):
            with self.subTest(valid=valid), tempfile.TemporaryDirectory() as temp:
                directory = Path(temp)
                scripts = directory / "scripts"
                scripts.mkdir()
                installer = scripts / "install-terraform.sh"
                shutil.copyfile(ROOT / ".github/scripts/install-terraform.sh", installer)
                archive = directory / "fixture.zip"
                with zipfile.ZipFile(archive, "w") as zipped:
                    zipped.writestr("terraform", "fixture binary")
                checksum = hashlib.sha256(archive.read_bytes()).hexdigest() if valid else "0" * 64
                (directory / "tool-versions.json").write_text(json.dumps({"terraform": {"version": "1.13.5", "linux_amd64_sha256": checksum}}))
                binary = directory / "bin"
                binary.mkdir()
                curl = binary / "curl"
                curl.write_text('#!/usr/bin/env bash\nset -eu\ncp "$FIXTURE_ARCHIVE" "${@: -1}"\n')
                curl.chmod(0o755)
                runner = directory / "runner"
                runner.mkdir()
                path = directory / "github-path"
                path.touch()
                result = subprocess.run(["bash", str(installer)], env={**os.environ, "PATH": f"{binary}{os.pathsep}{os.environ['PATH']}", "FIXTURE_ARCHIVE": str(archive), "RUNNER_TEMP": str(runner), "GITHUB_PATH": str(path)}, capture_output=True, text=True)
                self.assertEqual(result.returncode == 0, valid, result.stderr)
                self.assertEqual((runner / "terraform-cli/terraform").exists(), valid)
                self.assertEqual(bool(path.read_text()), valid)


class ReconcileShellTest(unittest.TestCase):
    def test_tenant_config_is_private_removed_and_never_printed_even_when_release_fails(self):
        configs = ("", '{"tenant":{"password":"synthetic-private-value"}}', '{"platform":{},"tenant":{}}', '{"tenant":[]}', 'invalid json')
        for config in configs:
            for release_status in (0, 1):
                with self.subTest(config=config, release_status=release_status), tempfile.TemporaryDirectory() as temp:
                    directory = Path(temp)
                    binary = directory / "bin"
                    binary.mkdir()
                    fake = binary / "python3"
                    fake.write_text(f'#!{sys.executable}\n' + '''import json, os, pathlib, stat, sys
config = os.environ.get("LAB_SMOKE_CONFIG")
result = {"mode": stat.S_IMODE(pathlib.Path(config).stat().st_mode) if config else None,
          "secret_unset": "SMOKE_CONFIG_JSON" not in os.environ,
          "args": sys.argv[1:]}
pathlib.Path(os.environ["MARKER"]).write_text(json.dumps(result))
print('{"outcome":"fixture"}')
sys.exit(int(os.environ["FAKE_EXIT"]))
''')
                    fake.chmod(0o755)
                    marker = directory / "marker.json"
                    env = {key: value for key, value in os.environ.items() if key != "LAB_SMOKE_CONFIG"}
                    env.update(PATH=f"{binary}{os.pathsep}{os.environ['PATH']}", RUNNER_TEMP=str(directory), SMOKE_CONFIG_JSON=config, FRONTEND="true", MARKER=str(marker), FAKE_EXIT=str(release_status))
                    result = subprocess.run(["bash", str(ROOT / ".github/scripts/run-lab-reconcile.sh")], env=env, cwd=ROOT, text=True, capture_output=True)
                    valid = not config or config.startswith('{"tenant":{"password"')
                    self.assertEqual(marker.exists(), valid, result.stderr)
                    self.assertEqual(result.returncode, release_status if valid else 1)
                    self.assertEqual(list(directory.glob("smoke.*")), [])
                    self.assertNotIn("synthetic-private-value", result.stdout + result.stderr)
                    if valid:
                        report = json.loads(marker.read_text())
                        self.assertTrue(report["secret_unset"])
                        self.assertEqual(report["mode"], 0o600 if config else None)
                        self.assertEqual(report["args"][-3:], ["reconcile", "--yes", "--frontend"])


if __name__ == "__main__":
    unittest.main()
