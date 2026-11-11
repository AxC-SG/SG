import copy
import importlib.util
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest

spec = importlib.util.spec_from_file_location("archive", Path(__file__).with_name("verify-aws-backend-archive.py"))
verifier = importlib.util.module_from_spec(spec)
spec.loader.exec_module(verifier)
SHA = "a" * 40


class ArchiveTest(unittest.TestCase):
    def fixture(self, directory, oci=True, wrong_config=False):
        config = {"os": "linux", "architecture": "amd64", "config": {"User": "vulnwatch:vulnwatch", "Cmd": ["run"]},
                  "rootfs": {"diff_ids": ["sha256:" + "c" * 64]}}
        raw = json.dumps(config).encode()
        config_id = verifier.digest(raw)
        layer = "blobs/sha256/" + "c" * 64
        path = "blobs/sha256/" + config_id.split(":")[1]
        members = {path: raw, "manifest.json": json.dumps([{"Config": path, "RepoTags": [f"scoutgrid-aws-backend:{SHA}"], "Layers": [layer]}]).encode()}
        manifest_id = None
        if oci:
            raw_manifest = json.dumps({"config": {"digest": "sha256:" + "d" * 64 if wrong_config else config_id, "size": len(raw)},
                                       "layers": [{"digest": "sha256:" + "c" * 64}]}).encode()
            manifest_id = verifier.digest(raw_manifest)
            members["blobs/sha256/" + manifest_id.split(":")[1]] = raw_manifest
            members["index.json"] = json.dumps({"manifests": [{"digest": manifest_id, "size": len(raw_manifest)}]}).encode()
        archive = Path(directory) / "image.tar.gz"
        with tarfile.open(archive, "w:gz") as saved:
            for name, value in members.items():
                info = tarfile.TarInfo(name)
                info.size = len(value)
                saved.addfile(info, io.BytesIO(value))
        release = {"source_sha": SHA, "image_id": config_id, "archive_sha256": verifier.digest(archive.read_bytes()).split(":")[1], "platform": "linux/amd64"}
        loaded = {"Id": manifest_id or config_id, "Os": "linux", "Architecture": "amd64", "RootFS": {"Layers": config["rootfs"]["diff_ids"]}, "Config": config["config"]}
        return archive, release, loaded

    def test_classic_and_containerd_image_stores(self):
        for oci in [False, True]:
            with self.subTest(oci=oci), tempfile.TemporaryDirectory() as directory:
                archive, release, loaded = self.fixture(directory, oci=oci)
                result = verifier.verify(archive, release, SHA, loaded)
                self.assertEqual(result["image_config_digest"], release["image_id"])
                loaded["Id"] = release["image_id"]
                verifier.verify(archive, release, SHA, loaded)

    def test_wrong_source_and_archive_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            archive, release, _ = self.fixture(directory)
            with self.assertRaisesRegex(ValueError, "source"):
                verifier.verify(archive, release, "b" * 40)
            release["archive_sha256"] = "0" * 64
            with self.assertRaisesRegex(ValueError, "checksum"):
                verifier.verify(archive, release, SHA)

    def test_unrelated_loaded_image_and_changed_runtime_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            archive, release, loaded = self.fixture(directory)
            for mutation in [lambda x: x.update(Id="sha256:" + "e" * 64),
                             lambda x: x["RootFS"].update(Layers=[]),
                             lambda x: x["Config"].update(User="root"),
                             lambda x: x["Config"].update(Cmd=["different"])]:
                altered = copy.deepcopy(loaded)
                mutation(altered)
                with self.assertRaises(ValueError):
                    verifier.verify(archive, release, SHA, altered)

    def test_oci_descriptor_cannot_substitute_another_configuration(self):
        with tempfile.TemporaryDirectory() as directory:
            archive, release, loaded = self.fixture(directory, wrong_config=True)
            with self.assertRaisesRegex(ValueError, "different configuration"):
                verifier.verify(archive, release, SHA, loaded)


if __name__ == "__main__":
    unittest.main()
