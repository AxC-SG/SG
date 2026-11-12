#!/usr/bin/env python3
"""Verify retained bytes and either Docker image-store identity, without publishing."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tarfile


def digest(data):
    return "sha256:" + hashlib.sha256(data).hexdigest()


def verify(archive, release, source_sha, loaded=None):
    if not re.fullmatch(r"[0-9a-f]{40}", source_sha) or release.get("source_sha") != source_sha:
        raise ValueError("Release source does not match the reviewed SHA.")
    with Path(archive).open("rb") as stream:
        checksum = hashlib.sha256()
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            checksum.update(chunk)
        archive_sha = checksum.hexdigest()
    if archive_sha != release.get("archive_sha256"):
        raise ValueError("Archive checksum does not match the release manifest.")
    image_ref = f"scoutgrid-aws-backend:{source_sha}"
    manifest_digest = None
    with tarfile.open(archive, "r:gz") as saved:
        names = saved.getnames()
        if len(names) != len(set(names)):
            raise ValueError("Archive has duplicate members.")

        def read(name):
            member = saved.getmember(name)
            if not member.isfile():
                raise ValueError("Image metadata must be a regular archive member.")
            return saved.extractfile(member).read()

        entries = json.loads(read("manifest.json"))
        if len(entries) != 1 or entries[0].get("RepoTags") != [image_ref]:
            raise ValueError("Archive must contain only the reviewed image tag.")
        entry = entries[0]
        raw_config = read(entry["Config"])
        config_digest = digest(raw_config)
        config = json.loads(raw_config)
        if (config.get("os"), config.get("architecture"), config.get("config", {}).get("User")) != (
            "linux", "amd64", "vulnwatch:vulnwatch"
        ) or release.get("platform") != "linux/amd64":
            raise ValueError("Unexpected runtime platform or user.")
        if "index.json" in names:
            descriptors = json.loads(read("index.json"))["manifests"]
            if len(descriptors) != 1:
                raise ValueError("Expected one saved OCI manifest.")
            descriptor = descriptors[0]
            manifest_digest = descriptor["digest"]
            if not re.fullmatch(r"sha256:[0-9a-f]{64}", manifest_digest):
                raise ValueError("Invalid OCI manifest digest.")
            raw_manifest = read("blobs/sha256/" + manifest_digest.split(":")[1])
            if digest(raw_manifest) != manifest_digest or len(raw_manifest) != descriptor["size"]:
                raise ValueError("Saved OCI descriptor does not match its bytes.")
            oci = json.loads(raw_manifest)
            if oci["config"]["digest"] != config_digest or oci["config"]["size"] != len(raw_config):
                raise ValueError("OCI manifest references a different configuration.")
            if ["blobs/sha256/" + layer["digest"].split(":")[1] for layer in oci["layers"]] != entry["Layers"]:
                raise ValueError("OCI and Docker layer order differ.")
        allowed_ids = {config_digest}
        if manifest_digest:
            allowed_ids.add(manifest_digest)
        if release.get("image_id") not in allowed_ids:
            raise ValueError("Recorded image identity is absent from the scanned archive.")
        if loaded is not None:
            if loaded.get("Id") not in allowed_ids:
                raise ValueError("Loaded image is not the scanned image.")
            if (loaded.get("Os"), loaded.get("Architecture")) != ("linux", "amd64"):
                raise ValueError("Loaded image platform differs.")
            if loaded.get("RootFS", {}).get("Layers") != config["rootfs"]["diff_ids"]:
                raise ValueError("Loaded filesystem differs from the scanned image.")
            for field in ["User", "Env", "Cmd", "Entrypoint", "WorkingDir", "ExposedPorts", "Healthcheck"]:
                if loaded.get("Config", {}).get(field) != config["config"].get(field):
                    raise ValueError(f"Loaded runtime configuration differs: {field}.")
    return {
        "source_sha": source_sha, "archive_sha256": archive_sha,
        "image_config_digest": config_digest, "saved_oci_manifest_digest": manifest_digest,
        "loaded_image_id": loaded.get("Id") if loaded is not None else None,
        "registry_digest": None,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", type=Path)
    parser.add_argument("manifest", type=Path)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--loaded-image", action="store_true")
    args = parser.parse_args()
    loaded = None
    if args.loaded_image:
        [loaded] = json.loads(subprocess.check_output([
            "docker", "image", "inspect", f"scoutgrid-aws-backend:{args.source_sha}"
        ], text=True))
    print(json.dumps(verify(args.archive, json.loads(args.manifest.read_text()), args.source_sha, loaded), indent=2))


if __name__ == "__main__":
    try:
        main()
    except (ValueError, KeyError, TypeError, tarfile.TarError, subprocess.CalledProcessError) as error:
        raise SystemExit(f"Archive verification failed: {error}")
