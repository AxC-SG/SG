#!/usr/bin/env python3
"""Check the packaged AWS runtime without starting the app or reaching a database."""

import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[2]
BACKEND = ROOT / "prototype-app/backend"
MIGRATION = r"V([0-9]+)__[^\s/]+\.sql"
CA_BUNDLES = {
    "us-east-1": "/app/rds-ca.pem",
    "ap-southeast-2": "/app/rds-ca-ap-southeast-2.pem",
}


def catalog_fingerprint(files):
    """SHA-256 over every packaged migration: line, version order, name and content digest.

    Equal heads with a different fingerprint mean the migration catalog changed without a new
    version, so a release cannot be proven schema-neutral from heads alone.
    """
    order = {"platform": 0, "tenant": 1}
    lines = [
        f"{label}/{name} {sha}\n"
        for (label, name), sha in sorted(
            files.items(), key=lambda item: (order[item[0][0]], int(re.match(MIGRATION, item[0][1])[1]), item[0][1]))
    ]
    return hashlib.sha256("".join(lines).encode()).hexdigest()


def packaged_digests(image_id, paths):
    """Content digests of the migration files inside the image's application jar."""
    output = subprocess.check_output(
        [
            "docker", "run", "--rm", "--platform=linux/amd64", "--network=none", "--read-only",
            "--cap-drop=ALL", "--security-opt=no-new-privileges", "--entrypoint=/bin/sh", image_id, "-ec",
            """
            for path in "$@"; do
              sum=$(busybox unzip -p /app/vulnwatch-backend.jar "$path" | sha256sum)
              printf '%s %s\\n' "${sum%% *}" "$path"
            done
            """,
            "digests", *paths,
        ],
        text=True,
    )
    return {path: sha for sha, path in (line.split() for line in output.splitlines())}


def inspect(image):
    metadata = json.loads(subprocess.check_output(["docker", "image", "inspect", image], text=True))
    [config] = metadata
    if (config["Os"], config["Architecture"], config["Config"]["User"]) != ("linux", "amd64", "vulnwatch:vulnwatch"):
        raise ValueError("The AWS backend image must be Linux/amd64 and run as vulnwatch.")
    payload = subprocess.check_output(
        [
            "docker", "run", "--rm", "--platform=linux/amd64", "--network=none", "--read-only",
            "--cap-drop=ALL", "--security-opt=no-new-privileges", "--entrypoint=/bin/sh", config["Id"], "-ec",
            """
            test "$(id -u)" -ne 0
            MIGRATION_DB_HOST=fixture.internal MIGRATION_DB_NAME=fixture \
              MIGRATION_DB_USERNAME=fixture_owner MIGRATION_DB_PASSWORD=fixture \
              RUNTIME_DB_PASSWORD=fixture APP_CREDENTIAL_ENCRYPTION_KEY=fixture \
              /app/scripts/run-schema-migration.sh --validate-env-only >&2
            sha256sum "$@"
            busybox unzip -l /app/vulnwatch-backend.jar
            """,
            "inspect", *CA_BUNDLES.values(),
        ],
        text=True,
    )
    *ca_lines, listing = payload.split("\n", len(CA_BUNDLES))
    checksums = {path: sha for sha, path in (line.split() for line in ca_lines)}
    dockerfile = (BACKEND / "Dockerfile").read_text()
    ca_sha_by_region = {}
    for region, path in CA_BUNDLES.items():
        url = f"https://truststore.pki.rds.amazonaws.com/{region}/{region}-bundle.pem"
        pin = re.search(
            rf"^ADD --checksum=sha256:([0-9a-f]{{64}}) --chmod=0444 {re.escape(url)} {re.escape(path)}$",
            dockerfile, re.M,
        )
        if pin is None or checksums.get(path) != pin[1]:
            raise ValueError(f"The packaged RDS CA bundle for {region} does not match its Dockerfile pin.")
        ca_sha_by_region[region] = pin[1]

    heads = {}
    catalog = {}
    for label, directory in (("platform", "postgres_reset"), ("tenant", "tenant")):
        base = f"db/migration/{directory}"
        source = {
            path.name for path in (BACKEND / "src/main/resources" / base).iterdir()
            if re.fullmatch(MIGRATION, path.name)
        }
        names = re.findall(rf"BOOT-INF/classes/{base}/({MIGRATION})$", listing, re.M)
        packaged = {name for name, _ in names}
        if not source or packaged != source or len(names) != len(source):
            raise ValueError(f"Packaged {label} migrations differ from source.")
        heads[label] = max(int(version) for _, version in names)
        catalog.update({(label, name): f"BOOT-INF/classes/{base}/{name}" for name, _ in names})

    digests = packaged_digests(config["Id"], sorted(catalog.values()))
    files = {}
    for (label, name), path in catalog.items():
        source = BACKEND / "src/main/resources" / path.removeprefix("BOOT-INF/classes/")
        if digests.get(path) != hashlib.sha256(source.read_bytes()).hexdigest():
            raise ValueError(f"Packaged {label} migration {name} differs from source.")
        files[(label, name)] = digests[path]

    return {
        "image_id": config["Id"], "platform": "linux/amd64",
        "rds_ca_sha256_by_region": ca_sha_by_region, "migration_heads": heads,
        "migration_catalog_sha256": catalog_fingerprint(files),
    }


if __name__ == "__main__":
    if len(sys.argv) != 2 or sys.argv[1].startswith("-"):
        sys.exit("Usage: inspect-aws-backend-image.py IMAGE")
    try:
        print(json.dumps(inspect(sys.argv[1]), indent=2, sort_keys=True))
    except (ValueError, subprocess.CalledProcessError) as failure:
        sys.exit(f"Unable to verify AWS backend image: {failure}")
