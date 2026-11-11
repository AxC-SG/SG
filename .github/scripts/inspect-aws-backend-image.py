#!/usr/bin/env python3
"""Check the packaged AWS runtime without starting the app or reaching a database."""

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

    return {
        "image_id": config["Id"], "platform": "linux/amd64",
        "rds_ca_sha256_by_region": ca_sha_by_region, "migration_heads": heads,
    }


if __name__ == "__main__":
    if len(sys.argv) != 2 or sys.argv[1].startswith("-"):
        sys.exit("Usage: inspect-aws-backend-image.py IMAGE")
    try:
        print(json.dumps(inspect(sys.argv[1]), indent=2, sort_keys=True))
    except (ValueError, subprocess.CalledProcessError) as failure:
        sys.exit(f"Unable to verify AWS backend image: {failure}")
