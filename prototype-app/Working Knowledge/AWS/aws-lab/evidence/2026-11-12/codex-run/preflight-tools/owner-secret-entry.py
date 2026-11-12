#!/usr/bin/env python3
"""Owner-run, create-only secret entry; emits metadata, never secret values.

Run only after the fresh application key and exact custody policy are bound and
verified. This is not an infrastructure creation or permission-grant script.
"""
import argparse
import base64
import datetime
import getpass
import json
import os
from pathlib import Path
import re
import secrets
import sys
import uuid
import warnings

import boto3
from botocore.exceptions import ClientError

ACCOUNT = "736486260824"
REGION = "ap-southeast-2"
SOURCE = "0ae3de9f4e4f7b1f784622d31656f30a89499043"
ROLE = "arn:aws:iam::736486260824:role/ScoutGridSydneyLabSecretCustody"
OLD_KEYS = {"22cf6682-3133-47bd-af3e-200a1464b054", "ddb15ff2-ac4a-4eaa-92d4-7b697706ea11"}
TAGS = [{"Key": k, "Value": v} for k, v in {
    "Application": "ScoutGrid", "Environment": "lab", "Profile": "Standard",
    "ManagedBy": "ScoutGridReleaseOperator",
}.items()]


def custody_session():
    base = boto3.Session(region_name=REGION)
    sts = base.client("sts")
    identity = sts.get_caller_identity()
    if identity["Account"] != ACCOUNT:
        raise ValueError("Wrong account")
    if ":assumed-role/ScoutGridSydneyLabSecretCustody/" in identity["Arn"]:
        return base, identity["Arn"]
    if ":assumed-role/AccountFullAccessRole/" not in identity["Arn"]:
        raise ValueError("Use the approved owner or custody session")
    c = sts.assume_role(RoleArn=ROLE, RoleSessionName="sg-owner-secret-entry-20261112",
                        DurationSeconds=900)["Credentials"]
    session = boto3.Session(region_name=REGION, aws_access_key_id=c["AccessKeyId"],
                            aws_secret_access_key=c["SecretAccessKey"],
                            aws_session_token=c["SessionToken"])
    who = session.client("sts").get_caller_identity()
    if not who["Arn"].startswith(f"arn:aws:sts::{ACCOUNT}:assumed-role/ScoutGridSydneyLabSecretCustody/"):
        raise ValueError("Unexpected effective caller")
    return session, who["Arn"]


def store_metadata(path, result):
    temporary = path.with_suffix(".new")
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as stream:
        json.dump(result, stream, indent=2)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)


def create_one(client, name, value, key, output, result):
    # Never update or rotate an existing secret. Partial failures need metadata
    # reconciliation, not blind replay or regeneration of keys/passwords.
    response = client.create_secret(Name="scoutgrid-lab/" + name,
        ClientRequestToken=str(uuid.uuid4()), KmsKeyId=key, Tags=TAGS,
        SecretString=json.dumps(value, separators=(",", ":")))
    arn = response["ARN"]
    if not re.fullmatch(r"arn:aws:secretsmanager:ap-southeast-2:736486260824:secret:scoutgrid-lab/"
                        + re.escape(name) + r"-[A-Za-z0-9]{6}", arn):
        raise ValueError("Unexpected created secret ARN; stop and reconcile metadata")
    result["created"].append({"name": response["Name"], "arn": arn,
                              "version_id": response["VersionId"], "fields": sorted(value)})
    store_metadata(output, result)
    print("Created " + name + "; metadata saved.")


def execute(args):
    if not sys.stdin.isatty():
        raise ValueError("A private interactive terminal is required")
    binding = json.loads(args.bindings.read_text())
    if (binding.get("account"), binding.get("region"), binding.get("source_sha")) != (ACCOUNT, REGION, SOURCE):
        raise ValueError("Binding account, region or source mismatch")
    key = binding["application_key_arn"]
    if not re.fullmatch(r"arn:aws:kms:ap-southeast-2:736486260824:key/[0-9a-f-]{36}", key):
        raise ValueError("Invalid application key ARN")
    if key.rsplit("/", 1)[-1] in OLD_KEYS or not binding.get("final_custody_effective_checks_passed"):
        raise ValueError("Fresh-key effective custody checks are required")
    if args.output.exists() or args.output.with_suffix(".new").exists():
        raise ValueError("Metadata output already exists; reconcile before retry")
    session, caller = custody_session()
    client = session.client("secretsmanager")
    names = ["runtime-db", "application-settings"] if args.mode == "runtime" else ["managed-installation"]
    preflight = boto3.Session(region_name=REGION).client("secretsmanager")
    for name in names:
        try:
            preflight.describe_secret(SecretId="scoutgrid-lab/" + name)
        except preflight.exceptions.ResourceNotFoundException:
            continue
        raise ValueError("A target secret already exists; do not overwrite or regenerate")
    result = {"source_sha": SOURCE, "caller": caller, "key_arn": key,
              "created_at": datetime.datetime.now(datetime.timezone.utc).isoformat(), "created": []}
    if args.mode == "runtime":
        with warnings.catch_warnings():
            warnings.simplefilter("error", getpass.GetPassWarning)
            turnstile = getpass.getpass("Paste the LAB Turnstile secret (hidden): ")
            repeated = getpass.getpass("Paste it again (hidden): ")
        if turnstile != repeated or not re.fullmatch(r"[A-Za-z0-9_-]{20,200}", turnstile):
            raise ValueError("Turnstile inputs do not match the expected format")
        app = {"credential_encryption_key": base64.b64encode(secrets.token_bytes(32)).decode(),
               "ai_identity_hmac_key": secrets.token_urlsafe(48), "turnstile_secret_key": turnstile}
        database = {"username": "scout_runtime", "password": secrets.token_urlsafe(48)}
        # Save metadata immediately after each mutation for partial recovery.
        create_one(client, "runtime-db", database, key, args.output, result)
        create_one(client, "application-settings", app, key, args.output, result)
    else:
        subjects = binding["verified_enrollment_subjects"]
        owner = subjects["scoutgrid.io@gmail.com"]
        admin = subjects["scoutgridtenant@gmail.com"]
        if owner == admin or not all(re.fullmatch(r"[0-9a-f-]{36}", x) for x in [owner, admin]):
            raise ValueError("Distinct verified Cognito subjects are required")
        create_one(client, "managed-installation", {"owner_email": "scoutgrid.io@gmail.com",
            "owner_subject": owner, "internal_admin_email": "scoutgridtenant@gmail.com",
            "internal_admin_subject": admin}, key, args.output, result)
    print("Complete. Only ARNs, version IDs and field names were recorded.")
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=["runtime", "enrollment"])
    parser.add_argument("--bindings", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    try:
        return execute(args)
    except ClientError as error:
        print("AWS operation stopped: " + error.response["Error"]["Code"] +
              ". Reconcile created-secret metadata before retry.", file=sys.stderr)
        return 1
    except (ValueError, KeyError, OSError, getpass.GetPassWarning, KeyboardInterrupt):
        print("Stopped safely. Check private inputs/bindings and any created-secret metadata before retry.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
