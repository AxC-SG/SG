"""Positive/negative controls for the SQL checksum exception; never prints tokens."""
import argparse
import hashlib
import json
from pathlib import Path
import secrets
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
MANIFEST = "prototype-app/Working Knowledge/AWS/release-evidence/postmerge-20261111/packaged-source-verification.json"
FILES = ["V9__bom_ingest_api_keys.sql", "V2__invitation_token_hashes.sql"]


def check(scanner, path, records, expect_leak, rule="generic-api-key"):
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        target = root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text((records if isinstance(records, str) else json.dumps(records, indent=2)) + "\n")
        for args in [["init", "-q"], ["add", "."], ["-c", "user.name=Scanner Control", "-c", "user.email=control@example.invalid", "commit", "-qm", "synthetic control"]]:
            subprocess.run(["git", *args], cwd=root, check=True, capture_output=True)
        report = root / "report.json"
        result = subprocess.run([
            str(scanner), "git", ".", "--config", str(ROOT / ".gitleaks.toml"),
            "--gitleaks-ignore-path", str(ROOT / ".gitleaksignore"),
            "--log-opts=--all", "--redact", "--report-format=json", "--report-path", str(report)
        ], cwd=root, capture_output=True)
        if result.returncode not in [0, 1]:
            raise AssertionError("Scanner execution failed; inspect its configuration.")
        findings = json.loads(report.read_text())
        detected = any(f["RuleID"] == rule for f in findings)
        if detected != expect_leak or (not expect_leak and findings):
            raise AssertionError("Checksum exception control produced an unexpected result.")


def check_detected(scanner, path, make_records, rule="generic-api-key", attempts=5):
    """Random tokens are occasionally skipped by the scanner's generic-key filters (about 1 in 150).
    A true detection regression fails every attempt, so retry with fresh tokens before failing."""
    for _ in range(attempts):
        try:
            check(scanner, path, make_records(), True, rule)
            return
        except AssertionError:
            continue
    raise AssertionError("Checksum exception control produced an unexpected result.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scanner", required=True, type=Path)
    args = parser.parse_args()
    scanner = args.scanner.resolve()
    records = {"postgres_reset/" + name: hashlib.sha256((ROOT / "prototype-app/backend/src/main/resources/db/migration/postgres_reset" / name).read_bytes()).hexdigest() for name in FILES}
    recorded = json.loads((ROOT / MANIFEST).read_text())["migration_sha256"]
    assert all(recorded[key] == value for key, value in records.items())
    check(scanner, MANIFEST, records, False)
    check(scanner, "unrelated.json", records, True)
    check_detected(scanner, MANIFEST, lambda: {"postgres_reset/" + FILES[0]: secrets.token_urlsafe(32)})
    check_detected(scanner, MANIFEST, lambda: {"api_key": secrets.token_urlsafe(32)})
    check_detected(scanner, "GHSA_NEXT_STEPS.md", lambda: 'curl https://example.invalid/api -H "X-API-Key: ' + secrets.token_urlsafe(32) + '"', "curl-auth-header")
    print("Five controls passed; credential values, wrong paths and new curl headers remain detected.")


if __name__ == "__main__":
    main()
