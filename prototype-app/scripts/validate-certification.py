#!/usr/bin/env python3
"""Fail-closed certification checks; the diagnostic API stays unchanged."""
import argparse
import csv
import json
import math
from pathlib import Path
import sys


def positive(value):
    if not value.isdecimal() or int(value) < 1:
        raise ValueError("iterations must be a positive integer")
    return int(value)


def reject_constant(value):
    raise ValueError(f"invalid JSON numeric constant: {value}")


def read_json(path):
    data = json.loads(Path(path).read_text(), parse_constant=reject_constant)
    if not isinstance(data, dict):
        raise ValueError(f"{path}: expected a JSON object")
    return data


def baseline(routes, samples, iterations):
    expected = {row[0] for row in csv.reader(Path(routes).read_text().splitlines(), delimiter="\t") if row}
    if not expected:
        raise ValueError("no routes configured")
    seen = set()
    with Path(samples).open() as stream:
        rows = list(csv.DictReader(stream, delimiter="\t"))
    for row in rows:
        route, iteration = row["route"], int(row["iteration"])
        key = (route, iteration)
        if route not in expected or iteration not in range(1, iterations + 1) or key in seen:
            raise ValueError(f"unexpected or duplicate sample: {key}")
        seen.add(key)
        if not row["status"].isdigit() or not 200 <= int(row["status"]) < 300 or row["classification"] != "ok":
            raise ValueError(f"{route} sample {iteration}: HTTP {row['status']} ({row['classification']})")
    if len(seen) != len(expected) * iterations:
        raise ValueError("incomplete route sampling")


def scorecard(path):
    data = read_json(path)
    if data.get("overallCompliant") is not True:
        raise ValueError("scorecard is not compliant")
    for key in ("routeFailureCount", "routeNoDataCount", "freshnessFailureCount", "resourceFailureCount", "resourceNoDataCount"):
        if type(data.get(key)) is not int or data[key] != 0:
            raise ValueError(f"{key} must be zero")
    for key in ("routeItems", "resourceItems", "freshnessItems"):
        items = data.get(key)
        if not isinstance(items, list) or not items:
            raise ValueError(f"{key}: missing required entries")
        if any(not isinstance(item, dict) or item.get("compliant") is not True for item in items):
            raise ValueError(f"{key}: noncompliant or malformed entry")
        if key != "freshnessItems" and any(item.get("status") != "PASS" for item in items):
            raise ValueError(f"{key}: missing measurements or failed entry")
        if key == "routeItems" and any(type(item.get("requestCount")) is not int or item["requestCount"] < 1 for item in items):
            raise ValueError("routeItems: missing request samples")
        if key in ("routeItems", "resourceItems"):
            names = [item.get("key") for item in items]
            if any(not isinstance(name, str) or not name for name in names) or len(set(names)) != len(names):
                raise ValueError(f"{key}: invalid or duplicate keys")
            fields = ("currentP95Ms", "currentP99Ms") if key == "routeItems" else ("currentValue",)
            for item in items:
                for field in fields:
                    value = item.get(field)
                    if type(value) not in (int, float) or not math.isfinite(value) or value < 0:
                        raise ValueError(f"{key}: invalid measurement {field}")
    config = Path(__file__).parent
    required_paths = {row[1].split("?")[0] for row in csv.reader((config / "performance-routes.tsv").read_text().splitlines(), delimiter="\t")}
    paths = [item.get("path") for item in data["routeItems"]]
    if not required_paths.issubset(set(paths)) or len(set(paths)) != len(paths):
        raise ValueError("scorecard is missing required routes or has duplicate paths")
    required_resources = set(json.loads((config / "certification-resources.json").read_text()))
    if not required_resources.issubset({item["key"] for item in data["resourceItems"]}):
        raise ValueError("scorecard is missing required resources")


def reports(directory, require_slo):
    root = Path(directory)
    if read_json(root / "readiness.json").get("status") != "UP":
        raise ValueError("readiness is not UP")
    if not (root / "prometheus.txt").read_text().strip():
        raise ValueError("Prometheus report is empty")
    scorecard(root / "performance-scorecard.json")
    if require_slo:
        data = read_json(root / "slo-status.json")
        if data.get("overallCompliant") is not True or not isinstance(data.get("slos"), list) or not data["slos"]:
            raise ValueError("SLO report is missing or noncompliant")
        if any(not isinstance(item, dict) or item.get("compliant") is not True for item in data["slos"]):
            raise ValueError("SLO entry is noncompliant")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    sample = sub.add_parser("baseline")
    for key in ("routes", "samples", "iterations"):
        sample.add_argument(key)
    report = sub.add_parser("reports")
    report.add_argument("directory")
    report.add_argument("--require-slo", action="store_true")
    sub.add_parser("scorecard").add_argument("path")
    sub.add_parser("iterations").add_argument("value")
    args = parser.parse_args()
    try:
        if args.command == "baseline":
            baseline(args.routes, args.samples, positive(args.iterations))
        elif args.command == "reports":
            reports(args.directory, args.require_slo)
        elif args.command == "scorecard":
            scorecard(args.path)
        else:
            positive(args.value)
    except (ValueError, OSError, KeyError, TypeError) as error:
        print(f"Certification validation failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
