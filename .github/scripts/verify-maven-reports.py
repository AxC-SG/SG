#!/usr/bin/env python3
"""Check execution evidence, including missing classes and unexpected skips."""
import argparse
from pathlib import Path
import re
import sys
import xml.etree.ElementTree as ET


def expected_classes(source):
    result = set()
    for path in Path(source).rglob("*PostgresIntegrationTest.java"):
        text = path.read_text()
        package = re.search(r"package\s+([\w.]+);", text)
        match = re.search(r"(?:^|\n)\s*(?:public\s+)?(?:final\s+)?class\s+(\w*PostgresIntegrationTest)\b", text)
        if match and package:
            result.add(package[1] + "." + match[1])
    return result


def verify(reports, expected, integration=False):
    suites = {}
    files = list(Path(reports).glob("TEST-*.xml"))
    if not files or not expected:
        raise ValueError("no expected tests or XML test reports")
    for file in files:
        root = ET.parse(file).getroot()
        for suite in ([root] if root.tag == "testsuite" else root.findall("testsuite")):
            suites[suite.get("name")] = suite
    for name in sorted(expected):
        suite = suites.get(name)
        if suite is None:
            raise ValueError(f"missing test class: {name}")
        if int(suite.get("tests", "0")) < 1:
            raise ValueError(f"no tests executed: {name}")
        if any(int(suite.get(key, "0")) for key in ("failures", "errors", "skipped")):
            raise ValueError(f"failed or skipped tests: {name}")
    if integration:
        if any(not name.split("$")[0].endswith("PostgresIntegrationTest") for name in suites):
            raise ValueError("ordinary test suite leaked into PostgreSQL reports")
        if any(suite.find(".//skipped") is not None for suite in suites.values()):
            raise ValueError("unexpected skipped integration test")
    print(f"Verified {len(expected)} expected test classes in {reports}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=["unit", "postgres"])
    parser.add_argument("backend")
    args = parser.parse_args()
    backend = Path(args.backend)
    integration = args.mode == "postgres"
    expected = expected_classes(backend / "src/test/java") if integration else {
        "com.prototype.vulnwatch.migration.MigrationCatalogTest",
        "com.prototype.vulnwatch.migration.PostgresResetMigrationGuardTest",
    }
    try:
        verify(backend / "target" / ("failsafe-reports" if integration else "surefire-reports"), expected, integration)
    except (ValueError, OSError, ET.ParseError) as error:
        print(f"Test execution verification failed: {error}", file=sys.stderr)
        sys.exit(1)
