import importlib.util
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location("reports", Path(__file__).with_name("verify-maven-reports.py"))
reports = importlib.util.module_from_spec(spec)
spec.loader.exec_module(reports)


class ReportsTest(unittest.TestCase):
    def test_execution_failures(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for tests, skipped, failures in [(0, 0, 0), (1, 1, 0), (1, 0, 1)]:
                (root / "TEST-Example.xml").write_text(f'<testsuite name="ExamplePostgresIntegrationTest" tests="{tests}" skipped="{skipped}" failures="{failures}"/>')
                with self.assertRaises(ValueError):
                    reports.verify(root, {"ExamplePostgresIntegrationTest"}, True)
            (root / "TEST-Example.xml").write_text('<testsuite name="ExamplePostgresIntegrationTest" tests="1" skipped="0" failures="0"/>')
            reports.verify(root, {"ExamplePostgresIntegrationTest"}, True)
            with self.assertRaisesRegex(ValueError, "missing"):
                reports.verify(root, {"MissingPostgresIntegrationTest"}, True)
            (root / "TEST-Example.xml").write_text("invalid")
            with self.assertRaises(reports.ET.ParseError):
                reports.verify(root, {"ExamplePostgresIntegrationTest"}, True)


if __name__ == "__main__":
    unittest.main()
