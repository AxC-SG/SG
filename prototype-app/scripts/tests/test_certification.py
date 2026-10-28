import csv
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

SCRIPTS = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("validation", SCRIPTS / "validate-certification.py")
validation = importlib.util.module_from_spec(spec)
spec.loader.exec_module(validation)


def card():
    return dict(overallCompliant=True, routeFailureCount=0, routeNoDataCount=0,
                freshnessFailureCount=0, resourceFailureCount=0, resourceNoDataCount=0,
                routeItems=[dict(key=row[0], path=row[1].split("?")[0], compliant=True,
                                 status="PASS", requestCount=3, currentP95Ms=1, currentP99Ms=1)
                            for row in csv.reader((SCRIPTS / "performance-routes.tsv").read_text().splitlines(), delimiter="\t")],
                resourceItems=[dict(key=key, compliant=True, status="PASS", currentValue=0)
                               for key in json.loads((SCRIPTS / "certification-resources.json").read_text())],
                freshnessItems=[dict(compliant=True)])


class CertificationTest(unittest.TestCase):
    def run_fixture(self, scenario="healthy", enterprise=True, strict=None, iterations="1"):
        counts = {}
        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_GET(self):
                path = self.path.split("?")[0]
                counts[path] = counts.get(path, 0) + 1
                status, body = 200, {}
                if path == "/api/operations/performance-scorecard":
                    body = card()
                    if scenario == "no-data":
                        body["routeNoDataCount"] = 1
                        body["routeItems"][0]["status"] = "NO_DATA"
                    elif scenario == "missing-items":
                        del body["resourceItems"]
                    elif scenario == "resource-no-data":
                        body["resourceItems"][0]["status"] = "NO_DATA"
                    elif scenario == "partial-routes":
                        body["routeItems"].pop()
                    elif scenario == "partial-resources":
                        body["resourceItems"].pop()
                    elif scenario == "invalid-metric":
                        body["resourceItems"][0]["currentValue"] = None
                    elif scenario == "malformed":
                        body = "invalid-json"
                elif path == "/api/slo/status":
                    body = dict(overallCompliant=True, slos=[dict(compliant=True)])
                elif path == "/actuator/health/readiness":
                    body = dict(status="UP")
                elif path == "/actuator/prometheus":
                    body = "scoutgrid.finding_delta_queue.oldest_age_seconds 0\nscoutgrid.finding_projection.max_lag_seconds 0\n"
                elif path == "/api/vuln-repo/org-cves/status":
                    body = dict(pendingEventCount=0, processingEventCount=0, staleEventCount=0,
                                failedEventCount=0, oldestProcessingEventAgeSeconds=0,
                                ingestionQueuedJobCount=0, ingestionRunningJobCount=0)
                elif path == "/api/findings/projection-status":
                    body = dict(stale=False)
                if path.startswith("/api/") and path not in ["/api/operations/performance-scorecard", "/api/slo/status"]:
                    if scenario == "http-500":
                        status = 500
                    if scenario == "auth-skip":
                        status, body = 403, dict(message="Tenant context is required")
                # Status endpoints must remain valid to isolate sampling from scorecard checks.
                if counts[path] > 1 and path in ["/api/vuln-repo/org-cves/status", "/api/findings/projection-status"]:
                    status = 200
                payload = body if isinstance(body, str) else json.dumps(body, separators=(",", ":"))
                self.send_response(status)
                self.send_header("x-request-id", "fixture-id")
                self.send_header("server-timing", "app;dur=1")
                self.end_headers()
                self.wfile.write(payload.encode())

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with tempfile.TemporaryDirectory() as directory:
                env = dict(PATH=os.environ["PATH"], OUT_DIR=directory,
                           BASE_URL=f"http://127.0.0.1:{server.server_port}", CREATOR_KEY="fixture",
                           SETTLE_MAX_WAIT_SECONDS="0",
                           BASELINE_ITERATIONS=iterations, ITERATIONS=iterations,
                           MAX_WAIT_SECONDS="1", POLL_INTERVAL_SECONDS="1")
                env["ROUTE_AUTH_MODE"] = "api-key"
                if strict is not None:
                    env["CERTIFICATION_STRICT"] = strict
                script = "enterprise-performance-certification.sh" if enterprise else "performance-baseline.sh"
                result = subprocess.run(["sh", str(SCRIPTS / script)], env=env, text=True,
                                        capture_output=True, timeout=30)
                root = Path(directory)
                summary = root / "certification-summary.txt"
                sample = root / ("baseline/route-samples.tsv" if enterprise else "route-samples.tsv")
                return result, summary.read_text() if summary.exists() else "", sample.read_text() if sample.exists() else ""
        finally:
            server.shutdown()
            server.server_close()
            thread.join()

    def test_healthy_certification_and_lowercase_headers(self):
        result, summary, samples = self.run_fixture()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Baseline status: PASS", summary)
        self.assertNotIn("missing", samples)
        self.assertIn("fixture-id", samples)

    def test_http_failures_fail_and_keep_summary(self):
        result, summary, samples = self.run_fixture("http-500")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Baseline status: FAIL", summary)
        self.assertEqual(samples.count("\t500\t"), 20)

    def test_strict_rejects_auth_and_missing_or_invalid_measurements(self):
        for scenario in ["auth-skip", "no-data", "resource-no-data", "malformed", "missing-items", "partial-routes", "partial-resources", "invalid-metric"]:
            with self.subTest(scenario=scenario):
                result, summary, _ = self.run_fixture(scenario)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("Final scorecard capture status:", summary)

    def test_diagnostic_mode_preserves_http_failure_report(self):
        result, _, samples = self.run_fixture("http-500", enterprise=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("http_failure", samples)

    def test_invalid_iterations_fail_with_summary(self):
        for count in ["0", "-1", "invalid"]:
            result, summary, _ = self.run_fixture(iterations=count)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("Baseline status: FAIL", summary)

    def test_incomplete_and_duplicate_samples_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            routes, samples = root / "routes.tsv", root / "samples.tsv"
            routes.write_text("route\t/api/route\n")
            header = "route\titeration\tstatus\tclassification\n"
            samples.write_text(header + "route\t1\t200\tok\n")
            with self.assertRaisesRegex(ValueError, "incomplete"):
                validation.baseline(routes, samples, 2)
            samples.write_text(header + "route\t1\t200\tok\n" * 2)
            with self.assertRaisesRegex(ValueError, "duplicate"):
                validation.baseline(routes, samples, 2)

    def test_missing_report_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(OSError):
                validation.reports(directory, True)


if __name__ == "__main__":
    unittest.main()
