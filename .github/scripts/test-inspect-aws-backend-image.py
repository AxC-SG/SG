import hashlib
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location("inspector", Path(__file__).with_name("inspect-aws-backend-image.py"))
inspector = importlib.util.module_from_spec(spec)
spec.loader.exec_module(inspector)

CATALOG = {
    ("tenant", "V10__ten.sql"): "c" * 64,
    ("platform", "V1__platform_schema.sql"): "a" * 64,
    ("tenant", "V2__two.sql"): "b" * 64,
    ("tenant", "V1__tenant_schema.sql"): "d" * 64,
}


class CatalogFingerprintTest(unittest.TestCase):
    def test_orders_by_line_then_numeric_version(self):
        expected = "".join([
            f"platform/V1__platform_schema.sql {'a' * 64}\n",
            f"tenant/V1__tenant_schema.sql {'d' * 64}\n",
            f"tenant/V2__two.sql {'b' * 64}\n",
            f"tenant/V10__ten.sql {'c' * 64}\n",
        ])
        self.assertEqual(inspector.catalog_fingerprint(CATALOG), hashlib.sha256(expected.encode()).hexdigest())

    def test_changes_when_content_changes_with_equal_heads(self):
        edited = {**CATALOG, ("tenant", "V2__two.sql"): "e" * 64}
        self.assertNotEqual(inspector.catalog_fingerprint(CATALOG), inspector.catalog_fingerprint(edited))

    def test_changes_when_a_file_is_renamed_or_moved_between_lines(self):
        renamed = {**{key: value for key, value in CATALOG.items() if key != ("tenant", "V2__two.sql")},
                   ("tenant", "V2__renamed.sql"): "b" * 64}
        moved = {**{key: value for key, value in CATALOG.items() if key != ("tenant", "V2__two.sql")},
                 ("platform", "V2__two.sql"): "b" * 64}
        fingerprints = {inspector.catalog_fingerprint(catalog) for catalog in (CATALOG, renamed, moved)}
        self.assertEqual(len(fingerprints), 3)

    def test_source_catalog_is_stable_and_complete(self):
        root = inspector.BACKEND / "src/main/resources/db/migration"
        files = {
            (label, path.name): hashlib.sha256(path.read_bytes()).hexdigest()
            for label, directory in (("platform", "postgres_reset"), ("tenant", "tenant"))
            for path in (root / directory).iterdir() if inspector.re.fullmatch(inspector.MIGRATION, path.name)
        }
        self.assertTrue({label for label, _ in files} == {"platform", "tenant"})
        self.assertRegex(inspector.catalog_fingerprint(files), r"^[0-9a-f]{64}$")


if __name__ == "__main__":
    unittest.main()
