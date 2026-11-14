import importlib.util
from pathlib import Path
import subprocess
import tempfile
import unittest

spec = importlib.util.spec_from_file_location("migrations", Path(__file__).with_name("check-migrations.py"))
migrations = importlib.util.module_from_spec(spec)
spec.loader.exec_module(migrations)

PLATFORM, TENANT = migrations.LINES
SQL = "-- migration-guard: tenant-only\ncreate table t (id int);\n"


class Repo:
    """A throwaway git repository holding both migration lines."""

    def __init__(self, directory):
        self.root = Path(directory)
        self.git("init", "-q", "-b", "main")
        self.git("config", "user.email", "ci@example.invalid")
        self.git("config", "user.name", "ci")
        for line in (PLATFORM, TENANT):
            for version in (1, 2):
                self.write(f"{line}/V{version}__baseline_{version}.sql", SQL)
        self.base = self.commit("base")

    def git(self, *args):
        return subprocess.check_output(["git", *args], cwd=self.root, text=True).strip()

    def write(self, path, text):
        target = self.root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text)

    def commit(self, message):
        self.git("add", "-A")
        self.git("commit", "-q", "--allow-empty", "-m", message)
        return self.git("rev-parse", "HEAD")

    def failures(self, base=True):
        return migrations.check(self.root, self.base if base else None)


class CheckMigrationsTest(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.repo = Repo(self.directory.name)

    def tearDown(self):
        self.directory.cleanup()

    def assertRejected(self, fragment):
        self.repo.commit("change")
        failures = self.repo.failures()
        self.assertTrue(any(fragment in failure for failure in failures), failures)

    def test_new_versions_in_either_line_pass(self):
        self.repo.write(f"{TENANT}/V3__add_column.sql", SQL)
        self.repo.write(f"{PLATFORM}/V3__add_table.sql", SQL)
        self.repo.commit("add")
        self.assertEqual(self.repo.failures(), [])

    def test_lines_are_versioned_independently(self):
        self.repo.write(f"{TENANT}/V3__tenant_change.sql", SQL)
        self.repo.commit("tenant V3")
        self.repo.base = self.repo.commit("new base")
        self.repo.write(f"{PLATFORM}/V3__platform_change.sql", SQL)
        self.repo.commit("platform V3")
        self.assertEqual(self.repo.failures(), [])

    def test_editing_an_applied_migration_is_rejected(self):
        self.repo.write(f"{TENANT}/V2__baseline_2.sql", SQL + "alter table t add column c int;\n")
        self.assertRejected("applied migration edited")

    def test_deleting_an_applied_migration_is_rejected(self):
        (self.repo.root / PLATFORM / "V2__baseline_2.sql").unlink()
        self.assertRejected("applied migration deleted")

    def test_renaming_an_applied_migration_is_rejected(self):
        self.repo.git("mv", f"{TENANT}/V2__baseline_2.sql", f"{TENANT}/V2__renamed.sql")
        self.assertRejected("applied migration renamed")

    def test_reusing_a_base_version_is_rejected(self):
        self.repo.write(f"{TENANT}/V2__another_change.sql", SQL)
        self.assertRejected("version V2 already exists")

    def test_malformed_filename_is_rejected_without_a_base(self):
        self.repo.write(f"{TENANT}/V3_missing_double_underscore.sql", SQL)
        self.repo.commit("bad name")
        self.assertTrue(any("malformed" in failure for failure in self.repo.failures(base=False)))

    def test_migration_without_sql_is_rejected_without_a_base(self):
        self.repo.write(f"{TENANT}/V3__comment_only.sql", "-- migration-guard: tenant-only\n-- nothing here\n")
        self.repo.commit("empty")
        self.assertTrue(any("no substantive SQL" in failure for failure in self.repo.failures(base=False)))

    def test_change_checks_need_a_base(self):
        self.repo.write(f"{TENANT}/V2__baseline_2.sql", SQL + "-- edited\n")
        self.repo.commit("edit")
        self.assertEqual(self.repo.failures(base=False), [])

    def test_all_v1_reset_shape_is_not_an_exception(self):
        for line in (PLATFORM, TENANT):
            (self.repo.root / line / "V2__baseline_2.sql").unlink()
            self.repo.write(f"{line}/V1__baseline_1.sql", SQL + "-- consolidated\n")
        self.repo.write("prototype-app/docs/development-v1-baseline-reset.md", "reset record\n")
        self.assertRejected("applied migration")

    def test_retired_collision_deletion_is_allowed(self):
        retired = sorted(migrations.RETIRED_COLLISIONS)[0]
        self.repo.write(retired, SQL)
        self.repo.base = self.repo.commit("retired file present")
        (self.repo.root / retired).unlink()
        self.repo.commit("remove retired collision")
        self.assertEqual(self.repo.failures(), [])


if __name__ == "__main__":
    unittest.main()
