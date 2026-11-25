from copy import deepcopy
import json
import subprocess
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts import package_ledger
from scripts.cli_signed_feed import build_feed, verify_ledger_admission

ROOT = Path(__file__).resolve().parents[1]


class WebsiteV1CompatibilityTests(unittest.TestCase):
    def test_current_website_consumer_fields_remain_available(self):
        index = json.loads((ROOT / "index.json").read_text(encoding="utf-8"))
        self.assertEqual(3, index["schemaVersion"])
        self.assertEqual("packages", index["packagesDir"])
        self.assertTrue(index["identities"])
        self.assertTrue(index["extensions"])
        self.assertEqual(len(index["extensions"]),len(set(index["extensions"])))
        self.assertTrue({"pg_bigm","pg_cron","pg_hint_plan","pg_ivm","pg_qualstats","pg_repack","pgaudit","set_user","plpgsql_check"}.issubset(set(index["extensions"])))

        for name in index["extensions"]:
            record = package_ledger.website_record(
                package_ledger.read_record(ROOT / "packages" / f"{name}.json")
            )

            self.assertTrue(record["displayName"])
            self.assertTrue(record["description"])
            self.assertTrue(record["upstream"]["repository"])
            self.assertTrue(record["repository"])
            self.assertTrue(record["license"])
            self.assertEqual("x64", record["architecture"])
            self.assertTrue(record["latest"]["releaseTag"])

            supported_majors = range(14, 19) if "14" in record["postgresql"] else range(15, 19)
            for major in map(str, supported_majors):
                info = record["postgresql"][major]
                if info["available"] is False:
                    # PG14 EOL rollover marker: the major stays present in
                    # the record but is explicitly unavailable (no asset).
                    continue
                self.assertIs(info["available"], True)
                self.assertTrue(info["asset"])

            expected_release = (
                f"https://github.com/{record['repository']}/releases/tag/"
                f"{record['latest']['releaseTag']}"
            )
            self.assertEqual(expected_release, record["latest"]["releaseUrl"])

    def test_ledger_projects_v3_with_local_admissions_and_per_major_versions(self):
        commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
        with patch("urllib.request.urlopen", side_effect=AssertionError("unexpected HTTP request")):
            feed = build_feed(ROOT, commit)
        self.assertEqual(feed["schemaVersion"], "pgextwin-signed-catalog-zip-feed/v3")
        self.assertNotIn("14", feed["postgresqlMajors"])
        entries = {entry["extension"]: entry for entry in feed["extensions"]}
        for entry in entries.values():
            for release in entry["releases"]:
                self.assertNotIn("14", {row["pgMajor"] for row in release["packages"]})
        for name in ("pg_hint_plan", "pgaudit"):
            entry = entries[name]
            current = next(r for r in entry["releases"] if r["releaseTag"] == entry["latestReleaseTag"])
            view = package_ledger.website_record(
                package_ledger.read_record(ROOT / "packages" / f"{name}.json")
            )
            versions = view["upstream"]["perPostgresql"]
            self.assertGreater(len({row["version"] for row in current["packages"]}), 1)
            for row in current["packages"]:
                self.assertEqual(row["version"], versions[row["pgMajor"]]["version"])

    def test_migrated_historical_license_is_admitted_from_protected_git(self):
        name = "hypopg"
        load = package_ledger.git_admissions(ROOT)
        migration_base = "34da9eb5f08491b37859cf834fd9a833440ba3fe"
        history = load(migration_base, name)["releaseInventory"]["history"]
        snapshot = {**next(r for r in history if r["releaseTag"] == "v1.4.4-windows.1"),
                    "legacyInventoryCommit": migration_base}
        verify_ledger_admission(name, 1, snapshot, load)
        altered = deepcopy(snapshot)
        altered["packages"][0]["license"]["name"] = "Different license"
        with self.assertRaisesRegex(ValueError, "historical license evidence"):
            verify_ledger_admission(name, 1, altered, load)
        altered = deepcopy(snapshot)
        altered["admission"]["catalogCommit"] = "0" * 40
        with self.assertRaisesRegex(ValueError, "outside protected main"):
            verify_ledger_admission(name, 1, altered, load)

    def test_lifecycle_remains_external(self):
        index = json.loads((ROOT / "index.json").read_text(encoding="utf-8"))
        for name in index["extensions"]:
            record = package_ledger.website_record(
                package_ledger.read_record(ROOT / "packages" / f"{name}.json")
            )
            self.assertNotIn("maintained", record)
            self.assertNotIn("eol", record)
            for info in record["postgresql"].values():
                self.assertNotIn("maintained", info)
                self.assertNotIn("eol", info)


if __name__ == "__main__":
    unittest.main()
