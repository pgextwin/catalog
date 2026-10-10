import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class WebsiteV1CompatibilityTests(unittest.TestCase):
    def test_current_website_consumer_fields_remain_available(self):
        index = json.loads((ROOT / "index.json").read_text(encoding="utf-8"))
        self.assertEqual(2, index["schemaVersion"])
        self.assertTrue(9 <= len(index["extensions"]) <= 11)
        self.assertTrue({"pg_bigm","pg_cron","pg_hint_plan","pg_ivm","pg_qualstats","pg_repack","pgaudit","set_user","plpgsql_check"}.issubset(set(index["extensions"])))

        for name in index["extensions"]:
            record = json.loads(
                (ROOT / "extensions" / f"{name}.json").read_text(encoding="utf-8")
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
                self.assertIs(info["available"], True)
                self.assertTrue(info["asset"])

            expected_release = (
                f"https://github.com/{record['repository']}/releases/tag/"
                f"{record['latest']['releaseTag']}"
            )
            self.assertEqual(expected_release, record["latest"]["releaseUrl"])

    def test_lifecycle_remains_external(self):
        index = json.loads((ROOT / "index.json").read_text(encoding="utf-8"))
        for name in index["extensions"]:
            record = json.loads(
                (ROOT / "extensions" / f"{name}.json").read_text(encoding="utf-8")
            )
            self.assertNotIn("maintained", record)
            self.assertNotIn("eol", record)
            for info in record["postgresql"].values():
                self.assertNotIn("maintained", info)
                self.assertNotIn("eol", info)


if __name__ == "__main__":
    unittest.main()
