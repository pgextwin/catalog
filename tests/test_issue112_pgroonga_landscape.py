"""Issue #112: PGroonga Website landscape is source discovery, never GET authorization."""
import json
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker

ROOT = Path(__file__).resolve().parents[1]


class PGroongaLandscapeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.record = json.loads((ROOT / "landscape/extensions/pgroonga.json").read_text(encoding="utf-8"))
        cls.index = json.loads((ROOT / "landscape/index.json").read_text(encoding="utf-8"))
        cls.schema = json.loads((ROOT / "schema/landscape-extension.schema.json").read_text(encoding="utf-8"))
        cls.validator = Draft202012Validator(cls.schema, format_checker=FormatChecker())

    def test_exact_landscape_entry_and_schema(self):
        self.assertEqual(self.index["extensions"].count("pgroonga"), 1)
        self.assertEqual(self.record["name"], "pgroonga")
        self.assertEqual(list(self.validator.iter_errors(self.record)), [])

    def test_source_is_official_but_pgextwin_public_get_is_not_authorized(self):
        self.assertEqual(self.record["status"], "candidate")
        self.assertNotIn("pgextwinCatalogName", self.record)
        self.assertEqual(self.record["roadmap"]["decision"], "research")
        self.assertEqual(self.record["windowsBinarySources"][0]["type"], "upstream-official")
        self.assertEqual(self.record["windowsBinarySources"][0]["url"],
                         "https://github.com/pgroonga/pgroonga/releases/tag/4.1.0")
        self.assertIn("NOT authorized", self.record["windowsBinarySources"][0]["notes"])
        self.assertIn("No PGroonga ZIP is available through the public pgextwin CLI.",
                      self.record["candidateRationale"])
        # A catalog entry would need a different, formally authorized admission.
        mutated = dict(self.record, status="implemented")
        self.assertTrue(list(self.validator.iter_errors(mutated)))

    def test_original_receipts_are_counts_of_members_not_43_zip_files(self):
        notes = self.record["windowsBinarySources"][0]["notes"]
        self.assertIn("five Windows x64 ZIP assets", notes)
        self.assertIn("PostgreSQL 14–18", notes)
        self.assertIn("43 DLL/EXE members", notes)
        self.assertIn("20 license/NOTICE-named documents", notes)
        self.assertIn("NOT 43 ZIPs", notes)
        self.assertIn("Variable Groonga source", self.record["candidateRationale"])
        self.assertTrue(any("f5edeb939d6a41a75c180e16a66442c59bff1c74" in u
                            for u in self.record["evidenceUrls"]))


if __name__ == "__main__":
    unittest.main()
