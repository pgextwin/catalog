"""Issue #112: new external http Windows source must remain metadata-only."""
import json
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker


ROOT = Path(__file__).resolve().parents[1]


class HttpWindowsResearchBoundaryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.entry = json.loads(
            (ROOT / "landscape/extensions/http.json").read_text(encoding="utf-8")
        )
        cls.landscape = json.loads(
            (ROOT / "landscape/index.json").read_text(encoding="utf-8")
        )
        cls.catalog = json.loads((ROOT / "index.json").read_text(encoding="utf-8"))
        cls.schema = json.loads(
            (ROOT / "schema/landscape-extension.schema.json").read_text(encoding="utf-8")
        )

    def test_research_entry_is_schema_valid_but_not_distributed(self):
        validator = Draft202012Validator(self.schema, format_checker=FormatChecker())
        self.assertEqual([], list(validator.iter_errors(self.entry)))
        self.assertEqual(self.landscape["extensions"].count("http"), 1)
        self.assertNotIn("http", self.catalog["extensions"])
        self.assertNotIn("pgextwinCatalogName", self.entry)
        self.assertEqual(self.entry["name"], "http")
        self.assertEqual(self.entry["status"], "candidate")
        self.assertEqual(self.entry["roadmap"]["decision"], "research")
        with_implemented = dict(self.entry, status="implemented")
        self.assertNotEqual([], list(validator.iter_errors(with_implemented)))

    def test_independent_community_origin_is_not_a_github_signed_asset(self):
        source, = self.entry["windowsBinarySources"]
        self.assertEqual(source["type"], "community")
        self.assertEqual(source["url"],
                         "https://www.postgresonline.com/article_pfriendly/371.html")
        self.assertEqual(source["compatibility"], "manual-verification-required")
        self.assertIn("NOT authorized", source["notes"])
        self.assertIn("external HTTPS origin", self.entry["candidateRationale"])
        self.assertIn("no public pgextwin CLI download", self.entry["candidateRationale"])
        self.assertIn("libcurl", self.entry["candidateRationale"])
        self.assertIn("1.7.2", self.entry["currentStableVersion"])

    def test_audited_per_major_urls_remain_research_only(self):
        doc = (ROOT / "docs/issue-112-http-windows-source-intake.md").read_text(
            encoding="utf-8"
        )
        for major, version in ((14, "1.5.0"), (15, "1.6.1"),
                               (16, "1.6.1"), (17, "1.7.1"), (18, "1.7.1")):
            with self.subTest(pg=major):
                self.assertIn(
                    f"https://www.postgresonline.com/downloads/pg{major}http_w64.zip",
                    doc,
                )
                self.assertIn(f"| {major} | {version} |", doc)
        self.assertIn("Cryptographic original-byte verification", doc)
        self.assertIn("NOT VERIFIED", doc)
        self.assertIn("PUBLIC_GET_DENY / MIRROR_DENY / RELEASE_DENY", doc)
        self.assertIn("Do not fabricate such IDs", doc)


if __name__ == "__main__":
    unittest.main()
