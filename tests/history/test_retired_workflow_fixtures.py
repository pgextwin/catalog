"""Frozen content of completed one-shot workflows; entrypoint guard stays normal."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]


class RetiredWorkflowFixtureTests(unittest.TestCase):
    def test_original_canary_and_bilingual_fixture_contracts(self):
        original = (ROOT / "tests/fixtures/historical-workflows/catalog-fleet14-readonly-canary.yml").read_text(encoding="utf-8")
        self.assertIn("DRY_RUN_FLEET14_METADATA_ONLY", original)
        self.assertNotIn("contents: write", original)
        original_notes = (ROOT / "tests/fixtures/historical-workflows/historical-release-bilingual.yml").read_text(encoding="utf-8")
        self.assertIn("Update ONLY existing public Release bodies", original_notes)
        self.assertNotIn("pull_request_target:", original_notes)


if __name__ == "__main__":
    unittest.main()
