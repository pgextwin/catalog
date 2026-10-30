#!/usr/bin/env python3
"""Safety regression: a protected main push without public Catalog data must not publish."""
import json
from pathlib import Path
import re
import subprocess
import unittest

WORKFLOW = Path(__file__).resolve().parents[1] / ".github/workflows/cli-signed-catalog-feed.yml"


class CatalogFeedPublicationGate(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.workflow = WORKFLOW.read_text(encoding="utf-8")
        match = re.search(r"if ! jq -e '(?P<filter>[\\s\\S]*?)' <<< .*? >/dev/null;", cls.workflow)
        if match is None:
            raise AssertionError("Missing independent GitHub commit changed-file gate")
        cls.filter = match.group("filter")

    def accepted(self, filenames):
        response = {"files": [{"filename": path, "status": "modified"} for path in filenames]}
        result = subprocess.run(
            ["jq", "-e", self.filter], input=json.dumps(response),
            text=True, capture_output=True, check=False,
        )
        self.assertIn(result.returncode, (0, 1), result.stderr)
        return result.returncode == 0

    def test_private_or_noop_changes_cannot_publish(self):
        for paths in (
            [],
            [".github/workflows/cli-signed-catalog-feed.yml"],
            ["metadata/issue311-r09-shadow-nonpublishing.json"],
            ["tests/test_issue311_r09_shadow_contract.py", ".github/workflows/issue311-r09-shadow-preview.yml"],
            ["README.md", "docs/cli-feed.md"],
            ["extensions/orafce.json/extra"],
            ["extensions/orafce.txt"],
        ):
            with self.subTest(paths=paths):
                self.assertFalse(self.accepted(paths))

    def test_genuine_catalog_record_change_still_eligible_for_existing_full_gate(self):
        for paths in (["index.json"], ["extensions/orafce.json"], ["extensions/pg_bigm.json", "README.md"]):
            with self.subTest(paths=paths):
                self.assertTrue(self.accepted(paths))

    def test_both_publication_jobs_skip_when_gate_has_no_source(self):
        self.assertIn("if: needs.gate.outputs.source != ''", self.workflow)
        self.assertEqual(self.workflow.count("if: needs.gate.outputs.source != ''"), 2)
        self.assertIn("CATALOG_FEED_NOOP_NO_PUBLIC_RECORD_CHANGE", self.workflow)
        self.assertLess(
            self.workflow.index("CATALOG_FEED_NOOP_NO_PUBLIC_RECORD_CHANGE"),
            self.workflow.index('echo "source=$RUN_SHA" >> "$GITHUB_OUTPUT"'),
        )


if __name__ == "__main__":
    unittest.main()
