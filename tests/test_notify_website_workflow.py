"""Invariant checks for read-only cross-repository Website acceptance."""
from pathlib import Path
import re
import unittest

YAML = (Path(__file__).resolve().parents[1] /
        ".github" / "workflows" / "notify-website.yml").read_text(encoding="utf-8")

class CrossRepositoryWebsiteAudit(unittest.TestCase):
    def test_pinned_reusable_workflow(self):
        self.assertRegex(YAML, r"uses:\s+pgextwin/website/\.github/workflows/pages-smoke\.yml@[0-9a-f]{40}")
        self.assertIn("push:", YAML)
        self.assertIn("branches: [main]", YAML)
        self.assertIn("contents: read", YAML)

    def test_does_not_need_pat_app_key_or_privileged_dispatch(self):
        for forbidden in ("GH_TOKEN", "PGEXTWIN_WEBSITE_APP_CLIENT_ID",
                          "PGEXTWIN_WEBSITE_APP_PRIVATE_KEY",
                          "workflow_dispatch", "contents: write",
                          "permission-actions: write", "pull_request_target",
                          "pending_config", "secrets."):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, YAML)

if __name__ == "__main__":
    unittest.main()
