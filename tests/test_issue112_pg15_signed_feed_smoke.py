"""Regression of PG15-18 post-EOL read-only public CLI smoke expectations."""
import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FILES = (
    ".github/workflows/cli-anonymous-latest.yml",
    ".github/workflows/cli-authenticated-latest-canary.yml",
    ".github/workflows/cli-published-e2e.yml",
)


class SignedFeedTransitionSmokeContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.sources = {p: (ROOT / p).read_text(encoding="utf-8") for p in FILES}

    def test_protected_policy_now_contains_only_current_major_cohort(self):
        policy = json.loads((ROOT / "config/cli-feed-majors.json").read_text())
        self.assertEqual(policy, {"schemaVersion": 1,
                                  "postgresqlMajors": ["15", "16", "17", "18"]})

    def test_all_real_smokes_follow_signed_cohort_not_stale_five_major_path(self):
        for path, source in self.sources.items():
            with self.subTest(path=path):
                self.assertNotIn("'pgextwin-pg14-18'", source)
                self.assertNotIn("(% 5)", source)
                self.assertIn("CATALOG_COMMIT=([0-9a-f]{40})", source)
                self.assertIn("/config/cli-feed-majors.json", source)
                self.assertIn("Expected exactly one signed PG cohort directory", source)
                self.assertIn("($approved -join ',') -cne", source)
                self.assertIn("Sort-Object -Unique", source)
                self.assertIn("pgextwin-pg$($approved[0])-$($approved[-1])", source)
                self.assertIn("ZIP", source)
                self.assertIn("SHA256", source)

    def test_no_publishing_or_manual_dispatch_added_to_anonymous_or_canary(self):
        for path in FILES[:2]:
            with self.subTest(path=path):
                s = self.sources[path]
                self.assertIn("permissions:\n  contents: read", s)
                self.assertNotIn("contents: write", s)
                self.assertNotIn("workflow_dispatch:", s)
                self.assertNotIn("pull_request_target:", s)

    def test_published_exe_acceptance_is_still_genuine_main_only(self):
        s = self.sources[FILES[2]]
        self.assertIn("branches: [main]", s)
        self.assertIn("paths:\n      - '.github/workflows/cli-published-e2e.yml'", s)
        self.assertIn("github.ref == 'refs/heads/main'", s)
        self.assertIn("PUBLIC_EXE_SIGSTORE=PASS", s)
        self.assertIn("PUBLIC_CLI_REAL_ZIPS=PASS", s)
        self.assertNotIn("contents: write", s)


if __name__ == "__main__":
    unittest.main()
