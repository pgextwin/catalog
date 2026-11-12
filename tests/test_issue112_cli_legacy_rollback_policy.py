"""Immutable source-level guard for genuine old published CLI rollback acceptance."""
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/issue112-cli-legacy-rollback-e2e.yml"


class PublishedLegacyRollbackContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.body = WORKFLOW.read_text(encoding="utf-8")

    def test_release_identity_and_sigstore_are_pinned(self):
        body = self.body
        for value in (
            "0.3.13", "0.3.14",
            "188d3f2d645d0583808db4bf6e8ab80029dbb65f",
            "dd5bd347cdf1a1a864b0880d0b951254e1fe0af2",
            "281fbba9b59c5d2173ecd9b9249fd22955b0ea9cb0541f23450d491c811236ed",
            "8e7c19cfffd794519b2a63feebe2e2e9f52040787236dc1c8154cbdf40e72814",
            "gh attestation verify", "--source-digest", "--deny-self-hosted-runners",
            "Get-FileHash", "Invoke-WebRequest", "release.assets",
        ):
            with self.subTest(value=value):
                self.assertIn(value, body)

    def test_latest_incompatible_v13_fails_closed_then_fixed_pg14_verifies(self):
        body = self.body
        self.assertLess(
            body.index("download-all --pg 15 --latest"),
            body.index("LEGACY_V13_LATEST_FOUR_MAJOR=EXPECTED_DENY"),
        )
        self.assertLess(
            body.index("LEGACY_V13_LATEST_FOUR_MAJOR=EXPECTED_DENY"),
            body.index("download-all --pg 14 --fixed"),
        )
        self.assertIn("Signed Catalog fleet is incomplete", body)
        self.assertIn("LEGACY_V13_FIXED_PG14=PASS SHA256=14/14", body)
        self.assertIn("CLI_PINNED_HISTORICAL_CANDIDATE_POLICY", body)
        self.assertIn("LEGACY_V14_LATEST_PG15=PASS SHA256=17/17", body)
        self.assertIn("SIGSTORE_SIGNED_CATALOG_FEED_ORIGINAL_ZIPS", body)

    def test_readonly_and_main_only_nonpublishing(self):
        body = self.body
        self.assertIn("permissions:\n  contents: read", body)
        self.assertIn("branches: [main]", body)
        self.assertIn("fail-fast: false", body)
        self.assertIn("Remove-Item Env:GH_TOKEN", body)
        self.assertIn("Remove-Item Env:GITHUB_TOKEN", body)
        for forbidden in ("contents: write", "id-token: write",
                          "workflow_dispatch:", "pull_request_target:",
                          "gh release create", "gh workflow run", "gh run rerun",
                          "--clobber", "GITHUB_TOKEN:"):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, body)


if __name__ == "__main__":
    unittest.main()
