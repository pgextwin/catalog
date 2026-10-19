"""Static R6 deployment policy guard; no network or workflow dispatch."""
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "cli-candidate.yml"
PIN = "actions/attest@1e69f48acb82d1966a394da916b4c1698aa569d6"


class CliR6WorkflowPolicyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.workflow = WORKFLOW.read_text(encoding="utf-8")

    def test_only_main_is_eligible_for_oidc_and_attestation(self):
        doc = self.workflow
        marker = "  attest-provenance:\n"
        self.assertEqual(doc.count(marker), 1)
        attest = doc.split(marker, 1)[1].split("\n  verify-provenance:", 1)[0]
        self.assertIn("if: github.event_name == 'push' && github.ref == 'refs/heads/main'", attest)
        self.assertIn("needs: [candidate, independent-smoke]", attest)
        self.assertIn("id-token: write", attest)
        self.assertIn("attestations: write", attest)
        self.assertIn("subject-path: ${{ runner.temp }}/cli-signed/pgextwin.exe", attest)
        self.assertIn(PIN, attest)
        self.assertNotIn("contents: write", doc)

    def test_verification_is_independent_and_exact_identity_bound(self):
        verify = self.workflow.split("\n  verify-provenance:", 1)[1]
        self.assertIn("if: github.event_name == 'push' && github.ref == 'refs/heads/main'", verify)
        self.assertIn("needs: [attest-provenance]", verify)
        self.assertIn("--repo pgextwin/catalog", verify)
        self.assertIn("--signer-workflow pgextwin/catalog/.github/workflows/cli-candidate.yml", verify)
        self.assertIn("--source-ref refs/heads/main", verify)
        self.assertIn("--source-digest $env:GITHUB_SHA", verify)
        self.assertIn("CLI_R6_GENUINE_SLSA_SIGNER_MAIN_VERIFIED=PASS", verify)
        self.assertNotIn("id-token: write", verify)
        self.assertNotIn("attestations: write", verify)

    def test_no_release_or_manual_dispatch_endpoint(self):
        s = self.workflow
        for bad in ("workflow_dispatch:", "softprops/action-gh-release", "gh release create",
                    "create-release", "upload-release-asset", "install --apply",
                    "pull_request_target:", "workflow_run:"):
            with self.subTest(bad=bad):
                self.assertNotIn(bad, s)


if __name__ == "__main__":
    unittest.main()
