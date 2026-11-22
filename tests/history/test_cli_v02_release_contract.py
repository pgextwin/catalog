"""Exact publication contracts for the frozen CLI v0.2 release workflows."""
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
ARCHIVE = ROOT / "tests/fixtures/historical-workflows"
RELEASES = (
    ("cli-v02", "cli-v0.2.0", "529718ac8ff829c8a98b57d26adb1d74971588c1",
     "1764d2f5a54b9fa715a2bba1d068493ef1d5dcb159b895e3f24becf2dee6fdc0", 39205817118),
    ("cli-v021", "cli-v0.2.1", "79db0018cd930847330c024770328892eb46cf3c",
     "78de25e4ac3b8d40ba173f3369a12cf92e97ee0e2a65695820390231e3d08aca", 39210035547),
    ("cli-v022", "cli-v0.2.2", "594df3d703d983d5978b640a03c64d498765035a",
     "3567e34cf9f7347cfab7a1292f58965b7bd15e2d8a2bb5b1f0479685633862a0", 39211701760),
)


class CliV02ReleasePolicyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.workflows = {
            name: (ARCHIVE / f"{name}-release.yml").read_text(encoding="utf-8")
            for name, *_ in RELEASES
        }

    def test_single_exact_bounded_operator_intent(self):
        for name, tag, source, exe, run in RELEASES:
            with self.subTest(tag=tag):
                intent = json.loads((ROOT / "config" / f"{name}-release-intent.json")
                                    .read_text(encoding="utf-8"))
                self.assertEqual(intent, dict(
                    schemaVersion="pgextwin-cli-preview-release/v1", publish=True,
                    scope="CLI_ONLY_READONLY_PREVIEW", tag=tag,
                    sourceCommit=source, sourceRunId=run, exeSha256=exe,
                ))
                for word in (source, exe, str(run), tag):
                    self.assertIn(word, self.workflows[name])

    def test_same_original_binary_and_sigstore_provenance(self):
        for name, tag, *_ in RELEASES:
            with self.subTest(tag=tag):
                workflow = self.workflows[name]
                for required in (
                    "--signer-workflow pgextwin/catalog/.github/workflows/cli-candidate.yml",
                    "--source-ref refs/heads/main", "--source-digest $expectedSource",
                    "cli-r6-private-candidate", "CLI_R7_GENUINE_ORIGINAL_SLSA_VERIFIED=PASS",
                    "pgextwin.exe", "DOTNET-LICENSE.txt", "DOTNET-THIRD-PARTY-NOTICES.txt",
                    "pgextwin.spdx.json", "SHA256SUMS.txt",
                ):
                    self.assertIn(required, workflow)

    def test_publishing_is_main_only_after_pr_gate(self):
        for name, tag, *_ in RELEASES:
            with self.subTest(tag=tag):
                workflow = self.workflows[name]
                self.assertIn("  pull_request:", workflow)
                self.assertIn("  push:", workflow)
                self.assertIn(f"'config/{name}-release-intent.json'", workflow)
                self.assertIn("if: github.event_name == 'push' && github.ref == 'refs/heads/main'", workflow)
                verify, publish = workflow.split("  verify:", 1)[1].split("\n  publish:", 1)
                self.assertNotIn("contents: write", verify)
                for required in ("needs: verify", "contents: write", "--verify-tag --draft --prerelease",
                                 "gh release download $tag", "gh release edit $tag"):
                    self.assertIn(required, publish)
                for forbidden in ("workflow_dispatch:", "workflow_run:", "pull_request_target:",
                                  "--clobber", "install --apply", "gh api --method DELETE"):
                    self.assertNotIn(forbidden, workflow)


if __name__ == "__main__":
    unittest.main()
