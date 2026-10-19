"""Strict exact CLI v0.2.2 publication contract; no live network or mutation."""
from pathlib import Path
import json
import unittest

ROOT=Path(__file__).resolve().parents[1]
WF=(ROOT/".github/workflows/cli-v022-release.yml").read_text(encoding="utf-8")
INTENT=json.loads((ROOT/"config/cli-v022-release-intent.json").read_text(encoding="utf-8"))
SOURCE="594df3d703d983d5978b640a03c64d498765035a"
EXE="3567e34cf9f7347cfab7a1292f58965b7bd15e2d8a2bb5b1f0479685633862a0"
RUN="39211701760"

class CliV022ReleasePolicyTests(unittest.TestCase):
    def test_single_exact_bounded_operator_intent(self):
        self.assertEqual(INTENT,dict(schemaVersion="pgextwin-cli-preview-release/v1",
            publish=True,scope="CLI_ONLY_READONLY_PREVIEW",tag="cli-v0.2.2",
            sourceCommit=SOURCE,sourceRunId=int(RUN),exeSha256=EXE))
        for word in (SOURCE,EXE,RUN,"cli-v0.2.2"):
            self.assertIn(word,WF)

    def test_same_original_binary_and_sigstore_provenance(self):
        self.assertIn("--signer-workflow pgextwin/catalog/.github/workflows/cli-candidate.yml",WF)
        self.assertIn("--source-ref refs/heads/main",WF)
        self.assertIn("--source-digest $expectedSource",WF)
        self.assertIn("cli-r6-private-candidate",WF)
        self.assertIn("CLI_R7_GENUINE_ORIGINAL_SLSA_VERIFIED=PASS",WF)
        self.assertIn("pgextwin.exe",WF)
        self.assertIn("DOTNET-LICENSE.txt",WF)
        self.assertIn("DOTNET-THIRD-PARTY-NOTICES.txt",WF)
        self.assertIn("pgextwin.spdx.json",WF)
        self.assertIn("SHA256SUMS.txt",WF)

    def test_publishing_is_main_only_after_pr_gate(self):
        self.assertIn("  pull_request:",WF)
        self.assertIn("  push:",WF)
        self.assertIn("'config/cli-v022-release-intent.json'",WF)
        self.assertIn("if: github.event_name == 'push' && github.ref == 'refs/heads/main'",WF)
        v=WF.split("  verify:",1)[1].split("\n  publish:",1)[0]
        p=WF.split("\n  publish:",1)[1]
        self.assertNotIn("contents: write",v)
        self.assertIn("needs: verify",p)
        self.assertIn("contents: write",p)
        self.assertIn("--verify-tag --draft --prerelease",p)
        self.assertIn("gh release download $tag",p)
        self.assertIn("gh release edit $tag",p)
        for forbidden in ("workflow_dispatch:", "workflow_run:", "pull_request_target:",
                          "--clobber", "install --apply", "gh api --method DELETE"):
            self.assertNotIn(forbidden,WF)

if __name__=="__main__":
    unittest.main()
