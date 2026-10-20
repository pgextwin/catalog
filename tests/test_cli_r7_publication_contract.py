"""Guardrails for a gated v0.1 CLI-only release, with no live publish."""
from pathlib import Path
import json
import unittest

ROOT=Path(__file__).resolve().parents[1]
WORKFLOW=ROOT/"tests"/"fixtures"/"historical-workflows"/"cli-preview-release.yml"
INTENT=ROOT/"config"/"cli-preview-release-intent.json"


class CliReleasePolicyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.doc=WORKFLOW.read_text(encoding="utf-8")

    def test_no_release_before_separate_intent_pr(self):
        self.assertIn("'config/cli-preview-release-intent.json'",self.doc)
        if INTENT.exists():
            record=json.loads(INTENT.read_text(encoding="utf-8"))
            self.assertEqual(set(record), {"schemaVersion","publish","scope","tag","sourceCommit","sourceRunId","exeSha256"})
            self.assertEqual(record["schemaVersion"],"pgextwin-cli-preview-release/v1")
            self.assertIs(record["publish"],True)
            self.assertEqual(record["scope"],"CLI_ONLY_READONLY_PREVIEW")
            self.assertEqual(record["tag"],"cli-v0.1.0-preview.1")
            self.assertEqual(record["sourceRunId"],39200819667)
            self.assertEqual(record["sourceCommit"],"d0056b688dc27095d2d7ffd6f8b77aff965def79")
            self.assertEqual(record["exeSha256"],"c2782f46539bd932c9c19105055e45dcf8796d573a8c30ad9844e6ba510ddfb1")
        self.assertIn("branches: [main]",self.doc)
        self.assertIn("pull_request:",self.doc)
        self.assertIn("if: github.event_name == 'push' && github.ref == 'refs/heads/main'",self.doc)
        for forbidden in ("pull_request_target:", "workflow_dispatch:", "workflow_run:"):
            with self.subTest(event=forbidden):
                self.assertNotIn(forbidden,self.doc)

    def test_nonpublishing_verifier_before_write_scoped_job(self):
        self.assertIn("  verify:",self.doc)
        self.assertIn("  publish:",self.doc)
        verify=self.doc.split("  verify:",1)[1].split("\n  publish:",1)[0]
        publish=self.doc.split("\n  publish:",1)[1]
        self.assertNotIn("contents: write",verify)
        self.assertIn("needs: verify",publish)
        self.assertIn("contents: write",publish)
        self.assertIn("CLI_R7_GENUINE_ORIGINAL_SLSA_VERIFIED=PASS",verify)
        self.assertIn("CLI_R7_PUBLIC_RELEASE=PASS",publish)

    def test_real_sha_and_signer_enforced(self):
        self.assertIn("39200819667",self.doc)
        self.assertIn("d0056b688dc27095d2d7ffd6f8b77aff965def79",self.doc)
        self.assertIn("c2782f46539bd932c9c19105055e45dcf8796d573a8c30ad9844e6ba510ddfb1",self.doc)
        self.assertIn("--signer-workflow pgextwin/catalog/.github/workflows/cli-candidate.yml",self.doc)
        self.assertIn("--source-ref refs/heads/main",self.doc)
        self.assertIn("--source-digest $expectedSource",self.doc)
        self.assertIn("--verify-tag --draft --prerelease",self.doc)
        self.assertIn("gh release download $tag",self.doc)
        self.assertIn("--draft=false",self.doc)
        self.assertNotIn("--clobber",self.doc)


if __name__=="__main__":
    unittest.main()
