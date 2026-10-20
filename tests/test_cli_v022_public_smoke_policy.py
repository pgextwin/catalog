"""Read-only public CLI smoke contract; prevents trusted release claims from local artifacts."""
from pathlib import Path
import unittest

ROOT=Path(__file__).resolve().parents[1]
WORKFLOW=ROOT/"tests/fixtures/historical-workflows/cli-v022-public-smoke.yml"


class CliPublicSmokeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text=WORKFLOW.read_text(encoding="utf-8")

    def test_public_original_exe_only_and_readonly(self):
        t=self.text
        self.assertIn("runs-on: windows-latest",t)
        self.assertIn("contents: read",t)
        self.assertNotIn("contents: write",t)
        self.assertNotIn("id-token: write",t)
        for name in ("workflow_dispatch:", "pull_request_target:", "workflow_run:",
                     "gh release create", "gh release edit", "gh release upload"):
            with self.subTest(name=name):
                self.assertNotIn(name,t)
        self.assertIn("https://github.com/pgextwin/catalog/releases/download/$version/pgextwin.exe",t)
        self.assertIn("Invoke-WebRequest -Uri $url -OutFile $exe",t)
        self.assertNotIn("actions/download-artifact",t)

    def test_exact_release_sha_and_authentic_signer(self):
        t=self.text
        self.assertIn("416989357",t)
        self.assertIn("655483599",t)
        self.assertIn("73684232",t)
        self.assertIn("594df3d703d983d5978b640a03c64d498765035a",t)
        self.assertIn("3567e34cf9f7347cfab7a1292f58965b7bd15e2d8a2bb5b1f0479685633862a0",t)
        self.assertIn("--signer-workflow pgextwin/catalog/.github/workflows/cli-candidate.yml",t)
        self.assertIn("--source-ref refs/heads/main",t)
        self.assertIn("--source-digest $source",t)
        self.assertIn("CLI_PUBLIC_REAL_BYTE_AND_SLSA=PASS",t)
        self.assertIn("CLI_V022_PUBLIC_WINDOWS_BINARY=PASS",t)
        self.assertIn("LOCAL_UNAUTHENTICATED",t)
        self.assertIn("UNVERIFIED",t)
        self.assertIn("download-all",t)
        self.assertIn("Bulk download without independent policy was not denied",t)
        self.assertIn("Real 70 original Release ZIPs by exactly one user command",t)
        self.assertIn("download-all --pg all",t)
        self.assertIn("CLI_V022_REAL_70_ZIP_DOWNLOAD=PASS",t)
        self.assertIn("Get-FileHash -LiteralPath $file",t)
        self.assertIn("Unimplemented extension Sigstore verification accepted",t)


if __name__=="__main__":
    unittest.main()
