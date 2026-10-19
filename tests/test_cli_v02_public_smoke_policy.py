"""Read-only public CLI smoke contract; prevents trusted release claims from local artifacts."""
from pathlib import Path
import unittest

ROOT=Path(__file__).resolve().parents[1]
WORKFLOW=ROOT/".github/workflows/cli-v02-public-smoke.yml"


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
        self.assertIn("416943008",t)
        self.assertIn("655369584",t)
        self.assertIn("73663752",t)
        self.assertIn("529718ac8ff829c8a98b57d26adb1d74971588c1",t)
        self.assertIn("1764d2f5a54b9fa715a2bba1d068493ef1d5dcb159b895e3f24becf2dee6fdc0",t)
        self.assertIn("--signer-workflow pgextwin/catalog/.github/workflows/cli-candidate.yml",t)
        self.assertIn("--source-ref refs/heads/main",t)
        self.assertIn("--source-digest $source",t)
        self.assertIn("CLI_PUBLIC_REAL_BYTE_AND_SLSA=PASS",t)
        self.assertIn("CLI_V02_PUBLIC_WINDOWS_BINARY=PASS",t)
        self.assertIn("LOCAL_UNAUTHENTICATED",t)
        self.assertIn("UNVERIFIED",t)
        self.assertIn("download-all",t)
        self.assertIn("Bulk download without independent policy was not denied",t)
        self.assertIn("Unimplemented extension Sigstore verification accepted",t)


if __name__=="__main__":
    unittest.main()
