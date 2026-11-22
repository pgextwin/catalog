"""Original-byte and read-only contracts for frozen CLI public smoke workflows."""
from pathlib import Path
import unittest

ARCHIVE = Path(__file__).resolve().parents[2] / "tests/fixtures/historical-workflows"
BULK = ("download-all", "Bulk download without independent policy was not denied")
SMOKES = {
    "cli-public-smoke.yml": (
        "416920183", "655295134", "73647388",
        "d0056b688dc27095d2d7ffd6f8b77aff965def79",
        "c2782f46539bd932c9c19105055e45dcf8796d573a8c30ad9844e6ba510ddfb1",
        "CLI_PUBLIC_DOWNLOADED_WIN_X64_SMOKE=PASS",
    ),
    "cli-v02-public-smoke.yml": (
        "416943008", "655369584", "73663752",
        "529718ac8ff829c8a98b57d26adb1d74971588c1",
        "1764d2f5a54b9fa715a2bba1d068493ef1d5dcb159b895e3f24becf2dee6fdc0",
        "CLI_V02_PUBLIC_WINDOWS_BINARY=PASS", *BULK,
    ),
    "cli-v022-public-smoke.yml": (
        "416989357", "655483599", "73684232",
        "594df3d703d983d5978b640a03c64d498765035a",
        "3567e34cf9f7347cfab7a1292f58965b7bd15e2d8a2bb5b1f0479685633862a0",
        "CLI_V022_PUBLIC_WINDOWS_BINARY=PASS", *BULK,
        "Real 70 original Release ZIPs by exactly one user command",
        "download-all --pg all", "CLI_V022_REAL_70_ZIP_DOWNLOAD=PASS",
        "Get-FileHash -LiteralPath $file",
    ),
}


class CliPublicSmokeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.workflows = {name: (ARCHIVE / name).read_text(encoding="utf-8") for name in SMOKES}

    def test_public_original_exe_only_and_readonly(self):
        for name, workflow in self.workflows.items():
            with self.subTest(workflow=name):
                for required in (
                    "runs-on: windows-latest", "contents: read",
                    "https://github.com/pgextwin/catalog/releases/download/$version/pgextwin.exe",
                    "Invoke-WebRequest -Uri $url -OutFile $exe",
                ):
                    self.assertIn(required, workflow)
                for forbidden in (
                    "contents: write", "id-token: write", "workflow_dispatch:",
                    "pull_request_target:", "workflow_run:", "gh release create",
                    "gh release edit", "gh release upload", "actions/download-artifact",
                ):
                    self.assertNotIn(forbidden, workflow)

    def test_exact_release_sha_and_authentic_signer(self):
        for name, expected in SMOKES.items():
            with self.subTest(workflow=name):
                for marker in (
                    *expected,
                    "--signer-workflow pgextwin/catalog/.github/workflows/cli-candidate.yml",
                    "--source-ref refs/heads/main", "--source-digest $source",
                    "CLI_PUBLIC_REAL_BYTE_AND_SLSA=PASS", "LOCAL_UNAUTHENTICATED", "UNVERIFIED",
                    "Unimplemented extension Sigstore verification accepted",
                ):
                    self.assertIn(marker, self.workflows[name])


if __name__ == "__main__":
    unittest.main()
