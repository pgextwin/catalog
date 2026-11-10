"""Keep genuine Windows original-provider E2E aligned with signed cohort sizes."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]


class PublicOriginalGetE2EGuard(unittest.TestCase):
    def test_exact_unsigned_sizes_and_expiry_denial_remain(self):
        script = (ROOT / "scripts/issue112-public-original-get-e2e.ps1").read_text()
        self.assertIn("@($latest.records).Count -notin @(5,7,11)", script)
        self.assertIn("if ($now -ge [DateTimeOffset]::Parse($signed.expiresAt))", script)
        self.assertIn("download-all --source external --pg $pgArg --output $dest", script)
        self.assertIn("Original cohort completeness mismatch", script)
        self.assertIn("Get-FileHash -LiteralPath $original.FullName -Algorithm SHA256", script)
        self.assertIn("REAL_WINDOWS_ORIGINAL_GET_ONLY_E2E=PASS", script)


if __name__ == "__main__":
    unittest.main()
