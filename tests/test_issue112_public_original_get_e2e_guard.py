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


    def test_one_shot_public_recovery_never_broadens_issuer_or_replays_private(self):
        workflow = (ROOT / ".github/workflows/issue112-external-public-get-e2e.yml").read_text()
        script = (ROOT / "scripts/issue112-public-original-get-e2e.ps1").read_text()
        # One genuine postmerge Validate, one immutable parent and exactly three
        # reviewed recovery files. An ordinary later main commit cannot replay it.
        self.assertIn('github.event.workflow_run.event == \'push\'', workflow)
        self.assertIn('.committer.login=="web-flow"', workflow)
        self.assertIn('.parents[0].sha=="82ed47a48d65278582f848a3964f5eb14699fe41"', workflow)
        self.assertIn('([.files[]?] | length)==3', workflow)
        self.assertIn('AUTHENTIC_PUBLIC_ONLY_E2E_RECOVERY=PASS', workflow)
        self.assertIn('RECOVERY_PUBLIC_ONLY:', workflow)
        self.assertIn('-PublicOnly', workflow)
        self.assertIn('python scripts/validate_public_get_pin.py --catalog .', workflow)
        self.assertNotIn('workflow_dispatch:', workflow)
        self.assertNotIn('pull_request_target:', workflow)
        self.assertIn('[switch]$PublicOnly', script)
        self.assertIn("if ($PublicOnly) { throw 'Public E2E recovery DENY: original admission expired' }", script)
        self.assertIn("$binaries=@(@{kind='public';path=$public})", script)
        self.assertIn('Remove-Item Env:GH_TOKEN', script)
        self.assertIn('Remove-Item Env:GITHUB_TOKEN', script)


if __name__ == "__main__":
    unittest.main()
