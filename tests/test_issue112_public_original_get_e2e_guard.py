"""Keep genuine Windows original-provider E2E aligned with signed cohort sizes."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]


class PublicOriginalGetE2EGuard(unittest.TestCase):
    def test_signed_cohort_bound_and_expiry_denial_remain(self):
        script = (ROOT / "scripts/issue112-public-original-get-e2e.ps1").read_text()
        self.assertIn("@($latest.records).Count -lt 1", script)
        self.assertIn("@($latest.records).Count -gt 20", script)
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
        self.assertIn('.parents[0].sha=="eefae36c4209f0feced26d7b7759837118dadae6"', workflow)
        self.assertIn('([.files[]?] | length)==3', workflow)
        self.assertIn('AUTHENTIC_PUBLIC_ONLY_E2E_RECOVERY=PASS', workflow)
        self.assertIn('repos/pgextwin/catalog/actions/runs/43192028928', workflow)
        self.assertIn('ANON_GITHUB_METADATA_DIAGNOSTIC', script)
        self.assertIn('if ($PublicOnly -and $binary.kind -ceq \'public\')', script)
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

    def test_genuine_403_recovery_is_bounded_and_only_collects_anonymous_evidence(self):
        workflow = (ROOT / ".github/workflows/issue112-external-public-get-e2e.yml").read_text()
        script = (ROOT / "scripts/issue112-public-original-get-e2e.ps1").read_text()
        source = (ROOT / "dotnet/src/PgExtWin.Releases/AuthenticatedCatalogHead.cs").read_text()
        self.assertIn('.parents[0].sha=="c57b1a1a357461ea4ba6b0559e6d892af4fc2d23"', workflow)
        self.assertIn('([.files[]?] | length)==5', workflow)
        self.assertIn('repos/pgextwin/catalog/actions/runs/43343335451', workflow)
        self.assertIn('.run_attempt==2', workflow)
        self.assertIn('.id==131621144270', workflow)
        self.assertIn('AUTHENTIC_ANONYMOUS_CATALOG_403_DIAGNOSTIC_RECOVERY=PASS', workflow)
        self.assertIn('ANON_CATALOG_HTTP_DIAGNOSTIC', script)
        self.assertIn("Remove-Item Env:GH_TOKEN", script)
        self.assertIn("Remove-Item Env:GITHUB_TOKEN", script)
        self.assertIn('TARGET=', source)
        self.assertIn('RATE_REMAINING=', source)
        self.assertIn('RATE_RESET=', source)
        self.assertIn('RETRY_AFTER=', source)
        self.assertNotIn('workflow_dispatch:', workflow)
        self.assertNotIn('pull_request_target:', workflow)


if __name__ == "__main__":
    unittest.main()
