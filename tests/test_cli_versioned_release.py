"""Existing signed CLI publication protections survive versioned automation."""
from pathlib import Path
import re
import unittest

ROOT=Path(__file__).resolve().parents[1]

class VersionedCliRelease(unittest.TestCase):
    def test_only_successful_original_protected_main_candidate_can_publish(self):
        source=(ROOT/'.github/workflows/cli-release.yml').read_text()
        for required in (
            "github.event.workflow_run.event == 'push'",
            "github.event.workflow_run.head_branch == 'main'",
            "github.event.workflow_run.conclusion == 'success'",
            "github.event.workflow_run.run_attempt == 1",
            "$run.path -cne '.github/workflows/cli-candidate.yml'",
            "$native[0].conclusion -ceq 'success'", "$_.app.id -eq 15368",
        ):
            self.assertIn(required,source)
        self.assertNotIn('workflow_dispatch:',source)
        self.assertNotIn('pull_request_target:',source)
        self.assertIn('pgextwin-cli-create-only-release-${{ github.event.workflow_run.event }}-${{ github.event.workflow_run.head_branch }}',source)
        prepare,publish=source.split('\n  publish:',1)
        self.assertNotIn('contents: write',prepare)
        self.assertIn('needs: prepare',publish)
        self.assertIn("if: needs.prepare.outputs.version != ''",publish)
        self.assertIn('contents: write',publish)

    def test_original_signature_create_only_tag_and_five_asset_rehash_remain(self):
        source=(ROOT/'.github/workflows/cli-release.yml').read_text()
        self.assertEqual(source.count('--signer-workflow pgextwin/catalog/.github/workflows/cli-candidate.yml'),2)
        self.assertIn('--source-digest $source',source)
        self.assertIn('--source-digest $env:SOURCE',source)
        self.assertIn('gh api --method POST repos/pgextwin/catalog/git/refs',source)
        self.assertIn('gh api --method POST repos/pgextwin/catalog/releases --input $requestFile',source)
        self.assertIn('draft=$true;prerelease=$true',source)
        self.assertIn('https://uploads.github.com/repos/pgextwin/catalog/releases/',source)
        self.assertIn('-InFile $file.FullName -MaximumRedirection 0',source)
        self.assertLess(source.index('Draft uploaded asset digest differs'),source.index('-F draft=false'))
        self.assertIn('gh api --method PATCH "repos/pgextwin/catalog/releases/$($release.id)"',source)
        self.assertIn('Public downloaded asset bytes differ',source)
        self.assertNotIn('gh release create',source)
        self.assertIn("./scripts/cli_r7_asset_set.ps1",source)
        self.assertIn('$asset.digest -cne "sha256:$hash"',source)
        self.assertIn('## English',source)
        self.assertLess(source.index('## English'),source.index('## 日本語'))
        for forbidden in ('--clobber','gh release delete','secrets: inherit','force: true'):
            self.assertNotIn(forbidden,source)
        for dependency in re.findall(r'(?m)^\s*- uses:\s+(\S+)',source):
            self.assertRegex(dependency,r'^[^@]+@[0-9a-f]{40}$')


    def test_publisher_public_smoke_checks_signed_feed_and_direct_pins(self):
        release=(ROOT/'.github/workflows/cli-release.yml').read_text()
        smoke=release.split("  public-smoke:",1)[1]
        self.assertNotIn("pgextwin-pg14-18",smoke)
        self.assertIn("Expected exactly one signed PG cohort directory",smoke)
        self.assertIn("CATALOG_COMMIT=([0-9a-f]{40})",smoke)
        self.assertIn("check-cli-signed-feed-receipt.ps1",smoke)
        self.assertIn("ref: ${{ needs.prepare.outputs.source }}",smoke)
        self.assertIn("issue112-public-original-get-e2e.ps1 -CliKind public",smoke)
        self.assertNotIn("validate_public_get_pin.py",smoke)
        self.assertNotIn("expiresAt",smoke)
        self.assertIn("Remove-Item Env:GH_TOKEN",smoke)

    def test_genuine_published_e2e_covers_signed_feed_and_direct_pins(self):
        e2e=(ROOT/'.github/workflows/cli-published-e2e.yml').read_text()
        self.assertIn("workflow_dispatch:",e2e)
        self.assertNotIn("  push:",e2e)
        self.assertIn("'refs/heads/main'",e2e)
        self.assertIn("Independently verify the published EXE Sigstore provenance",e2e)
        self.assertIn("Run the public EXE without tokens and rehash the complete current roster",e2e)
        self.assertIn("issue112-public-original-get-e2e.ps1 -CliKind public",e2e)
        self.assertNotIn("validate_public_get_pin.py",e2e)
        self.assertNotIn("expiresAt",e2e)
        self.assertIn("Remove-Item Env:GH_TOKEN",e2e)
        self.assertIn("published-pgextwin.exe",e2e)
        self.assertNotIn("--source all",e2e)
        self.assertNotIn("contents: write",e2e)
        self.assertNotIn("gh release create",e2e)

if __name__=='__main__': unittest.main()
