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
        self.assertIn('--verify-tag --target $env:SOURCE --draft',source)
        self.assertLess(source.index('Draft public asset bytes differ'),source.index('--draft=false'))
        self.assertIn("./scripts/cli_r7_asset_set.ps1",source)
        self.assertIn('$asset.digest -cne "sha256:$hash"',source)
        self.assertIn('## English',source)
        self.assertLess(source.index('## English'),source.index('## 日本語'))
        for forbidden in ('--clobber','gh release delete','secrets: inherit','force: true'):
            self.assertNotIn(forbidden,source)
        for dependency in re.findall(r'(?m)^\s*- uses:\s+(\S+)',source):
            self.assertRegex(dependency,r'^[^@]+@[0-9a-f]{40}$')

if __name__=='__main__': unittest.main()
