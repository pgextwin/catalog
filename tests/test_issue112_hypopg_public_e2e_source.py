"""Offline genuine-source, public-provenance and private direct GET guardrails."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
WF = (ROOT / '.github/workflows/issue112-external-public-get-e2e.yml').read_text()
PS = (ROOT / 'scripts/issue112-public-original-get-e2e.ps1').read_text()


class PublicGetGuard(unittest.TestCase):
    def test_genuine_original_source_only(self):
        for text in ('workflow_run:', 'github.event.workflow_run.run_attempt == 1',
                     "github.event.workflow_run.conclusion == 'success'",
                     "github.event.workflow_run.event == 'push'",
                     'gh api repos/pgextwin/catalog/branches/main',
                     '.commit.verification.verified==true', '.committer.login=="web-flow"',
                     'issue112-public-original-get-e2e.ps1'):
            self.assertIn(text, WF)
        self.assertNotIn('workflow_dispatch:', WF)
        self.assertNotIn('pull_request_target:', WF)

    def test_source_selected_from_relevant_direct_postmerge_commit(self):
        for text in ('external/direct-get.json', 'ExternalOriginalZipIntegrity.cs',
                     'AtomicStageGuard.cs', 'any(.files[]?;',
                     '(.status=="added" or .status=="modified")',
                     'NO_DIRECT_PATH_CHANGE; DIRECT_E2E=NOT_TESTED; no provider GET',
                     'echo "source=$CATALOG_SHA" >> "$GITHUB_OUTPUT"',
                     "if: needs.authenticate-original-main.outputs.source != ''",
                     'ref: ${{ needs.authenticate-original-main.outputs.source }}'):
            self.assertIn(text, WF)
        for text in ('signed-direct-get/', 'RECOVERY_PUBLIC_ONLY', 'PIN_PROVIDER', 'workflow-verified'):
            self.assertNotIn(text, WF)

    def test_formal_public_provenance_and_version_still_authenticated(self):
        for text in ('gh attestation verify $exe',
                     '--signer-workflow pgextwin/catalog/.github/workflows/cli-candidate.yml',
                     '--source-ref refs/heads/main --source-digest $source --deny-self-hosted-runners',
                     "$policy.publishAuthorized -ne $true", '$policy.approvedVersion -cne $version',
                     '$ref.object.sha -cne $source', "$comparison.status -cnotin @('ahead','identical')",
                     "$assets.Count -ne 1", "digest -cnotmatch '^sha256:[0-9a-f]{64}$'",
                     'Get-FileHash -LiteralPath $exe -Algorithm SHA256',
                     '$actual -cne $expected', '(& $exe --version).Trim() -cne $version',
                     'PUBLIC_CLI_BYTES_AND_SIGSTORE=PASS PROOF_SCOPE=PROVENANCE_VERSION_ONLY',
                     'PUBLIC_DIRECT_GET=NOT_TESTED LEGACY_SIGNED_CONTRACT'):
            self.assertIn(text, WF)
        self.assertNotIn('validate_public_get_pin.py', WF)
        self.assertNotIn('download-all', WF)

    def test_private_direct_all_originals_exact_hash_and_cleanup(self):
        for text in ("GITHUB_EVENT_NAME -cne 'workflow_run'",
                     "Join-Path $env:GITHUB_WORKSPACE 'external/direct-get.json'",
                     'pgextwin-external-direct-get/v1', '$manifest.records -isnot [array]',
                     "@('15','16','17','18')", '$row.licenseEvidence.Count -lt 1',
                     '$row.upstreamVersion', 'if (-not $identities.Add($identity)) { throw',
                     'if ($row.latest -eq $true)', '$expected.Count -lt 1 -or $expected.Count -gt 1000',
                     'Mandatory private-built CLI EXE missing',
                     '& $private download-all --source external --pg all --output $dest',
                     'if ($cliExit -ne 0)', 'throw "Actual private CLI provider GET failed',
                     '$originals.Count -ne $expected.Count', '$matches.Count -ne 1',
                     'Get-FileHash', '$original.Length -ne $pin.bytes -or $hash -cne $pin.sha',
                     'PRIVATE_DIRECT_PATH_ORIGINAL_GET_E2E=PASS SOURCE=external/direct-get.json CLI_KIND=private',
                     'ZIP_COUNT=$($expected.Count)', 'PUBLISH=DENY MIRROR=DENY',
                     'Remove-Item -LiteralPath $dest -Recurse -Force'):
            self.assertIn(text, PS)
        for text in ('--external-admission', '--external-bundle', 'gh release create',
                     'actions/upload-artifact', 'signed-direct-get/', 'expiresAt', '$PublicOnly', '$public'):
            self.assertNotIn(text, PS)


if __name__ == '__main__':
    unittest.main()
