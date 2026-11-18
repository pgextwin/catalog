"""Prevent fake acceptance at the Windows direct GET acceptance paths."""
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]
WF = (ROOT / ".github/workflows/issue112-external-public-get-e2e.yml").read_text()
PS = (ROOT / "scripts/issue112-public-original-get-e2e.ps1").read_text()
COMMAND = "& $CliPath download-all --source external --pg all --output $dest"
PASS = "DIRECT_PATH_ORIGINAL_GET_E2E=PASS"


class PublicOriginalGetE2EGuard(unittest.TestCase):
    def test_authenticated_original_current_protected_main_only(self):
        for text in (
            "github.repository == 'pgextwin/catalog'",
            "github.event_name == 'workflow_run'",
            "github.event.workflow_run.event == 'push'",
            "github.event.workflow_run.head_branch == 'main'",
            "github.event.workflow_run.run_attempt == 1",
            "github.event.workflow_run.conclusion == 'success'",
            'set -euo pipefail', '[[ "$CATALOG_SHA" =~ ^[0-9a-f]{40}$ ]] || exit 1',
            'gh api repos/pgextwin/catalog/branches/main',
            '''[[ "$(jq -r '.protected' <<< "$branch")" == true ]]''',
            '''[[ "$(jq -r '.commit.sha' <<< "$branch")" == "$CATALOG_SHA" ]]''',
            '.status=="completed" and .conclusion=="success"',
            '.event=="push" and .head_branch=="main" and .head_sha==$sha',
            '.run_attempt==1 and .path==".github/workflows/validate.yml"',
            '.repository.full_name=="pgextwin/catalog"',
            '.name=="validate" and .conclusion=="success"',
            '.commit.verification.verified==true and .commit.verification.reason=="valid"',
            '.committer.login=="web-flow"', '.commit.committer.email=="noreply@github.com"',
        ):
            self.assertIn(text, WF)
            self.assertLess(WF.index(text), WF.index('if ! jq -e'))

    def test_relevance_is_bounded_to_direct_runtime_and_entrance(self):
        predicate = WF.split("if ! jq -e '", 1)[1].split("' <<<", 1)[0]
        self.assertIn('any(.files[]?;', predicate)
        self.assertIn('(.status=="added" or .status=="modified") and', predicate)
        paths = re.findall(r'^\s+"([^"]+)"', predicate, re.M)
        self.assertEqual(set(paths), {
            'external/direct-get.json',
            'external/standalone-get.json',
            'dotnet/src/PgExtWin.Cli/Program.cs',
            'dotnet/src/PgExtWin.Releases/ExternalDownloadItem.cs',
            'dotnet/src/PgExtWin.Releases/ExternalSignedCatalogCohort.cs',
            'dotnet/src/PgExtWin.Releases/ExternalProviderAssetTransport.cs',
            'dotnet/src/PgExtWin.Releases/ExternalOriginalBatchStager.cs',
            'dotnet/src/PgExtWin.Releases/AtomicOriginalBatchDirectory.cs',
            'dotnet/src/PgExtWin.Releases/ExternalOriginalZipIntegrity.cs',
            'dotnet/src/PgExtWin.Releases/AtomicStageGuard.cs',
            '.github/workflows/issue112-external-public-get-e2e.yml',
            'scripts/issue112-public-original-get-e2e.ps1',
        })
        self.assertNotIn('length', predicate)  # extra license/evidence files are allowed
        self.assertIn("NO_DIRECT_PATH_CHANGE; DIRECT_E2E=NOT_TESTED; no provider GET'\n            exit 0\n          fi", WF)
        self.assertLess(WF.index('NO_DIRECT_PATH_CHANGE'), WF.index('echo "source=$CATALOG_SHA"'))
        self.assertEqual(WF.count('echo "source=$CATALOG_SHA" >> "$GITHUB_OUTPUT"'), 1)
        self.assertIn("if: needs.authenticate-original-main.outputs.source != ''", WF)

    def test_exact_checkout_private_windows_build_and_read_only_pins(self):
        self.assertEqual(re.findall(r'^  ([\w-]+):$', WF.split('jobs:\n', 1)[1], re.M),
                         [ 'authenticate-original-main', 'windows-real-original-get'])
        self.assertIn('ref: ${{ needs.authenticate-original-main.outputs.source }}', WF)
        self.assertIn('persist-credentials: false', WF)
        self.assertEqual(re.findall(r'uses: (\S+)', WF), [
            'actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1',
            'actions/setup-dotnet@67a3573c9a986a3f9c594539f4ab511d57bb3ce9',
        ])
        self.assertEqual(re.findall(r'^\s+(?:contents|actions|id-token|attestations): (\w+)$', WF, re.M), ['read', 'read'])
        self.assertIn('runs-on: windows-latest', WF)
        self.assertIn('dotnet publish dotnet/src/PgExtWin.Cli/PgExtWin.Cli.csproj', WF)
        self.assertIn('--runtime win-x64 --self-contained true', WF)
        self.assertIn("throw 'Private Windows CLI build missing'", WF)
        self.assertLess(WF.index('dotnet publish'), WF.index('./scripts/issue112-public-original-get-e2e.ps1'))

    def test_checkout_manifest_shape_and_exact_version_license_bookkeeping(self):
        for text in (
            "Join-Path $env:GITHUB_WORKSPACE 'external/direct-get.json'",
            "throw 'Direct manifest absent'",
            "schemaVersion -cne 'pgextwin-external-direct-get/v1'",
            '$manifest.records -isnot [array]', '$manifest.records.Count -lt 1',
            '$expected=@(foreach ($row in $manifest.records)',
            "@('extension','pgMajor','upstreamVersion','license','assetName','originalSha256')",
            '$row.$field -isnot [string]', '[string]::IsNullOrWhiteSpace($row.$field)',
            '$row.licenseEvidence -isnot [array]', '$row.licenseEvidence.Count -lt 1',
            '$row.latest -isnot [bool]', "$row.pgMajor -cnotin @('14','15','16','17','18')",
            "[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)",
            "$identity=$row.extension + ':' + $row.pgMajor + ':' + $row.upstreamVersion",
            'if (-not $identities.Add($identity)) { throw',
        ):
            self.assertIn(text, PS)
        self.assertLess(PS.index('$manifest=Get-Content'), PS.index(COMMAND))
        self.assertLess(PS.index('$standalone=Get-Content'), PS.index(COMMAND))
        self.assertEqual(PS.count('Get-Content'), 2)  # no post-GET expectation refresh
        self.assertIn("external/standalone-get.json", PS)
        self.assertIn("pgextwin-standalone-get/v1", PS)

    def test_latest_only_selection_and_dynamic_nonempty_batch_bound(self):
        selection = PS.split('if ($row.latest -eq $true) {', 1)[1].split('\n    }', 1)[0]
        self.assertIn("@{path=$path;bytes=[long]$row.originalBytes;sha=[string]$row.originalSha256;source='external/direct-get.json'}", selection)
        self.assertIn("""$major=if ($null -eq $row.pgMajor) { 'any' } else { "pg$($row.pgMajor)" }""", PS)
        self.assertIn("$path=Join-Path 'pgextwin-external-all' $major $row.item $row.assetName", PS)
        self.assertIn('if (-not $selectedPaths.Add($path)) { throw', selection)
        self.assertIn('[StringComparer]::OrdinalIgnoreCase', PS)
        self.assertLess(PS.index('$identities.Add'), PS.index('if ($row.latest -eq $true)'))
        self.assertIn("if ($expected.Count -lt 1 -or $expected.Count -gt 1000) { throw", PS)
        self.assertNotRegex(PS, r'(?:Count\s*-(?:eq|ne|gt|ge|lt|le)\s*(?:17|20)\b|FILE_COUNT=17)')
        self.assertLess(PS.index('$expected.Count -gt 1000'), PS.index(COMMAND))
        self.assertNotRegex(PS, r'\$expected\s*=.*(?:originals|Intersect|Compare-Object)')

    def test_mandatory_executable_and_real_cli_before_acceptance(self):
        self.assertIn("[Parameter(Mandatory)] [string]$CliPath", PS)
        self.assertIn("if (-not (Test-Path -LiteralPath $CliPath -PathType Leaf)) { throw 'Expected CLI EXE missing' }", PS)
        self.assertEqual(PS.count(COMMAND), 1)
        self.assertEqual(len(re.findall(r'^\s*& ', PS, re.M)), 1)
        self.assertLess(PS.index('Expected CLI EXE missing'), PS.index(COMMAND))
        self.assertIn(COMMAND + '\n    $cliExit=$LASTEXITCODE\n    if ($cliExit -ne 0) {', PS)
        self.assertLess(PS.index('throw "Actual $CliKind CLI provider GET failed (exit=$cliExit)"'), PS.index('$originals=@('))
        self.assertLess(PS.index('$originals=@('), PS.index(PASS))
        self.assertEqual(PS.count(PASS), 1)
        self.assertNotRegex(PS, r'(?im)^\s*(?:exit\s+0|return)\b')
        self.assertNotIn('$public', PS)
        self.assertNotIn('$binaries', PS)

    def test_full_exact_byte_and_unique_path_verification(self):
        for text in (
            "$row.originalSha256 -cnotmatch '^[0-9a-f]{64}$'",
            '$row.originalBytes -lt 4 -or $row.originalBytes -gt 67108864',
            "Get-ChildItem -LiteralPath $dest -Recurse -File)",
            'if ($originals.Count -ne $expected.Count) {',
            'throw "Original cohort completeness mismatch:',
            'foreach ($pin in $expected)',
            '''$path=Join-Path 'pgextwin-external-all' "pg$($row.pgMajor)" $row.extension $row.assetName''',
            '$path=Join-Path $dest $pin.path',
            'if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw',
            'Get-FileHash -LiteralPath $original.FullName -Algorithm SHA256',
            'if ($original.Length -ne $pin.bytes -or $hash -cne $pin.sha) {',
            'throw "Original provider exact byte mismatch',
            'FILE_COUNT=$($expected.Count) MIRROR=DENY',
        ):
            self.assertIn(text, PS)
            self.assertLess(PS.index(text), PS.index(PASS) if not text.startswith('FILE_COUNT') else len(PS))

    def test_tokens_removed_and_diagnostics_cannot_be_acceptance(self):
        for token in ('GH_TOKEN', 'GITHUB_TOKEN'):
            self.assertLess(PS.index('Remove-Item Env:' + token), PS.index(COMMAND))
        failure = PS.split('if ($cliExit -ne 0) {', 1)[1].split('$originals=@(', 1)[0]
        self.assertIn('ANON_CATALOG_HTTP_DIAGNOSTIC', failure)
        self.assertIn('-TimeoutSec 10 -MaximumRedirection 0', failure)
        self.assertIn('STATUS=UNAVAILABLE (DENY)', failure)
        self.assertTrue(failure.rstrip().endswith('throw "Actual $CliKind CLI provider GET failed (exit=$cliExit)"\n    }'))
        self.assertNotIn('=PASS', failure)
        self.assertNotRegex(PS, r'(?i)authorization|bearer|\$env:(?:GH_TOKEN|GITHUB_TOKEN)')
        for env in ('GITHUB_ACTIONS', 'GITHUB_REPOSITORY', 'GITHUB_EVENT_NAME', 'RUNNER_OS', 'GITHUB_WORKSPACE', 'RUNNER_TEMP'):
            self.assertIn('$env:' + env, PS)
        self.assertIn("throw 'Expected a disposable Catalog Windows acceptance job'", PS)

    def test_cleanup_warning_precedes_private_pass(self):
        self.assertIn('} finally {', PS)
        self.assertIn('Remove-Item -LiteralPath $dest -Recurse -Force -ErrorAction Stop', PS)
        self.assertIn("throw 'Destination path still exists after Remove-Item'", PS)
        self.assertIn('Write-Warning "STAGING_CLEANUP_WARNING CLI_KIND=$CliKind ERROR=$cleanupError" -WarningAction Continue', PS)
        self.assertLess(PS.index('} finally {'), PS.index(PASS))
        self.assertIn('SOURCE=$($pin.source) CLI_KIND=$CliKind', PS)

    def test_public_provenance_is_separate_and_never_public_direct_proof(self):
        call = './scripts/issue112-public-original-get-e2e.ps1'
        self.assertEqual(WF.count(call), 1)
        self.assertIn(call + " -CliKind private -CliPath (Join-Path $env:RUNNER_TEMP 'issue112-private-cli/pgextwin.exe')", WF)
        self.assertLess(WF.index(call), WF.index('gh release download'))
        self.assertIn('PUBLIC_DIRECT_GET=NOT_TESTED PROOF_SCOPE=PROVENANCE_VERSION_ONLY', WF)
        self.assertIn('PUBLIC_CLI_BYTES_AND_SIGSTORE=PASS PROOF_SCOPE=PROVENANCE_VERSION_ONLY', WF)
        self.assertNotIn('download-all', WF)
        for text in ('PUBLIC_CLI_PROVENANCE=SKIPPED_NO_FORMAL_CLI_RELEASE',
                     'PUBLIC_CLI_PROVENANCE=SKIPPED_PENDING_FORMAL_OWNER_RELEASE',
                     "throw 'Public CLI independent Sigstore provenance verification failed'"):
            self.assertIn(text, WF)

    def test_retired_prerequisites_and_synthetic_or_publication_routes_absent(self):
        for text in ('signed-direct-get/', 'issuerRunId', 'expiresAt', 'PublicOnly',
                     'PIN_PROVIDER', 'RECOVERY_PUBLIC_ONLY', 'validate_public_get_pin.py',
                     'external-get-admission.json', 'recovery=true'):
            self.assertNotIn(text, WF + PS)
        for text in ('workflow_dispatch:', 'pull_request_target:', 'schedule:',
                     'repository_dispatch:', 'actions/download-artifact',
                     'actions/upload-artifact', 'gh workflow run', 'gh release create',
                     'gh release upload', 'contents: write', 'id-token: write',
                     '--external-admission', '--external-bundle'):
            self.assertNotIn(text, WF + PS)
        # Historical archival validation is deliberately retained in general Validate.
        self.assertIn('python scripts/validate_public_get_pin.py --catalog .',
                      (ROOT / '.github/workflows/validate.yml').read_text())


if __name__ == '__main__':
    unittest.main()
