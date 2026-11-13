# Issue #112: actual published and privately compiled CLI direct original GET E2E.
# Only invoked by workflow_run after authenticated original Catalog/main push Validate.
[CmdletBinding()]
param([Parameter(Mandatory=$true)][ValidateSet('qualified_cohort')][string]$Source, [switch]$PublicOnly)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$PSNativeCommandUseErrorActionPreference=$false
if ($env:GITHUB_ACTIONS -cne 'true' -or
    $env:GITHUB_REPOSITORY -cne 'pgextwin/catalog' -or
    $env:GITHUB_EVENT_NAME -cne 'workflow_run' -or
    $env:RUNNER_OS -cne 'Windows' -or -not $env:GITHUB_WORKSPACE -or
    -not $env:RUNNER_TEMP) { throw 'Not a genuine disposable Catalog Windows workflow_run' }
$root=Join-Path $env:GITHUB_WORKSPACE "external/signed-direct-get/$Source"
if (-not (Test-Path -LiteralPath $root -PathType Container)) { throw 'Public original signed source absent' }
$latestPath=Join-Path $root 'latest.json'
if (-not (Test-Path -LiteralPath $latestPath -PathType Leaf)) { throw 'Catalog latest original pins absent' }
$latest=Get-Content -LiteralPath $latestPath -Raw | ConvertFrom-Json
if ($latest.schemaVersion -cne 'pgextwin-external-latest-original-pins/v1' -or
    [long]$latest.issuerRunId -le 0 -or @($latest.records).Count -lt 1 -or
    @($latest.records).Count -gt 20) {
    throw 'Catalog latest original pin schema invalid'
}
$now=[DateTimeOffset]::UtcNow
$selected=Join-Path $root ("run-" + [string]$latest.issuerRunId)
if (-not (Test-Path -LiteralPath $selected -PathType Container)) { throw 'Catalog latest signed Run archive absent' }
$admission=Join-Path $selected 'external-get-admission.json'
$signed=Get-Content -LiteralPath $admission -Raw | ConvertFrom-Json
if ([long]$signed.issuerRunId -ne [long]$latest.issuerRunId -or
    ([DateTimeOffset]::Parse($signed.issuedAt) -gt $now)) {
    throw 'Catalog latest admission Run is future-dated or mismatched'
}
if ($now -ge [DateTimeOffset]::Parse($signed.expiresAt)) {
    if ($PublicOnly) { throw 'Public E2E recovery DENY: original admission expired' }
    Write-Output 'Catalog latest admission Run is expired; provider GET skipped until fresh owner authorization'
    exit 0
}
$public=Join-Path $env:RUNNER_TEMP 'issue112-public-cli/pgextwin.exe'
if ($PublicOnly) {
    # Bounded one-shot recovery: do not repeat the already-successful private
    # 11/11 GET. A fresh, independently verified public EXE must exist.
    if (-not (Test-Path -LiteralPath $public -PathType Leaf)) {
        throw 'Public E2E recovery requires actual published CLI'
    }
    $binaries=@(@{kind='public';path=$public})
} else {
    $binaries=@(@{kind='private';path=(Join-Path $env:RUNNER_TEMP 'issue112-private-cli/pgextwin.exe')})
    if (Test-Path -LiteralPath $public -PathType Leaf) {
        $binaries+=@{kind='public';path=$public}
    } else {
        Write-Output 'PUBLIC_CLI_ORIGINAL_GET=SKIPPED_NO_FORMAL_CLI_RELEASE'
    }
}
$pgArg='all'
$expected=@($latest.records | ForEach-Object {
    @{name=[string]$_.assetName;bytes=[long]$_.originalBytes;sha=[string]$_.originalSha256}
})
Remove-Item Env:GH_TOKEN -ErrorAction SilentlyContinue
Remove-Item Env:GITHUB_TOKEN -ErrorAction SilentlyContinue
foreach ($binary in $binaries) {
    if (-not (Test-Path -LiteralPath $binary.path -PathType Leaf)) { throw 'CLI EXE missing' }
    $dest=Join-Path $env:RUNNER_TEMP "issue112-user-local-$($binary.kind)"
    New-Item -ItemType Directory -Path $dest -ErrorAction Stop | Out-Null
    try {
        & $($binary.path) download-all --source external --pg $pgArg --output $dest
        if ($LASTEXITCODE -ne 0) {
            # Anonymous diagnostics only, AFTER a genuine rejected local GET.
            # No job token, response body, redirect fallback or auth elevation.
            foreach ($endpoint in @(
                @{name='RATE_LIMIT';url='https://api.github.com/rate_limit'},
                @{name='CATALOG_HEAD';url='https://api.github.com/repos/pgextwin/catalog/branches/main'}
            )) {
                try {
                    $probe=Invoke-WebRequest -Uri $endpoint.url -Method Get -SkipHttpErrorCheck `
                        -TimeoutSec 10 -MaximumRedirection 0 -Headers @{
                            'User-Agent'='pgextwin-original-get-anon-diagnostic/1'
                            'Accept'='application/vnd.github+json'
                        }
                    $remaining=[string]$probe.Headers['X-RateLimit-Remaining']
                    $limit=[string]$probe.Headers['X-RateLimit-Limit']
                    $reset=[string]$probe.Headers['X-RateLimit-Reset']
                    $retry=[string]$probe.Headers['Retry-After']
                    Write-Output "ANON_CATALOG_HTTP_DIAGNOSTIC ENDPOINT=$($endpoint.name) STATUS=$([int]$probe.StatusCode) RATE_REMAINING=$remaining RATE_LIMIT=$limit RATE_RESET=$reset RETRY_AFTER=$retry"
                } catch {
                    Write-Output "ANON_CATALOG_HTTP_DIAGNOSTIC ENDPOINT=$($endpoint.name) STATUS=UNAVAILABLE (DENY)"
                }
            }
            if ($PublicOnly -and $binary.kind -ceq 'public') {
                # Read-only anonymous diagnostics ONLY after the original
                # published CLI failed. Never use the job's GitHub token or
                # treat a successful diagnostic as GET authorization.
                foreach ($source in @('laurenz/oracle_fdw',
                                      'andreiramani/pgvector_pgsql_windows',
                                      'trickle-labs/pg-trickle')) {
                    try {
                        $url="https://api.github.com/repos/$source"
                        $probe=Invoke-WebRequest -Uri $url -Method Get -SkipHttpErrorCheck `
                            -TimeoutSec 10 -Headers @{'User-Agent'='pgextwin-public-e2e-diagnostic/1';'Accept'='application/vnd.github+json'}
                        $remaining=[string]$probe.Headers['X-RateLimit-Remaining']
                        $limit=[string]$probe.Headers['X-RateLimit-Limit']
                        Write-Output "ANON_GITHUB_METADATA_DIAGNOSTIC SOURCE=$source STATUS=$([int]$probe.StatusCode) RATE_REMAINING=$remaining RATE_LIMIT=$limit"
                    } catch {
                        Write-Output "ANON_GITHUB_METADATA_DIAGNOSTIC SOURCE=$source STATUS=UNAVAILABLE (DENY)"
                    }
                }
            }
            throw "Actual $($binary.kind) CLI provider GET failed"
        }
        $originals=@(Get-ChildItem -LiteralPath $dest -Recurse -File -Filter '*.zip')
        if ($originals.Count -ne $expected.Count) {
            throw "Original cohort completeness mismatch: expected=$($expected.Count) got=$($originals.Count)"
        }
        foreach ($pin in $expected) {
            $matches=@($originals | Where-Object {$_.Name -ceq $pin.name})
            if ($matches.Count -ne 1) { throw "Missing/duplicate exact ZIP $($pin.name)" }
            $original=$matches[0]
            $hash=(Get-FileHash -LiteralPath $original.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
            if ($original.Length -ne $pin.bytes -or $hash -cne $pin.sha) {
                throw "Original provider exact byte mismatch for $($pin.name)"
            }
            Write-Output "REAL_WINDOWS_ORIGINAL_PROVIDER_BYTE=PASS SOURCE=$Source CLI_KIND=$($binary.kind) FILE=$($pin.name) BYTES=$($original.Length) SHA256=$hash"
        }
        Write-Output "REAL_WINDOWS_ORIGINAL_GET_ONLY_E2E=PASS SOURCE=$Source CLI_KIND=$($binary.kind) ZIP_COUNT=$($expected.Count) PUBLISH=DENY MIRROR=DENY"
    } finally {
        Remove-Item -LiteralPath $dest -Recurse -Force -ErrorAction SilentlyContinue
        if (Test-Path -LiteralPath $dest) { throw 'Original-byte staging cleanup failed' }
    }
}
