# Issue #112: private-built CLI direct original GET byte proof; no public GET proof.
# Only invoked by workflow_run after authenticated original Catalog/main push Validate.
[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$PSNativeCommandUseErrorActionPreference=$false
if ($env:GITHUB_ACTIONS -cne 'true' -or
    $env:GITHUB_REPOSITORY -cne 'pgextwin/catalog' -or
    $env:GITHUB_EVENT_NAME -cne 'workflow_run' -or
    $env:RUNNER_OS -cne 'Windows' -or -not $env:GITHUB_WORKSPACE -or
    -not $env:RUNNER_TEMP) { throw 'Not a genuine disposable Catalog Windows workflow_run' }
# Expectations are fixed from this authenticated checkout BEFORE the CLI reads main.
# Never refresh them from mutable main to accommodate a changed or incomplete result.
$manifestPath=Join-Path $env:GITHUB_WORKSPACE 'external/direct-get.json'
if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) { throw 'Direct manifest absent' }
$manifest=Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
if ($manifest.schemaVersion -cne 'pgextwin-external-direct-get/v1' -or
    $manifest.records -isnot [array] -or $manifest.records.Count -lt 1) {
    throw 'Direct manifest schema/records invalid'
}
$identities=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
$selectedNames=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
$expected=@(foreach ($row in $manifest.records) {
    # SelectDirect validates every row, including non-latest historical versions.
    foreach ($field in @('extension','pgMajor','upstreamVersion','license','assetName','originalSha256')) {
        if ($row.$field -isnot [string] -or [string]::IsNullOrWhiteSpace($row.$field)) {
            throw "Missing exact-version direct record field: $field"
        }
    }
    if ($row.licenseEvidence -isnot [array] -or $row.licenseEvidence.Count -lt 1 -or
        $row.latest -isnot [bool] -or $row.pgMajor -cnotin @('15','16','17','18')) {
        throw 'Direct record license evidence/latest/PG15-18 scope invalid'
    }
    $identity=$row.extension + ':' + $row.pgMajor + ':' + $row.upstreamVersion
    if (-not $identities.Add($identity)) { throw "Duplicate direct identity: $identity" }
    if (($row.originalBytes -isnot [long] -and $row.originalBytes -isnot [int]) -or
        $row.originalBytes -lt 4 -or $row.originalBytes -gt 67108864 -or $row.originalSha256 -cnotmatch '^[0-9a-f]{64}$' -or
        $row.assetName -cnotmatch '^[A-Za-z0-9][A-Za-z0-9._+-]*\.(?i:zip)$') {
        throw 'Invalid direct original filename/byte pins'
    }
    # --pg all, no extension/version: only latest:true across all supported majors.
    if ($row.latest -eq $true) {
        if (-not $selectedNames.Add($row.assetName)) { throw 'Duplicate selected ZIP filename' }
        @{name=[string]$row.assetName;bytes=[long]$row.originalBytes;sha=[string]$row.originalSha256}
    }
})
if ($expected.Count -lt 1 -or $expected.Count -gt 1000) { throw 'Direct selected batch bound is 1-1000' }
$private=Join-Path $env:RUNNER_TEMP 'issue112-private-cli/pgextwin.exe'
if (-not (Test-Path -LiteralPath $private -PathType Leaf)) { throw 'Mandatory private-built CLI EXE missing' }
Remove-Item Env:GH_TOKEN -ErrorAction SilentlyContinue
Remove-Item Env:GITHUB_TOKEN -ErrorAction SilentlyContinue
$dest=Join-Path $env:RUNNER_TEMP 'issue112-user-local-private'
New-Item -ItemType Directory -Path $dest -ErrorAction Stop | Out-Null
try {
    & $private download-all --source external --pg all --output $dest
    $cliExit=$LASTEXITCODE
    if ($cliExit -ne 0) {
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
        throw "Actual private CLI provider GET failed (exit=$cliExit)"
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
        Write-Output "REAL_WINDOWS_ORIGINAL_PROVIDER_BYTE=PASS SOURCE=external/direct-get.json CLI_KIND=private FILE=$($pin.name) BYTES=$($original.Length) SHA256=$hash"
    }
} finally {
    try {
        if (Test-Path -LiteralPath $dest) {
            Remove-Item -LiteralPath $dest -Recurse -Force -ErrorAction Stop
        }
        if (Test-Path -LiteralPath $dest) {
            throw 'Destination path still exists after Remove-Item'
        }
    } catch {
        $cleanupError=if ($_.Exception) { ($_.Exception.Message -replace '[\r\n]+', ' ').Trim() } else { ([string]$_ -replace '[\r\n]+', ' ').Trim() }
        throw "Staging cleanup failed for private direct proof: $cleanupError"
    }
}
Write-Output "PRIVATE_DIRECT_PATH_ORIGINAL_GET_E2E=PASS SOURCE=external/direct-get.json CLI_KIND=private ZIP_COUNT=$($expected.Count) PUBLISH=DENY MIRROR=DENY"
