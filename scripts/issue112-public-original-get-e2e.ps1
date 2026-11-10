# Issue #112: actual published and privately compiled CLI direct original GET E2E.
# Only invoked by workflow_run after authenticated original Catalog/main push Validate.
[CmdletBinding()]
param([Parameter(Mandatory=$true)][ValidateSet('qualified_cohort')][string]$Source)
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
    [long]$latest.issuerRunId -le 0 -or @($latest.records).Count -notin @(5,7,11)) {
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
    Write-Output 'Catalog latest admission Run is expired; provider GET skipped until fresh owner authorization'
    exit 0
}
$binaries=@(@{kind='private';path=(Join-Path $env:RUNNER_TEMP 'issue112-private-cli/pgextwin.exe')})
$public=Join-Path $env:RUNNER_TEMP 'issue112-public-cli/pgextwin.exe'
if (Test-Path -LiteralPath $public -PathType Leaf) {
    $binaries+=@{kind='public';path=$public}
} else {
    Write-Output 'PUBLIC_CLI_ORIGINAL_GET=SKIPPED_NO_FORMAL_CLI_RELEASE'
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
        if ($LASTEXITCODE -ne 0) { throw "Actual $($binary.kind) CLI provider GET failed" }
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
