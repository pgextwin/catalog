# Issue #112: actual published and privately compiled CLI direct original GET E2E.
# Only invoked by workflow_run after authenticated original Catalog/main push Validate.
[CmdletBinding()]
param([Parameter(Mandatory=$true)][ValidateSet('pg_trickle','hypopg','portalcorp_pgvector')][string]$Source)
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
$now=[DateTimeOffset]::UtcNow
$active=@(Get-ChildItem -LiteralPath $root -Directory | Where-Object {
    $doc=Get-Content -LiteralPath (Join-Path $_.FullName 'external-get-admission.json') -Raw | ConvertFrom-Json
    ([DateTimeOffset]::Parse($doc.issuedAt) -le $now) -and
    ($now -lt [DateTimeOffset]::Parse($doc.expiresAt))
})
if ($active.Count -ne 1) { throw "Exactly one live source-specific signed pin required; got $($active.Count)" }
$admission=Join-Path $active[0].FullName 'external-get-admission.json'
$bundle=Join-Path $active[0].FullName 'attestation.json'
$binaries=@(@{kind='private';path=(Join-Path $env:RUNNER_TEMP 'issue112-private-cli/pgextwin.exe')})
$public=Join-Path $env:RUNNER_TEMP 'issue112-public-cli/pgextwin.exe'
if (Test-Path -LiteralPath $public -PathType Leaf) {
    $binaries+=@{kind='public';path=$public}
} else {
    Write-Output 'PUBLIC_CLI_ORIGINAL_GET=SKIPPED_NO_FORMAL_CLI_RELEASE'
}
if ($Source -ceq 'pg_trickle') {
    $pgArg='18'
    $expected=@(@{
        name='pg_trickle-0.108.3-pg18-windows-amd64.zip';bytes=7029107
        sha='c2841dacee6fa1a09400c7e9a0f74159f2b7f36847a60ef10291d1beb06bd96b'
    })
} elseif ($Source -ceq 'portalcorp_pgvector') {
    $pgArg='16'
    $expected=@(@{
        name='pgvector-x86_64-pc-windows-msvc-pg16.zip';bytes=163732
        sha='a9c63a3e51c09c18f192277a28be3fb021f3872a7cc2d23e4ca06e10f2c99571'
    })
} else {
    $pgArg='all'
    $expected=@(
        @{name='hypopg-1.4.1-pg14-x64.zip';bytes=23115;sha='ac1114d1392494e688b5b6b6f151aebe6ccab2d8ae1a004ec510669c47ef3634'},
        @{name='hypopg-1.4.1-pg15-x64.zip';bytes=23123;sha='d23ea9ba7d064ee08e431b12ade50bed4b19a725b5f4df1e088e79e4af8d08ec'},
        @{name='hypopg-1.4.1-pg16-x64.zip';bytes=22997;sha='7afd7cda50050829787d4e901fc8292cf1eb2bc5ad59c996a92e414a1bead1f7'}
    )
}
Remove-Item Env:GH_TOKEN -ErrorAction SilentlyContinue
Remove-Item Env:GITHUB_TOKEN -ErrorAction SilentlyContinue
foreach ($binary in $binaries) {
    if (-not (Test-Path -LiteralPath $binary.path -PathType Leaf)) { throw 'CLI EXE missing' }
    $dest=Join-Path $env:RUNNER_TEMP "issue112-user-local-$($binary.kind)"
    New-Item -ItemType Directory -Path $dest -ErrorAction Stop | Out-Null
    try {
        & $($binary.path) download-all --source external --pg $pgArg --output $dest --external-admission $admission --external-bundle $bundle
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
