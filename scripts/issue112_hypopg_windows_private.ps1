# Issue #112: nonpublishing, disposable Windows PG original-HypoPG trial.
[CmdletBinding()]
param([Parameter(Mandatory=$true)][ValidateSet(14,15,16)][int]$Major)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$PSNativeCommandUseErrorActionPreference=$false
if ($env:GITHUB_ACTIONS -cne 'true' -or $env:GITHUB_REPOSITORY -cne 'pgextwin/catalog' -or
    $env:RUNNER_OS -cne 'Windows' -or -not $env:RUNNER_TEMP -or -not $env:PGROOT) {
    throw 'Only exact disposable GitHub Windows CI environment is supported'
}
$pg=[string]$Major
$pins=@{
    '14'=@{ assetId=164673161; bytes=23115 }
    '15'=@{ assetId=164673166; bytes=23123 }
    '16'=@{ assetId=164673171; bytes=22997 }
}
$pin=$pins[$pg]
$provider=gh api --method GET repos/HypoPG/hypopg | ConvertFrom-Json
if ($LASTEXITCODE -ne 0 -or $provider.id -ne 37308208 -or $provider.full_name -cne 'HypoPG/hypopg') {
    throw 'Unexpected original provider identity'
}
$release=gh api --method GET repos/HypoPG/hypopg/releases/tags/1.4.1 | ConvertFrom-Json
if ($LASTEXITCODE -ne 0 -or $release.id -ne 153113229 -or $release.tag_name -cne '1.4.1' -or
    $release.draft -ne $false -or $release.prerelease -ne $false) {
    throw 'Unexpected original Release identity/state'
}
$filename="hypopg-1.4.1-pg$pg-x64.zip"
$url="https://github.com/HypoPG/hypopg/releases/download/1.4.1/$filename"
$assets=@($release.assets | Where-Object { $_.name -ceq $filename })
if ($assets.Count -ne 1 -or $assets[0].id -ne $pin.assetId -or
    $assets[0].size -ne $pin.bytes -or $assets[0].state -cne 'uploaded' -or
    $assets[0].browser_download_url -cne $url) {
    throw 'Original asset ID/name/size/url mismatch'
}
$original=Join-Path $env:RUNNER_TEMP $filename
try {
    Invoke-WebRequest -Uri $url -OutFile $original -MaximumRedirection 3 -TimeoutSec 90
    if (-not (Test-Path -LiteralPath $original -PathType Leaf)) { throw 'Original provider ZIP absent' }
    if ((Get-Item -LiteralPath $original).Length -ne $pin.bytes) { throw 'Original provider bytes size mismatch' }
    $sha=(Get-FileHash -LiteralPath $original -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($assets[0].digest -and $assets[0].digest -cne "sha256:$sha") {
        throw 'Original GitHub API digest differs from privately hashed ZIP'
    }
    python scripts/issue112_hypopg_original_private.py --pg $pg --zip $original --pgroot $env:PGROOT
    if ($LASTEXITCODE -ne 0) { throw 'ZIP CRC/PE/allowlisted staging rejected' }
    Write-Output "HYPOPG_ORIGINAL_BYTES_PRIVATE=PASS PG=$pg ASSET=$($pin.assetId) SIZE=$($pin.bytes) SHA256=$sha"
} finally {
    Remove-Item -LiteralPath $original -Force -ErrorAction SilentlyContinue
    Remove-Item Env:GH_TOKEN -ErrorAction SilentlyContinue
}
$bin=Join-Path $env:PGROOT 'bin'
$initdb=Join-Path $bin 'initdb.exe'
$ctl=Join-Path $bin 'pg_ctl.exe'
$psql=Join-Path $bin 'psql.exe'
$datadir=Join-Path $env:RUNNER_TEMP "issue112-hypopg-pg$pg"
$log=Join-Path $env:RUNNER_TEMP "issue112-hypopg-pg$pg.log"
$started=$false
try {
    & $initdb -D $datadir -A trust -U postgres --no-instructions
    if ($LASTEXITCODE -ne 0) { throw 'Disposable PostgreSQL initdb failed' }
    & $ctl -D $datadir -l $log -o '-h 127.0.0.1 -p 55443' -w start
    if ($LASTEXITCODE -ne 0) { throw 'Disposable PostgreSQL start failed' }
    $started=$true
    $common=@('-X','-A','-t','-v','ON_ERROR_STOP=1','-h','127.0.0.1','-p','55443','-U','postgres','-d','postgres')
    & $psql @common -c 'CREATE EXTENSION hypopg;'
    if ($LASTEXITCODE -ne 0) { throw 'Original DLL CREATE EXTENSION hypopg failed' }
    $version=(& $psql @common -c "SELECT extversion FROM pg_extension WHERE extname='hypopg';" | Out-String).Trim()
    if ($LASTEXITCODE -ne 0 -or $version -cne '1.4.1') { throw "HypoPG original version mismatch: $version" }
    & $psql @common -c 'CREATE TABLE issue112_hypopg_probe (id integer); INSERT INTO issue112_hypopg_probe VALUES (1),(2);'
    if ($LASTEXITCODE -ne 0) { throw 'Disposable data probe creation failed' }
    $count=(& $psql @common -c "SELECT count(*) FROM hypopg_create_index('CREATE INDEX ON issue112_hypopg_probe (id)');" | Out-String).Trim()
    if ($LASTEXITCODE -ne 0 -or $count -cne '1') { throw "hypopg_create_index failed: $count" }
    & $psql @common -c 'SELECT hypopg_reset();'
    if ($LASTEXITCODE -ne 0) { throw 'hypopg_reset failed' }
    Write-Output "HYPOPG_ORIGINAL_PG_WINDOWS_SQL=PASS PG=$pg VERSION=1.4.1 FUNCTIONAL=PASS"
    Write-Output 'CANDIDATE_ONLY=YES SIGNED_ADMISSION=NONE GET_PUBLICATION=DENY MIRROR=DENY'
} finally {
    if ($started) {
        & $ctl -D $datadir -m immediate -w stop
        if ($LASTEXITCODE -ne 0) { Write-Warning 'Disposable test server shutdown failed' }
    }
}
