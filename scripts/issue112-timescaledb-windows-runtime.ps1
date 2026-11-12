# Issue #112: exact TimescaleDB 2.31.0 / 2.32.0 PG16-18 Windows SQL test.
# Disposable, nonpublishing, no output ZIP, never grants public download rights.
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][ValidateSet(16,17,18)][int]$Major,
    [ValidateSet('2.31.0','2.32.0')][string]$ReleaseVersion = '2.31.0'
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false

if ($env:GITHUB_ACTIONS -cne 'true' -or $env:GITHUB_REPOSITORY -cne 'pgextwin/catalog' -or
    $env:RUNNER_OS -cne 'Windows' -or -not $env:RUNNER_TEMP -or -not $env:PGROOT) {
    throw 'DENY: ephemeral pgextwin/catalog Windows CI and PGROOT are required'
}
$pg = [string]$Major
$root = [IO.Path]::GetFullPath($env:PGROOT).TrimEnd('\')
$bin = Join-Path $root 'bin'
$pgConfig = Join-Path $bin 'pg_config.exe'
if (-not (Test-Path -LiteralPath $pgConfig -PathType Leaf)) {
    throw 'PostgreSQL pg_config.exe missing'
}
$installed = (& $pgConfig --version | Out-String).Trim()
if ($LASTEXITCODE -ne 0 -or $installed -notmatch ('^PostgreSQL\s+' + $pg + '(?:\.|\s)')) {
    throw "Wrong PostgreSQL host: $installed"
}
$verSuffix = $ReleaseVersion.Replace('.', '-')
$staged = Join-Path $env:RUNNER_TEMP "issue112-timescale-$verSuffix-pg$pg-original"
& python scripts/issue112_timescaledb_windows_runtime_stage.py --pg $pg --version $ReleaseVersion --stage $staged
if ($LASTEXITCODE -ne 0) { throw 'Original bytes / ZIP staging failed' }
$setup = Join-Path $staged 'timescaledb\setup.exe'
if (-not (Test-Path -LiteralPath $setup -PathType Leaf)) { throw 'Validated setup.exe missing' }
# Match the tested official upstream Windows package installer (pinned version).
# No administrative persistence: ephemeral Windows runner, separate disposable DB.
# The official upstream test changes directory into the package root before
# launching setup.exe: its payload discovery uses paths relative to the CWD.
Push-Location -LiteralPath (Split-Path -Parent $setup)
try {
    & .\setup.exe -yes-tune -pgconfig $pgConfig
    if ($LASTEXITCODE -ne 0) { throw "Original TimescaleDB setup.exe failed ($LASTEXITCODE)" }
} finally {
    Pop-Location
}
$control = Join-Path $root 'share\extension\timescaledb.control'
if (-not (Test-Path -LiteralPath $control -PathType Leaf)) {
    throw 'TimescaleDB control file was not installed'
}

$initdb = Join-Path $bin 'initdb.exe'
$ctl = Join-Path $bin 'pg_ctl.exe'
$psql = Join-Path $bin 'psql.exe'
$data = Join-Path $env:RUNNER_TEMP "issue112-ts-pg$pg-data"
$log = Join-Path $env:RUNNER_TEMP "issue112-ts-pg$pg.log"
$started = $false
try {
    & $initdb -D $data -A trust -U postgres --no-instructions
    if ($LASTEXITCODE -ne 0) { throw 'Disposable initdb failed' }
    & $ctl -D $data -l $log -o '-h 127.0.0.1 -p 55461 -c shared_preload_libraries=timescaledb' -w start
    if ($LASTEXITCODE -ne 0) { throw 'PostgreSQL with TimescaleDB shared preload failed' }
    $started = $true
    $common = @('-X','-A','-t','-v','ON_ERROR_STOP=1','-h','127.0.0.1',
                '-p','55461','-U','postgres','-d','postgres')
    & $psql @common -c 'CREATE EXTENSION timescaledb;'
    if ($LASTEXITCODE -ne 0) { throw 'TimescaleDB CREATE EXTENSION failed' }
    $version = (& $psql @common -c "SELECT extversion FROM pg_extension WHERE extname='timescaledb';" | Out-String).Trim()
    if ($LASTEXITCODE -ne 0 -or $version -cne $ReleaseVersion) {
        throw "Unexpected installed TimescaleDB version: $version"
    }
    & $psql @common -c "CREATE TABLE issue112_ts_probe(ts timestamptz NOT NULL, value integer NOT NULL); SELECT create_hypertable('issue112_ts_probe', by_range('ts')); INSERT INTO issue112_ts_probe VALUES ('2026-01-01T00:00:00Z',1),('2026-01-02T00:00:00Z',2);"
    if ($LASTEXITCODE -ne 0) { throw 'TimescaleDB hypertable creation/insert failed' }
    $total = (& $psql @common -c 'SELECT SUM(value) FROM issue112_ts_probe;' | Out-String).Trim()
    if ($LASTEXITCODE -ne 0 -or $total -cne '3') {
        throw "TimescaleDB hypertable SQL failed: $total"
    }
    Write-Host "TIMESCALEDB_WINDOWS_REAL_SQL=PASS PG=$pg VERSION=$version PRELOAD=PASS HYPERTABLE=PASS QUERY=PASS"
} catch {
    Write-Host "TIMESCALEDB_WINDOWS_REAL_SQL=FAIL PG=$pg DETAIL=$($_.Exception.Message)"
    if (Test-Path -LiteralPath $log) { Get-Content -LiteralPath $log -Tail 80 | ForEach-Object { Write-Host $_ } }
    throw
} finally {
    if ($started) {
        & $ctl -D $data -m immediate -w stop
        if ($LASTEXITCODE -ne 0) { Write-Warning 'Disposable PostgreSQL shutdown failed' }
    }
    Remove-Item -LiteralPath $staged -Recurse -Force -ErrorAction SilentlyContinue
}
Write-Host 'RUNTIME_AUDIT_ONLY=YES RIGHTS=UNVERIFIED PRODUCER_ATTESTATION=UNVERIFIED SIGNED_ADMISSION=DENY PUBLIC_GET=DENY MIRROR=DENY RELEASE=DENY PUBLISH=DENY'
