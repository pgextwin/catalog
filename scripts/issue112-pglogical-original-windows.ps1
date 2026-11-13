# Issue #112 pglogical 2.4.8 provider original: private Windows runtime probe.
# Source bytes and ZIP members were independently validated by the Python step.
# No admission, artifact upload, signing, mirror or release is authorized.
[CmdletBinding()]
param([Parameter(Mandatory=$true)][ValidateSet(14,15,16,17,18)][int]$Major)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false

if ($env:GITHUB_ACTIONS -cne 'true' -or $env:GITHUB_REPOSITORY -cne 'pgextwin/catalog' -or
    $env:RUNNER_OS -cne 'Windows' -or -not $env:RUNNER_TEMP -or -not $env:PGROOT) {
    throw 'Private candidate runtime may only run on ephemeral GitHub Windows'
}
$root = [IO.Path]::GetFullPath($env:PGROOT)
$stage = Join-Path $env:RUNNER_TEMP "issue112-pglogical-pg$Major-stage"
$pgConfig = Join-Path $root 'bin/pg_config.exe'
if (-not (Test-Path -LiteralPath $pgConfig) -or -not (Test-Path -LiteralPath $stage)) {
    throw 'Pinned PostgreSQL root or independently verified stage is missing'
}
$ver = (& $pgConfig --version | Out-String).Trim()
if ($LASTEXITCODE -ne 0 -or $ver -notmatch "^PostgreSQL $Major(?:[.]|\s)") {
    throw "PostgreSQL ABI major differs from PG$($Major): $ver"
}
# Copy only the allowlisted files already validated against exact original ZIP.
$members = @(Get-ChildItem -LiteralPath $stage -Recurse -File)
if ($members.Count -lt 5 -or $members.Count -gt 100) { throw 'Unexpected staged member count' }
foreach ($member in $members) {
    $relative = [IO.Path]::GetRelativePath($stage, $member.FullName).Replace('\', '/')
    if ($relative -cnotmatch '^(lib/(pglogical|pglogical_output)\.dll|bin/pglogical_create_subscriber\.exe|share/extension/pglogical(_origin)?\.control|share/extension/pglogical(_origin)?--[A-Za-z0-9_.-]+\.sql)$') {
        throw "Unrecognized staged member: $relative"
    }
    $dest = Join-Path $root ($relative.Replace('/', [IO.Path]::DirectorySeparatorChar))
    if (Test-Path -LiteralPath $dest) { throw "No overwrite allowed: $relative" }
    Copy-Item -LiteralPath $member.FullName -Destination $dest
}

$data = Join-Path $env:RUNNER_TEMP "issue112-pglogical-pg$Major-data"
$log = Join-Path $env:RUNNER_TEMP "issue112-pglogical-pg$Major.log"
$bin = Join-Path $root 'bin'
$initdb = Join-Path $bin 'initdb.exe'
$ctl = Join-Path $bin 'pg_ctl.exe'
$psql = Join-Path $bin 'psql.exe'
$port = 55452
$started = $false
try {
    & $initdb -D $data -A trust -U postgres --no-instructions
    if ($LASTEXITCODE -ne 0) { throw 'initdb failed' }
    $config = Join-Path $data 'postgresql.conf'
    Add-Content -LiteralPath $config -Value @(
        "shared_preload_libraries = 'pglogical'"
        "wal_level = logical"
        "max_replication_slots = 10"
        "max_wal_senders = 10"
        "max_worker_processes = 16"
        "output_plugin_libraries = 'pgoutput, test_decoding, pglogical_output'"
    )
    & $ctl -D $data -l $log -o "-h 127.0.0.1 -p $port" -w start
    if ($LASTEXITCODE -ne 0) { throw 'PostgreSQL preload or Windows DLL loader failed' }
    $started = $true
    $common = @('-X', '-A', '-t', '-v', 'ON_ERROR_STOP=1',
                '-h', '127.0.0.1', '-p', [string]$port,
                '-U', 'postgres', '-d', 'postgres')
    & $psql @common -c 'CREATE EXTENSION pglogical;'
    if ($LASTEXITCODE -ne 0) { throw 'CREATE EXTENSION pglogical failed' }
    $version = (& $psql @common -c "SELECT extversion FROM pg_extension WHERE extname='pglogical';" | Out-String).Trim()
    if ($LASTEXITCODE -ne 0 -or $version -cne '2.4.8') {
        throw "Invalid pglogical native runtime version: $version"
    }
    $slot = (& $psql @common -c "SELECT slot_name FROM pg_create_logical_replication_slot('pgextwin_pglogical_probe','pglogical_output');" | Out-String).Trim()
    if ($LASTEXITCODE -ne 0 -or $slot -cne 'pgextwin_pglogical_probe') {
        throw "pglogical_output decoding slot failed: $slot"
    }
    & $psql @common -c "SELECT pg_drop_replication_slot('pgextwin_pglogical_probe');"
    if ($LASTEXITCODE -ne 0) { throw 'Logical replication slot cleanup failed' }
    Write-Host "PGLOGICAL_NATIVE_WINDOWS=PASS PG=$Major EXTENSION=2.4.8 OUTPUT_PLUGIN=PASS"
} finally {
    if ($started) {
        & $ctl -D $data -m immediate -w stop
        if ($LASTEXITCODE -ne 0) { Write-Warning 'Temporary PostgreSQL stop failed' }
    }
}
Write-Host "CANDIDATE_ONLY=YES REPLICATION_E2E=UNVERIFIED RIGHTS=UNVERIFIED SIGSTORE=UNVERIFIED GET=DENY MIRROR=DENY RELEASE=DENY"
