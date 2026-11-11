# PR-only: test pgextwin-owned pinned-source candidate; never Cybertec originals.
param([ValidateSet(14,15,16,17,18)][int]$Major)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false
if ($env:GITHUB_ACTIONS -cne 'true' -or $env:RUNNER_OS -cne 'Windows' -or
    -not $env:PGROOT -or -not $env:RUNNER_TEMP) { throw 'Ephemeral Windows Actions only' }
$root = [IO.Path]::GetFullPath($env:PGROOT)
$bin = Join-Path $root 'bin'
$pgconfig = Join-Path $bin 'pg_config.exe'
$initdb = Join-Path $bin 'initdb.exe'
$pgctl = Join-Path $bin 'pg_ctl.exe'
$psql = Join-Path $bin 'psql.exe'
foreach ($cmd in @($pgconfig,$initdb,$pgctl,$psql)) {
  if (-not (Test-Path -LiteralPath $cmd -PathType Leaf)) { throw 'Missing PostgreSQL binary' }
}
$pgVersion = (& $pgconfig --version | Out-String).Trim()
if ($LASTEXITCODE -ne 0 -or $pgVersion -notmatch "^PostgreSQL $Major([.]|\s)") { throw "Wrong PG version $pgVersion" }
$sharedir = (& $pgconfig --sharedir | Out-String).Trim()
if ($LASTEXITCODE -ne 0 -or -not ([IO.Path]::GetFullPath($sharedir)).StartsWith($root,[StringComparison]::OrdinalIgnoreCase)) { throw 'PG share path escaped root' }
$dest = Join-Path $sharedir 'extension'
if (-not (Test-Path -LiteralPath $dest -PathType Container)) { throw 'Missing extension directory' }
$source = Join-Path (Get-Location).Path 'pinned-upstream'
$zip = Join-Path $env:RUNNER_TEMP "track-source-pg$Major.zip"
if (Test-Path -LiteralPath $zip) { throw 'Create-only candidate already exists' }
$reply = @(& python scripts/issue112_track_owned_source_pilot.py --source $source --pg "$Major" --output $zip 2>&1)
if ($LASTEXITCODE -ne 0 -or $reply.Count -ne 1) { throw "Source-owned builder rejected: $($reply -join ' ')" }
$build = $reply[0] | ConvertFrom-Json
if ($build.status -cne 'CANDIDATE_ONLY' -or $build.postgresqlMajor -cne "$Major" -or
    $build.members -ne 15 -or $build.publicGet -cne 'DENY' -or
    $build.mirror -cne 'DENY' -or $build.release -cne 'DENY') { throw 'Build receipt invalid' }
$actual = (Get-FileHash -LiteralPath $zip -Algorithm SHA256).Hash.ToLowerInvariant()
if ($actual -cne $build.sha256) { throw 'Independent Windows SHA256 mismatch' }
$unpack = Join-Path $env:RUNNER_TEMP "track-source-pg$Major-extract"
if (Test-Path -LiteralPath $unpack) { throw 'Private extraction collision' }
Expand-Archive -LiteralPath $zip -DestinationPath $unpack -ErrorAction Stop
$receipt = Get-Content -LiteralPath (Join-Path $unpack 'SOURCE-INPUTS.json') -Raw | ConvertFrom-Json
$license = Join-Path $unpack 'LICENSE'
if ($receipt.postgresqlMajor -cne "$Major" -or
    $receipt.kind -cne 'PGEXTWIN_OWNED_SOURCE_ONLY_PRIVATE_PILOT_NOT_CYBERTEC_ORIGINAL' -or
    $receipt.upstreamCommit -cne '36a23f3c6d684c40140da1a24b1c3ee0e707b77a' -or
    $receipt.rightsNoticeIncluded -cne $true -or
    $receipt.cybertecProducerAttestation -cne $false -or
    $receipt.independentSignatureVerified -cne $false -or
    $receipt.downloadAuthorized -cne $false -or $receipt.releaseAuthorized -cne $false -or
    $receipt.publisherAuthorized -cne $false -or
    -not (Test-Path -LiteralPath $license -PathType Leaf)) { throw 'Source/rights/denial receipt invalid' }
if ((Get-FileHash -LiteralPath $license -Algorithm SHA256).Hash -cne
    (Get-FileHash -LiteralPath (Join-Path $source 'LICENSE') -Algorithm SHA256).Hash) {
  throw 'Embedded original LICENSE bytes differ'
}
$created = @()
try {
  $members = @(Get-ChildItem -LiteralPath (Join-Path $unpack 'share/extension') -File)
  if ($members.Count -ne 13) { throw 'Unexpected number of source members' }
  foreach ($item in $members) {
    if ($item.Name -cne 'pg_track_settings.control' -and
        $item.Name -cnotmatch '^pg_track_settings--[0-9.]+(--[0-9.]+)?[.]sql$') { throw 'Unexpected SQL file name' }
    $original = Join-Path $source $item.Name
    $target = Join-Path $dest $item.Name
    if (-not (Test-Path -LiteralPath $original -PathType Leaf) -or (Test-Path -LiteralPath $target)) { throw 'Invalid source or install target' }
    if ((Get-FileHash -LiteralPath $original -Algorithm SHA256).Hash -cne
        (Get-FileHash -LiteralPath $item.FullName -Algorithm SHA256).Hash) { throw 'SQL input not exact' }
    Copy-Item -LiteralPath $item.FullName -Destination $target -ErrorAction Stop
    $created += $target
  }
  $data = Join-Path $env:RUNNER_TEMP "track-source-pg$Major-data"
  $log = Join-Path $env:RUNNER_TEMP "track-source-pg$Major.log"
  $started = $false
  try {
    & $initdb -D $data -A trust -U postgres --no-instructions
    if ($LASTEXITCODE -ne 0) { throw 'initdb failed' }
    & $pgctl -D $data -l $log -o '-h 127.0.0.1 -p 55459' -w start
    if ($LASTEXITCODE -ne 0) { throw 'PostgreSQL start failed' }
    $started = $true
    $conn = @('-X','-A','-t','-v','ON_ERROR_STOP=1','-h','127.0.0.1','-p','55459','-U','postgres','-d','postgres')
    & $psql @conn -c 'CREATE EXTENSION pg_track_settings;'
    if ($LASTEXITCODE -ne 0) { throw 'CREATE EXTENSION failed' }
    $version = (& $psql @conn -c "SELECT extversion FROM pg_extension WHERE extname='pg_track_settings';" | Out-String).Trim()
    if ($LASTEXITCODE -ne 0 -or $version -cne '2.1.2') { throw 'Extension version mismatch' }
    $snap = (& $psql @conn -c "SELECT CASE WHEN pg_track_settings_snapshot() THEN 'PASS' ELSE 'FAIL' END;" | Out-String).Trim()
    if ($LASTEXITCODE -ne 0 -or $snap -cne 'PASS') { throw 'Snapshot failed' }
    $history = (& $psql @conn -c "SELECT CASE WHEN count(*) > 0 THEN 'PASS' ELSE 'FAIL' END FROM pg_track_settings_history;" | Out-String).Trim()
    if ($LASTEXITCODE -ne 0 -or $history -cne 'PASS') { throw 'History failed' }
    & $psql @conn -c "SELECT count(*) FROM pg_track_settings_diff(now() - interval '1 hour', now());"
    if ($LASTEXITCODE -ne 0) { throw 'Settings diff failed' }
    & $psql @conn -c "SELECT count(*) FROM pg_track_db_role_settings(now());"
    if ($LASTEXITCODE -ne 0) { throw 'Role/database settings failed' }
    Write-Host "OWNED_SOURCE_WINDOWS=PASS PG=$Major SQL=13/13 LICENSE=EMBEDDED SHA256=$actual SIGNED=NO PUBLIC_GET=DENY"
  } finally {
    if ($started) { & $pgctl -D $data -m immediate -w stop }
  }
} finally {
  foreach ($p in $created) { Remove-Item -LiteralPath $p -ErrorAction SilentlyContinue }
}
Write-Host 'SOURCE_PILOT_ONLY=YES CYBERTEC_ORIGINAL=NO SIGNER=NONE PUBLISHER=NONE RELEASE=DENY'
