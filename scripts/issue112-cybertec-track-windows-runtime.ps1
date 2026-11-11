# Issue112 — real Windows PG14–18 SQL runtime; no ZIP upload, Publisher or Release.
param([ValidateSet(14,15,16,17,18)][int]$Major)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$PSNativeCommandUseErrorActionPreference=$false
if ($env:GITHUB_ACTIONS -cne 'true' -or $env:RUNNER_OS -cne 'Windows' -or -not $env:PGROOT -or -not $env:RUNNER_TEMP) { throw 'Ephemeral Windows Actions only' }
$root=[IO.Path]::GetFullPath($env:PGROOT)
$bin=Join-Path $root 'bin'
$pgconfig=Join-Path $bin 'pg_config.exe'; $psql=Join-Path $bin 'psql.exe'
$initdb=Join-Path $bin 'initdb.exe'; $pgctl=Join-Path $bin 'pg_ctl.exe'
foreach ($p in @($pgconfig,$psql,$initdb,$pgctl)) { if (-not (Test-Path -LiteralPath $p -PathType Leaf)) { throw 'Missing pinned PostgreSQL executable' } }
$installedPg=(& $pgconfig --version | Out-String).Trim()
if ($LASTEXITCODE -ne 0 -or $installedPg -notmatch "^PostgreSQL $Major([.]|\s)") { throw "Wrong PG major $installedPg" }
$sharedir=(& $pgconfig --sharedir | Out-String).Trim()
if ($LASTEXITCODE -ne 0 -or -not ([IO.Path]::GetFullPath($sharedir)).StartsWith($root,[StringComparison]::OrdinalIgnoreCase)) { throw 'PostgreSQL root mismatch' }
$dest=Join-Path $sharedir 'extension'
if (-not (Test-Path -LiteralPath $dest -PathType Container)) { throw 'Missing extension install directory' }
$pins=@{
  14='91455e4fee5e12f2ef2a715b9fb9a89693e2a5ad9fa83b877c6a186ab1937c93'
  15='26047b240181ab255fe22aff8db3863d89c20c4108306bf461699a9bdfcb887e'
  16='9ca7204721622f41a980e32ec2d2798209e94d3cb12c143c2bddd0b43c2c7303'
  17='913677afc2d590572422b4cccf452870248de054882b746803afcc76d3d09d49'
  18='a4a4b9d1aba1bad9bcd7cfbf326c49caf929d048dc4c9856c1a840c947d602dc'
}
$upstream=Join-Path (Get-Location).Path 'pinned-upstream'
if (-not (Test-Path -LiteralPath $upstream -PathType Container)) { throw 'Pinned upstream missing' }
$lines=@(& python scripts/issue112_cybertec_track_original.py --pg ([string]$Major) --source $upstream 2>&1)
if ($LASTEXITCODE -ne 0 -or $lines.Count -ne 2) { throw "Original verifier failed: $($lines -join ' ')" }
$r=$lines[0] | ConvertFrom-Json
if ($null -eq $r -or $r.postgresqlMajor -cne ([string]$Major) -or
    $r.originalSha256 -cne $pins[$Major] -or $r.originalSizeBytes -ne 29613 -or
    $r.zipCrc -cne 'PASS' -or $r.zipMemberCount -ne 18 -or
    -not $r.upstreamCompleteSqlControlMatch -or
    @($r.upstreamByteDiffers).Count -ne 0 -or @($r.upstreamNotPresent).Count -ne 0 -or
    @($r.installableSqlAndControl).Count -ne 13 -or
    $r.status -cne 'CANDIDATE_ONLY' -or $r.publicGetAuthorized -or
    $r.publisherAuthorized -or $r.mirrorAuthorized -or $r.releaseAuthorized) {
  throw 'Byte-pinned original/source/denial mismatch'
}
Write-Host "ORIGINAL=PASS PG=$Major SIZE=$($r.originalSizeBytes) SHA256=$($r.originalSha256) SQL_CONTROL_MATCH=13/13"
$created=@()
try {
  foreach ($name in @($r.installableSqlAndControl)) {
    if ($name -cne 'pg_track_settings.control' -and $name -cnotmatch '^pg_track_settings--[A-Za-z0-9._-]+[.]sql$') { throw 'Unallowlisted filename' }
    $from=Join-Path $upstream $name; $target=Join-Path $dest $name
    if (-not (Test-Path -LiteralPath $from -PathType Leaf) -or (Get-Item -LiteralPath $from).LinkType -or (Test-Path -LiteralPath $target)) { throw 'Unsafe installation target/source' }
    Copy-Item -LiteralPath $from -Destination $target -ErrorAction Stop
    $created += $target
  }
  $data=Join-Path $env:RUNNER_TEMP "issue112-track-$Major-data"
  $log=Join-Path $env:RUNNER_TEMP "issue112-track-$Major.log"
  $started=$false
  try {
    & $initdb -D $data -A trust -U postgres --no-instructions
    if ($LASTEXITCODE -ne 0) { throw 'initdb failed' }
    & $pgctl -D $data -l $log -o '-h 127.0.0.1 -p 55449' -w start
    if ($LASTEXITCODE -ne 0) { throw 'PostgreSQL start failed' }
    $started=$true
    $conn=@('-X','-A','-t','-v','ON_ERROR_STOP=1','-h','127.0.0.1','-p','55449','-U','postgres','-d','postgres')
    & $psql @conn -c 'CREATE EXTENSION pg_track_settings;'
    if ($LASTEXITCODE -ne 0) { throw 'CREATE EXTENSION failed' }
    $version=(& $psql @conn -c "SELECT extversion FROM pg_extension WHERE extname='pg_track_settings';" | Out-String).Trim()
    if ($LASTEXITCODE -ne 0 -or $version -cne '2.1.2') { throw "Installed version mismatch: $version" }
    $snapshot=(& $psql @conn -c "SELECT CASE WHEN pg_track_settings_snapshot() THEN 'PASS' ELSE 'FAIL' END;" | Out-String).Trim()
    if ($LASTEXITCODE -ne 0 -or $snapshot -cne 'PASS') { throw "Snapshot failed: $snapshot" }
    $history=(& $psql @conn -c "SELECT CASE WHEN count(*) > 0 THEN 'PASS' ELSE 'FAIL' END FROM pg_track_settings_history;" | Out-String).Trim()
    if ($LASTEXITCODE -ne 0 -or $history -cne 'PASS') { throw "History empty: $history" }
    & $psql @conn -c "SELECT count(*) FROM pg_track_settings_diff(now() - interval '1 hour', now());"
    if ($LASTEXITCODE -ne 0) { throw 'Settings diff failed' }
    & $psql @conn -c "SELECT count(*) FROM pg_track_db_role_settings(now());"
    if ($LASTEXITCODE -ne 0) { throw 'Role/database settings lookup failed' }
    Write-Host "WINDOWS_EDB_PG$($Major)_FUNCTIONAL=PASS CREATE=YES SNAPSHOT=YES HISTORY=YES DIFF=YES DB_ROLE=YES"
  } catch {
    Write-Host "WINDOWS_EDB_PG$($Major)_FUNCTIONAL=FAIL DETAIL=$($_.Exception.Message)"
    if (Test-Path -LiteralPath $log) { Get-Content -LiteralPath $log -Tail 30 }
    throw
  } finally {
    if ($started) {
      & $pgctl -D $data -m immediate -w stop
      if ($LASTEXITCODE -ne 0) { Write-Warning 'Disposable stop failed' }
    }
  }
} finally {
  foreach ($path in $created) { Remove-Item -LiteralPath $path -ErrorAction SilentlyContinue }
}
Write-Host 'ORIGINAL_ZIP_UPLOAD=NONE SOURCE_PROVENANCE=UNVERIFIED COMPLETE_NOTICE=UNVERIFIED SIGNED_ADMISSION=NONE PUBLIC_GET=DENY MIRROR=DENY RELEASE=DENY'
