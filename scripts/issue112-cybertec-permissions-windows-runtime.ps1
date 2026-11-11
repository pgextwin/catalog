# Private original Cybertec pg_permissions SQL E2E on disposable Windows PG14-18.
# No upload, signing, Publisher, mirror, Release or public GET admission.
param([ValidateSet(14,15,16,17,18)][int]$Major)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$PSNativeCommandUseErrorActionPreference=$false
if ($env:GITHUB_ACTIONS -cne 'true' -or $env:RUNNER_OS -cne 'Windows' -or -not $env:PGROOT -or -not $env:RUNNER_TEMP) { throw 'Ephemeral Windows GitHub Actions only' }
$root=[IO.Path]::GetFullPath($env:PGROOT)
$bin=Join-Path $root 'bin'
$pgconfig=Join-Path $bin 'pg_config.exe'; $psql=Join-Path $bin 'psql.exe'
$initdb=Join-Path $bin 'initdb.exe'; $pgctl=Join-Path $bin 'pg_ctl.exe'
foreach ($p in @($pgconfig,$psql,$initdb,$pgctl)) { if (-not (Test-Path -LiteralPath $p -PathType Leaf)) { throw 'Missing pinned PostgreSQL executable' } }
$installedPg=(& $pgconfig --version | Out-String).Trim()
if ($LASTEXITCODE -ne 0 -or $installedPg -notmatch "^PostgreSQL $Major([.]|\s)") { throw "Wrong PostgreSQL major $installedPg" }
$sharedir=(& $pgconfig --sharedir | Out-String).Trim()
if ($LASTEXITCODE -ne 0 -or -not ([IO.Path]::GetFullPath($sharedir)).StartsWith($root,[StringComparison]::OrdinalIgnoreCase)) { throw 'PostgreSQL share root mismatch' }
$dest=Join-Path $sharedir 'extension'
if (-not (Test-Path -LiteralPath $dest -PathType Container)) { throw 'Missing extension install directory' }
$upstream=Join-Path (Get-Location).Path 'pinned-upstream'
$stage=Join-Path $env:RUNNER_TEMP "issue112-permissions-$Major-original-stage"
if (-not (Test-Path -LiteralPath $upstream -PathType Container) -or (Test-Path -LiteralPath $stage)) { throw 'Invalid upstream or staging directory' }
$lines=@(& python scripts/issue112_cybertec_permissions_original.py --pg ([string]$Major) --source $upstream --stage $stage 2>&1)
if ($LASTEXITCODE -ne 0 -or $lines.Count -ne 2) { throw "Private original verifier failed: $($lines -join ' ')" }
$r=$lines[0] | ConvertFrom-Json
if ($null -eq $r -or $r.postgresqlMajor -cne ([string]$Major) -or
    $r.providerOriginalPackageLabel -cne 'REL_1_4' -or $r.sqlExtensionDefaultVersion -cne '1.4' -or
    $r.upstreamReleaseLatestObserved -cne '1.4.1' -or $r.zipCrc -cne 'PASS' -or
    -not $r.completeSourceSqlControlMatch -or @($r.sourceByteDiffers).Count -ne 0 -or
    @($r.sourceNotPresent).Count -ne 0 -or @($r.installableSqlAndControl).Count -ne 8 -or
    $r.status -cne 'CANDIDATE_ONLY' -or $r.publicGetAuthorized -or
    $r.mirrorAuthorized -or $r.publisherAuthorized -or $r.releaseAuthorized -or
    $r.independentlySignedAdmission -or $r.producerProvenanceVerified -or $r.rightsNoticeClosureVerified) {
  throw 'Original/source equality or denial gate failed'
}
Write-Host "PRIVATE_ORIGINAL_SHA256 PG=$Major SIZE=$($r.originalSizeBytes) SHA256=$($r.originalSha256) ZIP_MEMBERS=$($r.zipMemberCount) LICENSE_NOTICE=$(@($r.packagedLicenseNoticeMembers).Count) INSTALLABLE_SOURCE_MATCH=8/8"
$allow=@('pg_permissions.control', 'pg_permissions--1.0.sql', 'pg_permissions--1.0--1.1.sql',
         'pg_permissions--1.1.sql', 'pg_permissions--1.1--1.2.sql',
         'pg_permissions--1.2.sql', 'pg_permissions--1.3.sql', 'pg_permissions--1.3--1.4.sql')
$created=@()
try {
  foreach ($name in @($r.installableSqlAndControl)) {
    if ($allow -cnotcontains $name) { throw 'Unallowlisted member' }
    $from=Join-Path $stage $name; $target=Join-Path $dest $name
    if (-not (Test-Path -LiteralPath $from -PathType Leaf) -or (Test-Path -LiteralPath $target)) { throw 'Missing original-stage member or existing destination' }
    Copy-Item -LiteralPath $from -Destination $target -ErrorAction Stop
    $created += $target
  }
  $data=Join-Path $env:RUNNER_TEMP "issue112-permissions-$Major-data"
  $log=Join-Path $env:RUNNER_TEMP "issue112-permissions-$Major.log"
  $started=$false
  try {
    & $initdb -D $data -A trust -U postgres --no-instructions
    if ($LASTEXITCODE -ne 0) { throw 'initdb failed' }
    & $pgctl -D $data -l $log -o '-h 127.0.0.1 -p 55449' -w start
    if ($LASTEXITCODE -ne 0) { throw 'PostgreSQL start failed' }
    $started=$true
    $conn=@('-X','-A','-t','-v','ON_ERROR_STOP=1','-h','127.0.0.1','-p','55449','-U','postgres','-d','postgres')
    & $psql @conn -c 'CREATE EXTENSION pg_permissions SCHEMA public;'
    if ($LASTEXITCODE -ne 0) { throw 'CREATE EXTENSION failed' }
    $version=(& $psql @conn -c "SELECT extversion FROM pg_extension WHERE extname='pg_permissions';" | Out-String).Trim()
    if ($LASTEXITCODE -ne 0 -or $version -cne '1.4') { throw "SQL extension version mismatch: $version" }
    & $psql @conn -c 'CREATE ROLE audit_reader LOGIN; CREATE SCHEMA audit_schema; CREATE TABLE audit_schema.audit_items (id int); GRANT USAGE ON SCHEMA audit_schema TO audit_reader; GRANT SELECT ON audit_schema.audit_items TO audit_reader;'
    if ($LASTEXITCODE -ne 0) { throw 'Disposable permission fixture setup failed' }
    $view=(& $psql @conn -c "SELECT CASE WHEN EXISTS (SELECT 1 FROM public.table_permissions WHERE role_name='audit_reader' AND schema_name='audit_schema' AND object_name='audit_items' AND permission='SELECT' AND granted) THEN 'PASS' ELSE 'FAIL' END;" | Out-String).Trim()
    if ($LASTEXITCODE -ne 0 -or $view -cne 'PASS') { throw "Permission view functional assertion failed: $view" }
    & $psql @conn -c "INSERT INTO public.permission_target (role_name, permissions, object_type, schema_name, object_name) VALUES ('audit_reader', '{SELECT}', 'TABLE', 'audit_schema', 'audit_items');"
    if ($LASTEXITCODE -ne 0) { throw 'Permission target insert failed' }
    & $psql @conn -c "SELECT count(*) FROM public.permission_diffs() WHERE role_name='audit_reader';"
    if ($LASTEXITCODE -ne 0) { throw 'permission_diffs function invocation failed' }
    Write-Host "WINDOWS_EDB_PG$($Major)_FUNCTIONAL=PASS ORIGINAL_ZIP_SQL=YES SQL_EXTVERSION=1.4 PERMISSION_VIEW=YES TARGET=YES DIFF=YES"
  } catch {
    Write-Host "WINDOWS_EDB_PG$($Major)_FUNCTIONAL=FAIL DETAIL=$($_.Exception.Message)"
    if (Test-Path -LiteralPath $log) { Get-Content -LiteralPath $log -Tail 30 }
    throw
  } finally {
    if ($started) {
      & $pgctl -D $data -m immediate -w stop
      if ($LASTEXITCODE -ne 0) { Write-Warning 'Disposable PostgreSQL stop failed' }
    }
  }
} finally {
  foreach ($path in $created) { Remove-Item -LiteralPath $path -ErrorAction SilentlyContinue }
  if (Test-Path -LiteralPath $stage) { Remove-Item -LiteralPath $stage -Recurse -Force -ErrorAction SilentlyContinue }
}
Write-Host 'PUBLIC_GET=DENY MIRROR=DENY RELEASE=DENY PROVIDER_SIGNER=UNVERIFIED NOTICE_CLOSURE=UNVERIFIED'
