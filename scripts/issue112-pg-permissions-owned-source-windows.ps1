# Issue #112: PR-only Windows SQL E2E from exact pgextwin-owned pg_permissions ZIP.
# Do not use or attribute Cybertec provider originals, and NEVER publish.
param([ValidateSet(14,15,16,17,18)][int]$Major)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false
if ($env:GITHUB_ACTIONS -cne 'true' -or $env:RUNNER_OS -cne 'Windows' -or
    -not $env:PGROOT -or -not $env:RUNNER_TEMP) { throw 'Disposable Windows GitHub Actions only' }
$root = [IO.Path]::GetFullPath($env:PGROOT).TrimEnd('\')
$bin = Join-Path $root 'bin'
$pgconfig = Join-Path $bin 'pg_config.exe'
$initdb = Join-Path $bin 'initdb.exe'
$pgctl = Join-Path $bin 'pg_ctl.exe'
$psql = Join-Path $bin 'psql.exe'
foreach ($cmd in @($pgconfig, $initdb, $pgctl, $psql)) {
  if (-not (Test-Path -LiteralPath $cmd -PathType Leaf)) { throw 'Missing PostgreSQL binary' }
}
$version = (& $pgconfig --version | Out-String).Trim()
if ($LASTEXITCODE -ne 0 -or $version -notmatch "^PostgreSQL $Major([.]|\s)") { throw "Wrong PostgreSQL major $version" }
$sharedir = (& $pgconfig --sharedir | Out-String).Trim()
if ($LASTEXITCODE -ne 0) { throw 'pg_config --sharedir failed' }
$sharePath = [IO.Path]::GetFullPath($sharedir)
if (-not $sharePath.StartsWith($root + '\', [StringComparison]::OrdinalIgnoreCase)) {
  throw 'PostgreSQL share path outside installed PG root'
}
$dest = Join-Path $sharePath 'extension'
if (-not (Test-Path -LiteralPath $dest -PathType Container)) { throw 'Missing PostgreSQL share/extension' }

$upstream = Join-Path (Get-Location).Path 'pinned-pg-permissions'
$zip = Join-Path $env:RUNNER_TEMP "permissions-source-pg$Major-private.zip"
$stage = Join-Path $env:RUNNER_TEMP "permissions-source-pg$Major-private-extract"
$data = Join-Path $env:RUNNER_TEMP "permissions-source-pg$Major-data"
$log = Join-Path $env:RUNNER_TEMP "permissions-source-pg$Major.log"
if (-not (Test-Path -LiteralPath $upstream -PathType Container) -or
    (Test-Path -LiteralPath $zip) -or (Test-Path -LiteralPath $stage) -or
    (Test-Path -LiteralPath $data)) { throw 'Missing exact source or staging collision' }

$allow = @('pg_permissions.control', 'pg_permissions--1.0.sql',
           'pg_permissions--1.0--1.1.sql', 'pg_permissions--1.1.sql',
           'pg_permissions--1.1--1.2.sql', 'pg_permissions--1.2.sql',
           'pg_permissions--1.3.sql', 'pg_permissions--1.3--1.4.sql')
$installed = @()
$started = $false
try {
  $lines = @(& python scripts/issue112_pg_permissions_owned_source_pilot.py --source $upstream --pg "$Major" --output $zip 2>&1)
  if ($LASTEXITCODE -ne 0 -or $lines.Count -ne 1) { throw "Private source ZIP rejected: $($lines -join ' ')" }
  $build = $lines[0] | ConvertFrom-Json
  if ($build.status -cne 'CANDIDATE_ONLY' -or $build.source -cne 'cybertec-postgresql/pg_permissions' -or
      $build.pgMajor -cne "$Major" -or $build.sqlDefaultVersion -cne '1.4' -or
      $build.upstreamPackageVersion -cne '1.4.1' -or $build.members -ne 10 -or
      $build.publicGet -cne 'DENY' -or $build.publisher -cne 'DENY') { throw 'Private-only build receipt invalid' }
  $actual = (Get-FileHash -LiteralPath $zip -Algorithm SHA256).Hash.ToLowerInvariant()
  if ($actual -cne $build.sha256) { throw 'Independent on-disk ZIP SHA256 mismatch' }
  Expand-Archive -LiteralPath $zip -DestinationPath $stage -ErrorAction Stop
  $allFiles = @(Get-ChildItem -LiteralPath $stage -File -Recurse)
  if ($allFiles.Count -ne 10) { throw 'Unexpected extracted ZIP member count' }
  $manifest = Get-Content -LiteralPath (Join-Path $stage 'SOURCE-INPUTS.json') -Raw | ConvertFrom-Json
  if ($manifest.status -cne 'CANDIDATE_ONLY' -or
      $manifest.kind -cne 'PGEXTWIN_OWNED_SQL_SOURCE_NOT_CYBERTEC_ORIGINAL' -or
      $manifest.upstreamRepository -cne 'cybertec-postgresql/pg_permissions' -or
      $manifest.upstreamCommit -cne '3360447e0668fed2b9db6a0ae1d086533781f9bd' -or
      $manifest.postgresqlMajor -cne "$Major" -or
      $manifest.upstreamPackageVersion -cne '1.4.1' -or
      $manifest.sqlExtensionDefaultVersion -cne '1.4' -or
      $manifest.fullUpstreamLicenseIncluded -cne $true) { throw 'Source-owned manifest identity invalid' }
  foreach ($field in @('cybertecOriginalZip', 'cybertecProducerAttestationVerified',
                        'independentSourceSignatureVerified', 'windowsRuntimeFromThisZipVerified',
                        'downloadAuthorized', 'mirrorAuthorized', 'releaseAuthorized',
                        'publisherAuthorized')) {
    if ($manifest.$field -cne $false) { throw "Source manifest authority escalation: $field" }
  }
  $license = Join-Path $stage 'LICENSE'
  if (-not (Test-Path -LiteralPath $license -PathType Leaf) -or
      (Get-FileHash -LiteralPath $license -Algorithm SHA256).Hash -cne
      (Get-FileHash -LiteralPath (Join-Path $upstream 'LICENSE') -Algorithm SHA256).Hash) {
    throw 'Embedded full upstream LICENSE is not exact'
  }
  if (@($manifest.sourceFileSha256.PSObject.Properties).Count -ne 9) { throw 'Wrong source input hash count' }
  $members = @(Get-ChildItem -LiteralPath (Join-Path $stage 'share/extension') -File)
  if ($members.Count -ne 8) { throw 'Wrong SQL/control member count' }
  if (@(Compare-Object -ReferenceObject ($allow | Sort-Object) -DifferenceObject ($members.Name | Sort-Object)).Count -ne 0) {
    throw 'SQL/control member allowlist differs'
  }
  foreach ($member in $members) {
    $name = $member.Name
    $src = Join-Path $upstream $name
    $target = Join-Path $dest $name
    if (-not (Test-Path -LiteralPath $src -PathType Leaf) -or
        (Test-Path -LiteralPath $target)) { throw 'Unsafe source or existing install target' }
    $digest = (Get-FileHash -LiteralPath $member.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($digest -cne (Get-FileHash -LiteralPath $src -Algorithm SHA256).Hash.ToLowerInvariant() -or
        $digest -cne $manifest.sourceFileSha256.$name) {
      throw "SQL/control member does not match source or manifest: $name"
    }
    Copy-Item -LiteralPath $member.FullName -Destination $target -ErrorAction Stop
    $installed += $target
  }

  & $initdb -D $data -A trust -U postgres --no-instructions
  if ($LASTEXITCODE -ne 0) { throw 'initdb failed' }
  & $pgctl -D $data -l $log -o '-h 127.0.0.1 -p 55449' -w start
  if ($LASTEXITCODE -ne 0) { throw 'Disposable PostgreSQL start failed' }
  $started = $true
  $conn = @('-X','-A','-t','-v','ON_ERROR_STOP=1',
            '-h','127.0.0.1','-p','55449','-U','postgres','-d','postgres')
  & $psql @conn -c 'CREATE EXTENSION pg_permissions SCHEMA public;'
  if ($LASTEXITCODE -ne 0) { throw 'CREATE EXTENSION from source-owned ZIP failed' }
  $sqlVer = (& $psql @conn -c "SELECT extversion FROM pg_extension WHERE extname='pg_permissions';" | Out-String).Trim()
  if ($LASTEXITCODE -ne 0 -or $sqlVer -cne '1.4') { throw "Incorrect extension version $sqlVer" }
  & $psql @conn -c 'CREATE ROLE audit_reader LOGIN; CREATE SCHEMA audit_schema; CREATE TABLE audit_schema.audit_items (id int); GRANT USAGE ON SCHEMA audit_schema TO audit_reader; GRANT SELECT ON audit_schema.audit_items TO audit_reader;'
  if ($LASTEXITCODE -ne 0) { throw 'Permission fixture failed' }
  $read = (& $psql @conn -c "SELECT CASE WHEN EXISTS (SELECT 1 FROM public.table_permissions WHERE role_name='audit_reader' AND schema_name='audit_schema' AND object_name='audit_items' AND permission='SELECT' AND granted) THEN 'PASS' ELSE 'FAIL' END;" | Out-String).Trim()
  if ($LASTEXITCODE -ne 0 -or $read -cne 'PASS') { throw "Permission view failed: $read" }
  & $psql @conn -c "INSERT INTO public.permission_target (role_name, permissions, object_type, schema_name, object_name) VALUES ('audit_reader', '{SELECT}', 'TABLE', 'audit_schema', 'audit_items');"
  if ($LASTEXITCODE -ne 0) { throw 'permission_target INSERT failed' }
  & $psql @conn -c "SELECT count(*) FROM public.permission_diffs() WHERE role_name='audit_reader';"
  if ($LASTEXITCODE -ne 0) { throw 'permission_diffs invocation failed' }
  Write-Host "PG_PERMISSIONS_OWN_SOURCE_WINDOWS=PASS PG=$Major SQL=8/8 UPSTREAM=PINNED ZIP_SHA256=$actual SQL_EXTVERSION=1.4 GET=DENY RELEASE=DENY"
} catch {
  Write-Host "PG_PERMISSIONS_OWN_SOURCE_WINDOWS=FAIL PG=$Major DETAIL=$($_.Exception.Message)"
  if (Test-Path -LiteralPath $log) { Get-Content -LiteralPath $log -Tail 30 }
  throw
} finally {
  if ($started) {
    & $pgctl -D $data -m immediate -w stop
    if ($LASTEXITCODE -ne 0) { Write-Warning 'Disposable database stop failed' }
  }
  foreach ($path in $installed) { Remove-Item -LiteralPath $path -ErrorAction SilentlyContinue }
  foreach ($path in @($stage, $zip)) {
    if (Test-Path -LiteralPath $path) { Remove-Item -LiteralPath $path -Recurse -Force -ErrorAction SilentlyContinue }
  }
}
Write-Host 'CANDIDATE_ONLY PUBLIC_GET=DENY MIRROR=DENY SIGNER=NONE PUBLISHER=NONE RELEASE=DENY'
