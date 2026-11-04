# Issue #112: disposable nonpublishing pg_trickle v0.108.3 PG18 Windows runtime.
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$PSNativeCommandUseErrorActionPreference=$false
if ($env:GITHUB_ACTIONS -cne 'true' -or $env:RUNNER_OS -cne 'Windows' -or -not $env:RUNNER_TEMP -or -not $env:PGROOT) { throw 'Requires ephemeral Windows GitHub Actions runner and PGROOT' }
$root=[IO.Path]::GetFullPath($env:PGROOT)
$bin=Join-Path $root 'bin'
$pgConfig=Join-Path $bin 'pg_config.exe'
if (-not (Test-Path -LiteralPath $pgConfig)) { throw 'PostgreSQL installation absent' }
$ver=(& $pgConfig --version | Out-String).Trim()
if ($LASTEXITCODE -ne 0 -or $ver -notmatch '^PostgreSQL 18(?:[.]|\s)') { throw "Unexpected PostgreSQL: $ver" }
$lib=(& $pgConfig --pkglibdir | Out-String).Trim()
$share=(& $pgConfig --sharedir | Out-String).Trim()
if ($LASTEXITCODE -ne 0 -or -not $lib -or -not $share -or
  -not ([IO.Path]::GetFullPath($lib)).StartsWith($root,[StringComparison]::OrdinalIgnoreCase) -or
  -not ([IO.Path]::GetFullPath($share)).StartsWith($root,[StringComparison]::OrdinalIgnoreCase)) { throw 'PG install root mismatch' }

$repo='trickle-labs/pg-trickle'
$tag='v0.108.3'
$assetName='pg_trickle-0.108.3-pg18-windows-amd64.zip'
$url="https://github.com/$repo/releases/download/$tag/$assetName"
$digest='c2841dacee6fa1a09400c7e9a0f74159f2b7f36847a60ef10291d1beb06bd96b'
$release=Invoke-RestMethod -Uri "https://api.github.com/repos/$repo/releases/tags/$tag" -TimeoutSec 40
$tagRef=Invoke-RestMethod -Uri "https://api.github.com/repos/$repo/git/ref/tags/$tag" -TimeoutSec 40
$a=@($release.assets | Where-Object { $_.id -eq 616203967 })
if ($release.id -ne 404988260 -or $release.tag_name -cne $tag -or $release.draft -or $release.prerelease -or
  $tagRef.object.type -cne 'commit' -or $tagRef.object.sha -cne 'ce709f06327b4801f79fc48934bc96107b450907' -or
  $a.Count -ne 1 -or $a[0].name -cne $assetName -or $a[0].size -ne 7029107 -or
  $a[0].digest -cne "sha256:$digest" -or $a[0].state -cne 'uploaded' -or
  $a[0].browser_download_url -cne $url) { throw 'Pinned source / Release / asset drift' }
$zip=Join-Path $env:RUNNER_TEMP 'issue112-original-pg-trickle.zip'
Invoke-WebRequest -Uri $url -OutFile $zip -MaximumRedirection 3 -TimeoutSec 120
$sha=(Get-FileHash -LiteralPath $zip -Algorithm SHA256).Hash.ToLowerInvariant()
if ((Get-Item -LiteralPath $zip).Length -ne 7029107 -or $sha -cne $digest) { throw 'Original Windows ZIP byte mismatch' }
Write-Host "ORIGINAL_SHA256=PASS SHA256=$sha SOURCE_SHA=ce709f06327b4801f79fc48934bc96107b450907"

Add-Type -AssemblyName System.IO.Compression
$archive=[IO.Compression.ZipFile]::OpenRead($zip)
$prefix='pg_trickle-0.108.3-pg18-windows-amd64/'
$seen=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
[long]$expanded=0
$dllCount=0; $controlCount=0; $sqlCount=0
try {
  if ($archive.Entries.Count -lt 4 -or $archive.Entries.Count -gt 2500) { throw 'Member count outside bounds' }
  # The upstream release.yml embeds a self-declared candidate commit and LICENSE.
  # Verify the fields in the independently rehashed original bytes, not a local fixture.
  # An embedded JSON document is NOT a cryptographically authenticated build attestation.
  $candidate=$archive.GetEntry($prefix+'release-candidate.json')
  $license=$archive.GetEntry($prefix+'LICENSE')
  if ($null -eq $candidate -or $candidate.Length -lt 80 -or $candidate.Length -gt 4096) {
    throw 'Missing or unbounded upstream release-candidate metadata'
  }
  if ($null -eq $license -or $license.Length -lt 5000 -or $license.Length -gt 30000) {
    throw 'Missing or unbounded upstream LICENSE'
  }
  $reader=[IO.StreamReader]::new($candidate.Open(),[Text.UTF8Encoding]::new($false,$true))
  try { $candidateText=$reader.ReadToEnd() } finally { $reader.Dispose() }
  $declared=$candidateText | ConvertFrom-Json -AsHashtable
  if ($null -eq $declared -or
      $declared.candidate_commit -cne 'ce709f06327b4801f79fc48934bc96107b450907' -or
      $declared.build_kind -cne 'exact-release' -or
      $declared.feature_scope -cne 'default-release' -or
      $declared.build_provenance.workflow -cne 'release.yml' -or
      $declared.build_provenance.cargo_profile -cne 'release' -or
      $declared.build_provenance.instrumentation -cne 'none') {
    throw 'Upstream self-declared release candidate/source metadata mismatch'
  }
  $reader=[IO.StreamReader]::new($license.Open(),[Text.UTF8Encoding]::new($false,$true))
  try { $licenseText=$reader.ReadToEnd() } finally { $reader.Dispose() }
  if (-not $licenseText.Contains('Apache License') -or
      -not $licenseText.Contains('Version 2.0, January 2004') -or
      -not $licenseText.Contains('TERMS AND CONDITIONS FOR USE, REPRODUCTION, AND DISTRIBUTION')) {
    throw 'Original package LICENSE does not identify expected Apache-2.0 text'
  }
  Write-Host 'UPSTREAM_EMBEDDED_ORIGIN=SOURCE_DECLARATION_MATCH SOURCE_SHA=ce709f06327b4801f79fc48934bc96107b450907 LICENSE_IN_ORIGINAL_ZIP=APACHE_2_0_PRESENT'
  Write-Host 'INDEPENDENT_SOURCE_TO_BINARY_ATTESTATION=NOT_VERIFIED THIRD_PARTY_NOTICE_CLOSURE=NOT_VERIFIED'
  foreach ($e in $archive.Entries) {
    $name=$e.FullName
    if (-not $name -or -not $name.StartsWith($prefix,[StringComparison]::Ordinal) -or
      $name.Contains('\') -or $name.Contains(':') -or $name -match '(^|/)[.][.]?(/|$)' -or
      -not $seen.Add($name)) { throw "Unsafe ZIP member: $name" }
    if ($e.Name -eq '') { continue }
    $expanded+=$e.Length
    if ($expanded -gt 180000000 -or $e.Length -gt 90000000 -or
        $e.Length -gt (1000 * [Math]::Max(1,$e.CompressedLength))) { throw 'Expansion budget exceeded' }
    $relative=$name.Substring($prefix.Length)
    if ($relative -ceq 'lib/pg_trickle.dll') { $dllCount++ }
    if ($relative -ceq 'extension/pg_trickle.control') { $controlCount++ }
    if ($relative -cmatch '^extension/pg_trickle--[A-Za-z0-9._-]+[.]sql$') { $sqlCount++ }
    if ($relative -ceq 'lib/pg_trickle.dll') { $destDir=$lib }
    elseif ($relative -ceq 'extension/pg_trickle.control' -or
            $relative -cmatch '^extension/pg_trickle--[A-Za-z0-9._-]+[.]sql$') { $destDir=Join-Path $share 'extension' }
    else { continue }
    $dest=Join-Path $destDir ([IO.Path]::GetFileName($relative))
    if (Test-Path -LiteralPath $dest) { throw "Existing PG file must not be overwritten: $dest" }
    $inputStream=$null; $outputStream=$null
    try {
      $inputStream=$e.Open(); $outputStream=[IO.File]::Create($dest)
      $inputStream.CopyTo($outputStream)
    } finally {
      if ($outputStream) { $outputStream.Dispose() }
      if ($inputStream) { $inputStream.Dispose() }
    }
  }
  if ($dllCount -ne 1 -or $controlCount -ne 1 -or $sqlCount -lt 1) { throw 'Required DLL/control/SQL missing' }
} finally { $archive.Dispose() }
Write-Host "ZIP_STAGE=PASS ENTRIES=$($seen.Count) SQL=$sqlCount EXPANDED=$expanded"

# Actual PE import table, not just machine header. dumpbin is supplied by VS on windows-latest.
$vswhere=Join-Path ([Environment]::GetFolderPath('ProgramFilesX86')) 'Microsoft Visual Studio/Installer/vswhere.exe'
if (-not (Test-Path -LiteralPath $vswhere)) { throw 'vswhere missing; dependency audit cannot pass' }
$vsroot=(& $vswhere -latest -property installationPath | Out-String).Trim()
$dumpbins=@(Get-ChildItem -LiteralPath (Join-Path $vsroot 'VC/Tools/MSVC') -Filter dumpbin.exe -File -Recurse |
  Where-Object { $_.FullName -match 'Hostx64[\\/]x64[\\/]dumpbin[.]exe$' })
if ($dumpbins.Count -lt 1) { throw 'x64 dumpbin missing' }
$depOutput=@(& $dumpbins[0].FullName /DEPENDENTS (Join-Path $lib 'pg_trickle.dll'))
if ($LASTEXITCODE -ne 0) { throw 'dumpbin dependency inspection failed' }
$names=@($depOutput | ForEach-Object {
  if ($_ -match '^\s*([A-Za-z0-9_.-]+[.]dll)\s*$') { $matches[1].ToLowerInvariant() }
} | Sort-Object -Unique)
if ($names.Count -lt 1) { throw 'No PE static imports read' }
Write-Host "STATIC_DEPENDENCY_DLLS=$($names -join ',') DELAY_AND_DYNAMIC_IMPORTS=NOT_FULLY_VERIFIED"

$data=Join-Path $env:RUNNER_TEMP 'issue112-trickle-pg18-data'
$log=Join-Path $env:RUNNER_TEMP 'issue112-trickle-pg18.log'
$ctl=Join-Path $bin 'pg_ctl.exe'; $psql=Join-Path $bin 'psql.exe'; $initdb=Join-Path $bin 'initdb.exe'
$port=55447; $started=$false
try {
  & $initdb -D $data -A trust -U postgres --no-instructions
  if ($LASTEXITCODE -ne 0) { throw 'initdb failed' }
  & $ctl -D $data -l $log -o "-h 127.0.0.1 -p $port -c shared_preload_libraries=pg_trickle -c max_worker_processes=16" -w start
  if ($LASTEXITCODE -ne 0) { throw 'PG startup with shared_preload failed' }
  $started=$true
  $args=@('-X','-A','-t','-v','ON_ERROR_STOP=1','-h','127.0.0.1','-p',[string]$port,'-U','postgres','-d','postgres')
  $preload=(& $psql @args -c 'SHOW shared_preload_libraries;' | Out-String).Trim()
  if ($LASTEXITCODE -ne 0 -or $preload -notmatch '(^|,)pg_trickle($|,)') { throw 'Preload missing' }
  & $psql @args -c 'CREATE EXTENSION pg_trickle;'
  if ($LASTEXITCODE -ne 0) { throw 'CREATE EXTENSION pg_trickle failed' }
  $installed=(& $psql @args -c "SELECT extversion FROM pg_extension WHERE extname='pg_trickle';" | Out-String).Trim()
  if ($LASTEXITCODE -ne 0 -or $installed -cne '0.108.3') { throw "Installed version unexpected: $installed" }
  $namespace=(& $psql @args -c "SELECT count(*) FROM pg_namespace WHERE nspname='pgtrickle';" | Out-String).Trim()
  if ($LASTEXITCODE -ne 0 -or $namespace -ne '1') { throw 'SQL schema absent' }
  # Full SQL-facing behaviour: source table, stream table, INSERT/UPDATE/DELETE, explicit refresh.
  # Each psql invocation commits separately, exercising CDC across transactions.
  & $psql @args -c "CREATE TABLE issue112_orders (id integer PRIMARY KEY, region text NOT NULL, amount numeric NOT NULL); INSERT INTO issue112_orders VALUES (1,'US',100),(2,'US',300),(3,'EU',200);"
  if ($LASTEXITCODE -ne 0) { throw 'Stream source setup failed' }
  & $psql @args -c "SELECT pgtrickle.create_stream_table(name => 'issue112_stream', query => 'SELECT region, SUM(amount) AS total, COUNT(*) AS order_count FROM issue112_orders GROUP BY region', schedule => '1m', refresh_mode => 'DIFFERENTIAL');"
  if ($LASTEXITCODE -ne 0) { throw 'Stream table creation failed' }
  $initial=(& $psql @args -c "SELECT CASE WHEN (SELECT total FROM issue112_stream WHERE region='US')=400 AND (SELECT order_count FROM issue112_stream WHERE region='US')=2 AND (SELECT total FROM issue112_stream WHERE region='EU')=200 THEN 1 ELSE 0 END;" | Out-String).Trim()
  if ($LASTEXITCODE -ne 0 -or $initial -cne '1') { throw "Stream initial materialization failed: $initial" }
  & $psql @args -c "INSERT INTO issue112_orders VALUES (4,'US',50); UPDATE issue112_orders SET amount=250 WHERE id=3; DELETE FROM issue112_orders WHERE id=1;"
  if ($LASTEXITCODE -ne 0) { throw 'Stream CDC source mutations failed' }
  & $psql @args -c "SELECT pgtrickle.refresh_stream_table('issue112_stream');"
  if ($LASTEXITCODE -ne 0) { throw 'Manual differential refresh failed' }
  $after=(& $psql @args -c "SELECT CASE WHEN (SELECT total FROM issue112_stream WHERE region='US')=350 AND (SELECT order_count FROM issue112_stream WHERE region='US')=2 AND (SELECT total FROM issue112_stream WHERE region='EU')=250 AND (SELECT order_count FROM issue112_stream WHERE region='EU')=1 THEN 1 ELSE 0 END;" | Out-String).Trim()
  if ($LASTEXITCODE -ne 0 -or $after -cne '1') { throw "Stream SQL CDC output mismatch: $after" }
  Write-Host 'PG_TRICKLE_PG18_STREAM_FUNCTIONAL=PASS CREATE=YES INITIAL=YES INSERT=YES UPDATE=YES DELETE=YES DIFFERENTIAL_REFRESH=YES SQL_VALUES=PASS'
  Write-Host "PG18_WINDOWS_RUNTIME=PASS EXTVERSION=$installed PRELOAD=YES LOAD=YES SQL_SCHEMA=YES"
} catch {
  Write-Host "PG18_WINDOWS_RUNTIME=FAIL DETAIL=$($_.Exception.Message)"
  if (Test-Path -LiteralPath $log) { Get-Content -LiteralPath $log -Tail 70 | ForEach-Object { Write-Host $_ } }
  throw
} finally {
  if ($started) {
    & $ctl -D $data -m immediate -w stop
    if ($LASTEXITCODE -ne 0) { Write-Warning 'Disposable shutdown failed' }
  }
}
Write-Host 'BUILD_PROVENANCE=NOT_VERIFIED DYNAMIC_DEPENDENCY_CLOSURE=NOT_VERIFIED COMPLETE_NOTICE_RIGHTS=NOT_VERIFIED'
Write-Host 'FORMAL_SOURCE_SPECIFIC_AUTHORIZATION=FALSE APPROVED_OPERATION=NONE DOWNLOAD_DENY=YES MIRROR_DENY=YES'
