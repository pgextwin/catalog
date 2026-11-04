# Issue #112: Hiraoka community pg_bigm original 7z, metadata-only/private.
# This is a 7z-aware bounded audit, not the existing ZIP auditor.
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$PSNativeCommandUseErrorActionPreference=$false
if ($env:GITHUB_ACTIONS -cne 'true' -or $env:RUNNER_OS -cne 'Windows' -or -not $env:RUNNER_TEMP) {
  throw 'Only private ephemeral Windows CI is supported'
}
$repo='HiraokaHyperTools/pg_bigm'; $tag='v20260107'
$assetName='20260107.7z'
$url="https://github.com/$repo/releases/download/$tag/$assetName"
$hash='4d627c5373886a37414b775f11f2bd4e78262a9b641cc155f0edf332fed132e5'
$release=Invoke-RestMethod -Uri "https://api.github.com/repos/$repo/releases/tags/$tag" -TimeoutSec 40
$sourceTag=Invoke-RestMethod -Uri "https://api.github.com/repos/$repo/git/ref/tags/$tag" -TimeoutSec 40
if ($sourceTag.object.type -cne 'commit' -or $sourceTag.object.sha -cne '921449b6569bcbca0f39ce4e7cf277b9b040ec8f') { throw 'Hiraoka original tag source SHA changed' }
$a=@($release.assets | Where-Object { $_.id -eq 337322081 })
if ($release.id -ne 274728862 -or $release.tag_name -cne $tag -or $release.draft -or
    $release.prerelease -or $a.Count -ne 1 -or $a[0].name -cne $assetName -or
    $a[0].size -ne 139599 -or $a[0].digest -cne "sha256:$hash" -or
    $a[0].state -cne 'uploaded' -or $a[0].browser_download_url -cne $url) {
  throw 'Original 7z release identity drift'
}
$file=Join-Path $env:RUNNER_TEMP 'issue112-hiraoka-original-20260107.7z'
Invoke-WebRequest -Uri $url -OutFile $file -MaximumRedirection 3 -TimeoutSec 90
$measured=(Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash.ToLowerInvariant()
if ((Get-Item -LiteralPath $file).Length -ne 139599 -or $measured -cne $hash) { throw 'Original 7z SHA256/length mismatch' }
Write-Host "HIRAOKA_7Z_ORIGINAL_SHA256=PASS HASH=$measured RELEASE_ID=274728862 ASSET_ID=337322081"

$seven=Join-Path ([Environment]::GetFolderPath('ProgramFiles')) '7-Zip/7z.exe'
if (-not (Test-Path -LiteralPath $seven)) {
  $found=Get-Command 7z.exe -ErrorAction SilentlyContinue
  if (-not $found) { throw '7z-aware tool missing; do not use ZIP inspector' }
  $seven=$found.Source
}
$listing=@(& $seven l -slt $file)
if ($LASTEXITCODE -ne 0) { throw '7z member listing failed' }
# 7-Zip -slt prints an archive header followed by dashed separator and
# independent key=value records for each member. Fail closed if unknown.
$sep=-1
for ($i=0; $i -lt $listing.Count; $i++) {
  if ($listing[$i] -match '^-{5,}$') { $sep=$i; break }
}
if ($sep -lt 0) { throw 'No 7z member metadata separator found' }
$members=[Collections.Generic.List[object]]::new()
$record=@{}
function End-Record {
  if ($record.Count -eq 0) { return }
  if (-not $record.ContainsKey('Path') -or -not $record.ContainsKey('Size')) { throw 'Malformed 7z member record' }
  $members.Add([pscustomobject]@{
    Name=[string]$record['Path']; NormalizedName=([string]$record['Path']).Replace('\','/'); Size=[long]$record['Size']
    Attributes=[string]$record['Attributes']; Encrypted=[string]$record['Encrypted']
  })
  $record.Clear()
}
for ($i=$sep+1; $i -lt $listing.Count; $i++) {
  $line=[string]$listing[$i]
  if (-not $line.Trim()) { End-Record; continue }
  if ($line -notmatch '^([A-Za-z ]+) = (.*)$') { throw "Unrecognized 7z metadata: $line" }
  $record[$matches[1].Trim()]=$matches[2]
}
End-Record
function Assert-SafeMembers([object[]]$entries) {
  if ($entries.Count -lt 3 -or $entries.Count -gt 1500) { throw '7z member count outside bounds' }
  $seen=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
  [long]$expanded=0
  foreach ($entry in $entries) {
    $n=[string]$entry.Name
    $canonical=$n.Replace('\','/')
    if (-not $canonical -or $canonical -match '^(/|[A-Za-z]:)' -or
      $canonical.Contains(':') -or $canonical -match '(^|/)[.][.]?(/|$)' -or
      -not $seen.Add($canonical) -or $canonical -notmatch '^[A-Za-z0-9._/-]+$') { throw "Unsafe or duplicated 7z path: $n" }
    if ($entry.Encrypted -eq '+' -or $entry.Attributes -match '[Ll]') { throw "Encrypted or linked 7z entry: $n" }
    if ($entry.Size -lt 0 -or $entry.Size -gt 20000000) { throw "Oversized 7z member: $n" }
    $expanded += $entry.Size
    if ($expanded -gt 90000000) { throw '7z aggregate expansion budget exceeded' }
  }
  return $expanded
}
# Offline adversarial fixtures: reject traversal, case-fold duplicates, encryption, bomb.
$fixture=@([pscustomobject]@{Name='a/file';Size=12;Attributes='A';Encrypted='-'},
           [pscustomobject]@{Name='b/file';Size=14;Attributes='A';Encrypted='-'},
           [pscustomobject]@{Name='c/file';Size=16;Attributes='A';Encrypted='-'})
[void](Assert-SafeMembers $fixture)
foreach ($bad in @(
  @([pscustomobject]@{Name='../escape';Size=10;Attributes='A';Encrypted='-'}),
  @([pscustomobject]@{Name='A/FILE';Size=10;Attributes='A';Encrypted='-'}),
  @([pscustomobject]@{Name='x/secret';Size=10;Attributes='A';Encrypted='+'}),
  @([pscustomobject]@{Name='x/huge';Size=20000001;Attributes='A';Encrypted='-'})
)) {
  $sample=@($fixture + $bad)
  $rejected=$false
  try { [void](Assert-SafeMembers $sample) } catch { $rejected=$true }
  if (-not $rejected) { throw 'Hostile 7z metadata fixture was accepted' }
}
Write-Host 'HIRAOKA_7Z_HOSTILE_METADATA_FIXTURES=PASS'
$expanded=Assert-SafeMembers $members.ToArray()
Write-Host "HIRAOKA_7Z_LIST=PASS MEMBERS=$($members.Count) EXPANDED=$expanded"
# 7z t validates the full original archive CRC without extracting to disk.
$test=@(& $seven t $file)
if ($LASTEXITCODE -ne 0 -or (($test | Out-String) -notmatch 'Everything is Ok')) {
  throw '7z full archive CRC test failed'
}
Write-Host 'HIRAOKA_7Z_CRC=PASS NO_EXTRACTION=YES'

$controls=@($members | Where-Object {
  $_.NormalizedName -match '^pg_bigm-postgresql-18[.]0-x64/(?:share/)?extension/pg_bigm[.]control$'
})
if ($controls.Count -ne 1 -or $controls[0].Size -gt 4096) {
  throw 'PG18 x64 control member not uniquely identified'
}
$controlText=(& $seven e -so $file $controls[0].Name | Out-String)
if ($LASTEXITCODE -ne 0) { throw 'Bounded PG18 control read failed' }
if ($controlText -notmatch '(?m)^\s*default_version\s*=\s*[''"]([0-9]+(?:[.][0-9]+)+)[''"]') {
  throw 'pg_bigm upstream extension version absent'
}
$sourceVersion=$matches[1]
if ($sourceVersion -cne '1.2') { throw 'Unexpected bundled pg_bigm upstream version; require independent review' }
$licenses=@($members | Where-Object { $_.NormalizedName -match '(^|/)(LICENSE|LICENCE|NOTICE)([.][A-Za-z0-9_-]+)?$' })
Write-Host "HIRAOKA_PG18_EXTENSION_VERSION=$sourceVersion SOURCE_BUILD_COMMIT=NOT_VERIFIED"
Write-Host "HIRAOKA_PACKAGE_RIGHTS_FILES=$(@($licenses | ForEach-Object { $_.Name }) -join ',') COPYRIGHT_NOTICE_REVIEW=NOT_COMPLETE"
# Native PG18 smoke is private and uses only individually vetted PG18 entries.
if (-not $env:PGROOT) { throw 'PGROOT missing from disposable PG18 runner' }
$root=[IO.Path]::GetFullPath($env:PGROOT)
$bin=Join-Path $root 'bin'
$pgConfig=Join-Path $bin 'pg_config.exe'
if (-not (Test-Path -LiteralPath $pgConfig)) { throw 'PG18 pg_config absent' }
$pgVersion=(& $pgConfig --version | Out-String).Trim()
if ($LASTEXITCODE -ne 0 -or $pgVersion -notmatch '^PostgreSQL 18(?:[.]|\s)') { throw "Wrong PG ABI: $pgVersion" }
$lib=(& $pgConfig --pkglibdir | Out-String).Trim()
$sharedir=(& $pgConfig --sharedir | Out-String).Trim()
foreach ($destDir in @($lib,$sharedir)) {
  if (-not ([IO.Path]::GetFullPath($destDir)).StartsWith($root,[StringComparison]::OrdinalIgnoreCase)) {
    throw 'pg_config location outside exact disposable PG18'
  }
}
$prefix='pg_bigm-postgresql-18.0-x64/'
$payload=@($members | Where-Object {
  $_.NormalizedName -cmatch '^pg_bigm-postgresql-18[.]0-x64/(?:lib/pg_bigm[.]dll|(?:share/)?extension/pg_bigm[.]control|(?:share/)?extension/pg_bigm--[A-Za-z0-9._-]+[.]sql)
Write-Host 'APPROVED_OPERATION=NONE DOWNLOAD_DENY=YES MIRROR_DENY=YES'

})
$dlls=@($payload | Where-Object { $_.NormalizedName -ceq ($prefix+'lib/pg_bigm.dll') })
$ctrls=@($payload | Where-Object { $_.NormalizedName -cmatch '/extension/pg_bigm[.]control
Write-Host 'APPROVED_OPERATION=NONE DOWNLOAD_DENY=YES MIRROR_DENY=YES'
 })
$sqls=@($payload | Where-Object { $_.NormalizedName -cmatch '/extension/pg_bigm--[A-Za-z0-9._-]+[.]sql
Write-Host 'APPROVED_OPERATION=NONE DOWNLOAD_DENY=YES MIRROR_DENY=YES'
 })
if ($dlls.Count -ne 1 -or $ctrls.Count -ne 1 -or $sqls.Count -lt 1) { throw 'Required exact PG18 DLL/control/SQL entries absent' }
$stage=Join-Path $env:RUNNER_TEMP 'issue112-hiraoka-pg18-vetted'
New-Item -Path $stage -ItemType Directory -Force | Out-Null
$destExt=Join-Path $sharedir 'extension'
foreach ($m in $payload) {
  $baseName=[IO.Path]::GetFileName($m.NormalizedName)
  if (-not $baseName -or $baseName -notmatch '^pg_bigm(?:--[A-Za-z0-9._-]+[.]sql|[.]control|[.]dll)
Write-Host 'APPROVED_OPERATION=NONE DOWNLOAD_DENY=YES MIRROR_DENY=YES'
) { throw 'Unexpected staged basename' }
  $destFolder=if ($baseName -ceq 'pg_bigm.dll') {$lib} else {$destExt}
  $dest=Join-Path $destFolder $baseName
  if (Test-Path -LiteralPath $dest) { throw "Refusing existing extension file: $dest" }
  & $seven e "-o$stage" -y $file $m.Name | Out-Null
  if ($LASTEXITCODE -ne 0) { throw 'Known exact 7z member extraction failed' }
  $staged=Join-Path $stage $baseName
  if (-not (Test-Path -LiteralPath $staged) -or (Get-Item -LiteralPath $staged).Length -ne $m.Size) {
    throw "Vetted member extraction length failed: $baseName"
  }
  Copy-Item -LiteralPath $staged -Destination $dest -ErrorAction Stop
  Remove-Item -LiteralPath $staged -Force
}
Write-Host "HIRAOKA_PG18_VETTED_STAGE=PASS DLLS=$($dlls.Count) SQL=$($sqls.Count) NO_UNKNOWN_MEMBER_EXTRACTION=YES"

$vswhere=Join-Path ([Environment]::GetFolderPath('ProgramFilesX86')) 'Microsoft Visual Studio/Installer/vswhere.exe'
if (-not (Test-Path -LiteralPath $vswhere)) { throw 'VS dependency tool missing' }
$vsroot=(& $vswhere -latest -property installationPath | Out-String).Trim()
$dumpbin=@(Get-ChildItem -LiteralPath (Join-Path $vsroot 'VC/Tools/MSVC') -Filter dumpbin.exe -Recurse -File |
  Where-Object { $_.FullName -match 'Hostx64[\\/]x64[\\/]dumpbin[.]exe
Write-Host 'APPROVED_OPERATION=NONE DOWNLOAD_DENY=YES MIRROR_DENY=YES'
 })
if ($dumpbin.Count -lt 1) { throw 'x64 dumpbin absent' }
$deps=@(& $dumpbin[0].FullName /DEPENDENTS (Join-Path $lib 'pg_bigm.dll'))
if ($LASTEXITCODE -ne 0) { throw 'pg_bigm PE import inspection failed' }
$imports=@($deps | ForEach-Object {
  if ($_ -match '^\s*([A-Za-z0-9_.-]+[.]dll)\s*
Write-Host 'APPROVED_OPERATION=NONE DOWNLOAD_DENY=YES MIRROR_DENY=YES'
) { $matches[1].ToLowerInvariant() }
} | Sort-Object -Unique)
if ($imports.Count -lt 1) { throw 'pg_bigm import names unavailable' }
Write-Host "HIRAOKA_PG18_STATIC_DEPENDENCIES=$($imports -join ',') TRANSITIVE_DYNAMIC_DEPENDENCIES=NOT_FULLY_VERIFIED"

$data=Join-Path $env:RUNNER_TEMP 'issue112-hiraoka-pg18-data'
$log=Join-Path $env:RUNNER_TEMP 'issue112-hiraoka-pg18.log'
$initdb=Join-Path $bin 'initdb.exe'; $pgctl=Join-Path $bin 'pg_ctl.exe'; $psql=Join-Path $bin 'psql.exe'
$started=$false
try {
  & $initdb -D $data -A trust -U postgres --no-instructions | Out-Null
  if ($LASTEXITCODE -ne 0) { throw 'initdb failed' }
  & $pgctl -D $data -l $log -o '-h 127.0.0.1 -p 55448' -w start | Out-Null
  if ($LASTEXITCODE -ne 0) { throw 'PostgreSQL startup failed' }
  $started=$true
  $psqlArgs=@('-X','-A','-t','-v','ON_ERROR_STOP=1','-h','127.0.0.1','-p','55448','-U','postgres','-d','postgres')
  & $psql @psqlArgs -c 'CREATE EXTENSION pg_bigm;'
  if ($LASTEXITCODE -ne 0) { throw 'Hiraoka pg_bigm CREATE EXTENSION failed' }
  $version=(& $psql @psqlArgs -c "SELECT extversion FROM pg_extension WHERE extname='pg_bigm';" | Out-String).Trim()
  if ($LASTEXITCODE -ne 0 -or $version -cne '1.2') { throw "Wrong installed pg_bigm version: $version" }
  $sql=@'
CREATE TABLE issue112_bigm (id integer PRIMARY KEY, val text NOT NULL);
INSERT INTO issue112_bigm VALUES (1,'applepie'),(2,'pineapple'),(3,'banana');
CREATE INDEX issue112_bigm_idx ON issue112_bigm USING gin (val gin_bigm_ops);
'@
  & $psql @psqlArgs -c $sql
  if ($LASTEXITCODE -ne 0) { throw 'pg_bigm test table/index setup failed' }
  $count=(& $psql @psqlArgs -c "SELECT COUNT(*) FROM issue112_bigm WHERE val LIKE likequery('apple');" | Out-String).Trim()
  if ($LASTEXITCODE -ne 0 -or $count -cne '2') { throw "Wrong pg_bigm indexed SQL result: $count" }
  $explain=(& $psql @psqlArgs -c "SET enable_seqscan=off; EXPLAIN SELECT val FROM issue112_bigm WHERE val LIKE likequery('apple');" | Out-String)
  if ($LASTEXITCODE -ne 0 -or $explain -notmatch 'Bitmap Index Scan on issue112_bigm_idx') { throw 'pg_bigm GIN plan not observed' }
  Write-Host "HIRAOKA_PG18_NATIVE_SQL=PASS VERSION=$version CREATE_EXTENSION=YES GIN_SEARCH=PASS INDEX_PLAN=PASS"
} catch {
  Write-Host "HIRAOKA_PG18_NATIVE_SQL=FAIL DETAIL=$($_.Exception.Message)"
  if (Test-Path -LiteralPath $log) { Get-Content -LiteralPath $log -Tail 70 | ForEach-Object { Write-Host $_ } }
  throw
} finally {
  if ($started) {
    & $pgctl -D $data -m immediate -w stop | Out-Null
    if ($LASTEXITCODE -ne 0) { Write-Warning 'Disposable PG18 shutdown failed' }
  }
}
Write-Host 'HIRAOKA_ORIGINAL_PACKAGE_NOTICE_MISSING=YES RIGHTS_REVIEW=NOT_COMPLETE SOURCE_BUILD_PROVENANCE=NOT_VERIFIED'
Write-Host 'HIRAOKA_PG18_NATIVE_BASIC_RUNTIME=PASS DYNAMIC_DEPENDENCY_CLOSURE=NOT_VERIFIED FORMAL_AUTHORIZATION=FALSE'
Write-Host 'APPROVED_OPERATION=NONE DOWNLOAD_DENY=YES MIRROR_DENY=YES'
