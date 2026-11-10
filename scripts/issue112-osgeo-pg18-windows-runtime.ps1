# Issue #112: immutable OSGeo bundle original, disposable Windows PostgreSQL 18.
# Nonpublishing technical qualification ONLY. No signed admission or public GET.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false

if ($env:GITHUB_ACTIONS -cne 'true' -or $env:GITHUB_REPOSITORY -cne 'pgextwin/catalog' -or
    $env:RUNNER_OS -cne 'Windows' -or -not $env:PGROOT -or -not $env:RUNNER_TEMP) {
  throw 'Requires pgextwin/catalog ephemeral Windows CI with PGROOT'
}
$root = [IO.Path]::GetFullPath($env:PGROOT)
$bin = Join-Path $root 'bin'
$pgconfig = Join-Path $bin 'pg_config.exe'
if (-not (Test-Path -LiteralPath $pgconfig)) { throw 'PG18 absent' }
$pgversion = (& $pgconfig --version | Out-String).Trim()
if ($LASTEXITCODE -ne 0 -or $pgversion -notmatch '^PostgreSQL 18(?:[.]|\s)') {
  throw "Unexpected PG binary: $pgversion"
}
$pkglib = (& $pgconfig --pkglibdir | Out-String).Trim()
$shared = (& $pgconfig --sharedir | Out-String).Trim()
if ($LASTEXITCODE -ne 0 -or -not $pkglib -or -not $shared) { throw 'PG directories unavailable' }
foreach ($path in @($pkglib, $shared)) {
  $full = [IO.Path]::GetFullPath($path)
  if (-not $full.StartsWith($root.TrimEnd('\') + '\', [StringComparison]::OrdinalIgnoreCase)) {
    throw "PG target escaped PGROOT: $path"
  }
}
$shareext = Join-Path $shared 'extension'
$effectiveCurl = Join-Path $bin 'libcurl.dll'
if (-not (Test-Path -LiteralPath $effectiveCurl -PathType Leaf)) {
  throw 'Required preinstalled EDB libcurl.dll absent; no presumed libnghttp2 closure'
}
$preinstalledCurlSha = (Get-FileHash -LiteralPath $effectiveCurl -Algorithm SHA256).Hash.ToLowerInvariant()

# Exact previous independent original-byte pilot evidence; not a signature.
$name = 'postgis-bundle-pg18-3.7.0x64.zip'
$url = "https://download-cache.osgeo.org/postgis/windows/pg18/$name"
$expectedBytes = 83320975
$expectedSha = 'fa3db8060d8d376e869d961659bf4eff326c0d99a731396701af61a13dc12a40'
$zip = Join-Path $env:RUNNER_TEMP $name
Invoke-WebRequest -Uri $url -OutFile $zip -MaximumRedirection 3 -TimeoutSec 240
$size = (Get-Item -LiteralPath $zip).Length
$sha = (Get-FileHash -LiteralPath $zip -Algorithm SHA256).Hash.ToLowerInvariant()
if ($size -ne $expectedBytes -or $sha -cne $expectedSha) { throw 'Original OSGeo byte identity mismatch' }
Write-Host "OSGEO_ORIGINAL_BYTES=PASS BYTES=$size SHA256=$sha PG=18"

Add-Type -AssemblyName System.IO.Compression
$archive = [IO.Compression.ZipFile]::OpenRead($zip)
$staged = @{ lib = 0; bin = 0; share = 0 }
$licenseFiles = @()
$seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
[long]$expanded = 0
try {
  if ($archive.Entries.Count -ne 1041) { throw 'Known original ZIP member count differs' }
  $controlName = 'share/extension/postgis.control'
  $roots = @($archive.Entries | Where-Object {
      $_.FullName.EndsWith($controlName, [StringComparison]::Ordinal)
    } | ForEach-Object { $_.FullName.Substring(0, $_.FullName.Length - $controlName.Length) })
  if ($roots.Count -ne 1) { throw 'Ambiguous or missing PostgreSQL bundle layout prefix' }
  $prefix = $roots[0]
  if ($prefix -match '(^|/)[.][.]?(/|$)' -or $prefix.Contains('\') -or $prefix.Contains(':')) {
    throw 'Unsafe archive root prefix'
  }
  if ($null -eq $archive.GetEntry($prefix + 'share/extension/pgrouting.control')) {
    throw 'pgRouting not in matching archive layout'
  }
  foreach ($entry in $archive.Entries) {
    $n = $entry.FullName
    if (-not $n -or $n.StartsWith('/') -or $n.Contains('\') -or $n.Contains(':') -or
        $n -match '(^|/)[.][.]?(/|$)' -or -not $seen.Add($n) -or
        ((($entry.ExternalAttributes -shr 16) -band 0xF000) -eq 0xA000)) {
      throw "Unsafe ZIP member: $n"
    }
    $expanded += $entry.Length
    if ($expanded -gt 2147483648 -or $entry.Length -gt (500 * [Math]::Max(1, $entry.CompressedLength))) {
      throw 'ZIP expansion limit exceeded'
    }
    if ($entry.Name -eq '') { continue }
    if ($n -match '(?i)(^|/)(LICENSE[^/]*|COPYING[^/]*|NOTICE[^/]*)(/|$)') {
      $licenseFiles += $n
    }
    if (-not $n.StartsWith($prefix, [StringComparison]::Ordinal)) { continue }
    $relative = $n.Substring($prefix.Length)
    $dest = $null
    $category = $null
    if ($relative -cmatch '^lib/[^/]+[.]dll$') {
      $dest = Join-Path $pkglib $entry.Name; $category = 'lib'
    } elseif ($relative -cmatch '^bin/[^/]+[.]dll$') {
      # Libraries bundled for PostGIS/GEOS/PROJ are staged only on this disposable runner.
      $dest = Join-Path $bin $entry.Name; $category = 'bin'
    } elseif ($relative -cmatch '^share/extension/(?:postgis|pgrouting)[A-Za-z0-9_.-]*[.](?:control|sql)$') {
      $dest = Join-Path $shareext $entry.Name; $category = 'share'
    } else { continue }
    if (Test-Path -LiteralPath $dest) {
      # Do not overwrite PostgreSQL's preinstalled, potentially unrelated DLLs.
      $original = (Get-FileHash -LiteralPath $dest -Algorithm SHA256).Hash.ToLowerInvariant()
      $stream = $entry.Open()
      try {
        $md5 = [Security.Cryptography.SHA256]::Create()
        try { $entryHash = [Convert]::ToHexString($md5.ComputeHash($stream)).ToLowerInvariant() }
        finally { $md5.Dispose() }
      } finally { $stream.Dispose() }
      if ($original -cne $entryHash) {
        if ($category -eq 'bin') {
          # Prefer the already installed EDB runtime DLL; do not replace OpenSSL
          # or any other PostgreSQL dependency with a third-party bundled copy.
          # The actual CREATE EXTENSION and SQL load below must establish ABI
          # compatibility; a missing/incompatible DLL fails the runtime gate.
          Write-Host "PREINSTALLED_PG_DEPENDENCY_KEPT=YES FILE=$($entry.Name)"
          continue
        }
        throw "Pre-existing PostgreSQL file collision: $dest"
      }
      continue
    }
    [IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($dest)) | Out-Null
    $read = $null; $write = $null
    try {
      $read = $entry.Open()
      $write = [IO.File]::Create($dest)
      $read.CopyTo($write)
    } finally {
      if ($write) { $write.Dispose() }
      if ($read) { $read.Dispose() }
    }
    $staged[$category] += 1
  }
} finally {
  $archive.Dispose()
}
if ($staged.lib -lt 2 -or $staged.share -lt 4) {
  throw "Missing core runtime DLL/SQL staged files: $($staged | ConvertTo-Json -Compress)"
}
Write-Host "OSGEO_WINDOWS_LAYOUT=PASS LIB_DLL=$($staged.lib) BIN_DLL=$($staged.bin) SHARE_FILES=$($staged.share)"
# The bin/postgisgui/ tree is excluded from this server-only staging.
# This EDB libcurl substitute is proven only for the tested PG18 host.
$effectiveCurlSha = (Get-FileHash -LiteralPath $effectiveCurl -Algorithm SHA256).Hash.ToLowerInvariant()
if ($effectiveCurlSha -cne $preinstalledCurlSha) {
  throw 'Original PostgreSQL libcurl.dll was replaced'
}
Write-Host "OSGEO_RUNTIME_CURL_SUBSTITUTION=EDB_PREINSTALLED_PRESERVED SHA256=$effectiveCurlSha GUI_TREE_STAGED=NO"
Write-Host "BUNDLE_LICENSE_NOTICE_PATHS=$($licenseFiles.Count) FILES=$($licenseFiles -join ';')"
Write-Host 'BUNDLE_LICENSE_CLOSURE=NOT_YET_VERIFIED REDISTRIBUTION=DENY'

# Actual PE import table inspection, in addition to executed SQL load.
$vswhere = Join-Path ([Environment]::GetFolderPath('ProgramFilesX86')) 'Microsoft Visual Studio/Installer/vswhere.exe'
if (-not (Test-Path -LiteralPath $vswhere)) { throw 'vswhere absent' }
$vsroot = (& $vswhere -latest -property installationPath | Out-String).Trim()
$dumpbin = @(Get-ChildItem -LiteralPath (Join-Path $vsroot 'VC/Tools/MSVC') -Filter dumpbin.exe -File -Recurse |
  Where-Object { $_.FullName -match 'Hostx64[\\/]x64[\\/]dumpbin[.]exe$' })
if ($dumpbin.Count -lt 1) { throw 'x64 dumpbin absent' }
$native = @(
  Get-ChildItem -LiteralPath $pkglib -Filter 'postgis-3.dll' -File;
  Get-ChildItem -LiteralPath $pkglib -Filter '*pgrouting*.dll' -File
)
if ($native.Count -lt 2) { throw 'PostGIS and pgRouting principal DLLs missing' }
foreach ($dll in $native) {
  $deps = @(& $dumpbin[0].FullName /DEPENDENTS $dll.FullName)
  if ($LASTEXITCODE -ne 0) { throw "Static import audit failed: $($dll.Name)" }
  $imports = @($deps | ForEach-Object {
    if ($_ -match '^\s*([A-Za-z0-9_.-]+[.]dll)\s*$') { $matches[1].ToLowerInvariant() }
  } | Sort-Object -Unique)
  if ($imports.Count -lt 1) { throw "No static dependencies enumerated for $($dll.Name)" }
  Write-Host "WINDOWS_PE_IMPORTS=OBSERVED DLL=$($dll.Name) NAMES=$($imports -join ',')"
}
Write-Host 'STATIC_IMPORTS=OBSERVED DYNAMIC_DEPENDENCY_CLOSURE=NOT_YET_VERIFIED'
$curlImportsRaw = @(& $dumpbin[0].FullName /DEPENDENTS $effectiveCurl)
if ($LASTEXITCODE -ne 0) { throw 'Installed EDB libcurl import audit failed' }
$curlImports = @($curlImportsRaw | ForEach-Object {
  if ($_ -match '^\s*([A-Za-z0-9_.-]+[.]dll)\s*$') { $matches[1].ToLowerInvariant() }
} | Sort-Object -Unique)
if ($curlImports.Count -lt 1) { throw 'EDB libcurl has no enumerated static imports' }
$referencesNghttp2 = [bool]($curlImports -contains 'libnghttp2-14.dll')
Write-Host "EDB_LIBCURL_STATIC_IMPORTS=OBSERVED REFERENCES_NGHTTP2=$referencesNghttp2 NAMES=$($curlImports -join ',')"
Write-Host 'SERVER_SCOPE_GUI_ICU_GAIL=EXCLUDED ORIGINAL_BUNDLE_GUI_COMPLETENESS=NOT_VERIFIED'

$data = Join-Path $env:RUNNER_TEMP 'osgeo-pg18-data'
$log = Join-Path $env:RUNNER_TEMP 'osgeo-pg18-server.log'
$initdb = Join-Path $bin 'initdb.exe'
$ctl = Join-Path $bin 'pg_ctl.exe'
$psql = Join-Path $bin 'psql.exe'
$port = 55449
$started = $false
try {
  & $initdb -D $data -A trust -U postgres --no-instructions
  if ($LASTEXITCODE -ne 0) { throw 'initdb failed' }
  & $ctl -D $data -l $log -o "-h 127.0.0.1 -p $port" -w start
  if ($LASTEXITCODE -ne 0) { throw 'Disposable PG18 startup failed' }
  $started = $true
  $ps = @('-X','-A','-t','-v','ON_ERROR_STOP=1',
          '-h','127.0.0.1','-p',[string]$port,'-U','postgres','-d','postgres')
  & $psql @ps -c 'CREATE EXTENSION postgis;'
  if ($LASTEXITCODE -ne 0) { throw 'CREATE EXTENSION postgis failed' }
  & $psql @ps -c 'CREATE EXTENSION pgrouting;'
  if ($LASTEXITCODE -ne 0) { throw 'CREATE EXTENSION pgrouting failed' }
  $versions = (& $psql @ps -c "SELECT extname || '=' || extversion FROM pg_extension WHERE extname IN ('postgis','pgrouting') ORDER BY extname;" | Out-String).Trim()
  if ($LASTEXITCODE -ne 0 -or $versions -notmatch 'postgis=3[.]7[.]0' -or $versions -notmatch 'pgrouting=[0-9]+[.]') {
    throw "Unexpected installed extension versions: $versions"
  }
  $postgisSQL = (& $psql @ps -c "SELECT CASE WHEN ST_Distance(ST_GeomFromText('POINT(0 0)'), ST_GeomFromText('POINT(3 4)'))=5 THEN 'PASS' ELSE 'FAIL' END;" | Out-String).Trim()
  if ($LASTEXITCODE -ne 0 -or $postgisSQL -cne 'PASS') { throw "PostGIS spatial SQL failed: $postgisSQL" }
  $routeQuery = "SELECT id, source, target, cost, reverse_cost FROM (VALUES (1,1,2,1.0::float8,1.0::float8),(2,2,3,1.0::float8,1.0::float8),(3,1,3,5.0::float8,5.0::float8)) AS edges(id,source,target,cost,reverse_cost)"
  $routingSQL = (& $psql @ps -c "SELECT CASE WHEN (SELECT MAX(agg_cost) FROM pgr_dijkstra('$routeQuery', 1, 3, true))=2 THEN 'PASS' ELSE 'FAIL' END;" | Out-String).Trim()
  if ($LASTEXITCODE -ne 0 -or $routingSQL -cne 'PASS') { throw "pgRouting dijkstra SQL failed: $routingSQL" }
  Write-Host "OSGEO_PG18_REAL_SQL=PASS POSTGIS=3.7.0 PGR_VERSION=$versions GEOMETRY_DISTANCE=PASS DIJKSTRA=PASS"
} catch {
  Write-Host "OSGEO_PG18_REAL_SQL=FAIL DETAIL=$($_.Exception.Message)"
  if (Test-Path -LiteralPath $log) { Get-Content -LiteralPath $log -Tail 70 | ForEach-Object { Write-Host $_ } }
  throw
} finally {
  if ($started) {
    & $ctl -D $data -m immediate -w stop
    if ($LASTEXITCODE -ne 0) { Write-Warning 'Disposable PG18 shutdown failed' }
  }
}
Write-Host 'OSGEO_CANDIDATE_ONLY=YES SIGNED_GET=DENY PUBLIC_CLI_DOWNLOAD=DENY MIRROR=DENY RELEASE=DENY'
