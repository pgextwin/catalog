# Issue #112: provider-original pgvector PG16 native Windows smoke; CANDIDATE_ONLY.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false
if ($env:GITHUB_ACTIONS -cne 'true' -or $env:RUNNER_OS -cne 'Windows' -or
    $env:GITHUB_REPOSITORY -cne 'pgextwin/catalog' -or
    -not $env:RUNNER_TEMP -or -not $env:PGROOT) {
  throw 'Only disposable authenticated GitHub Windows CI is permitted'
}

$repo='portalcorp/pgvector_compiled'
$tag='v0.16.105'
$name='pgvector-x86_64-pc-windows-msvc-pg16.zip'
$sourceUrl="https://github.com/$repo/releases/download/$tag/$name"
$expectedSha='a9c63a3e51c09c18f192277a28be3fb021f3872a7cc2d23e4ca06e10f2c99571'
$provider=gh api --method GET "repos/$repo" | ConvertFrom-Json
if ($LASTEXITCODE -ne 0 -or $provider.id -ne 835861704 -or
    $provider.full_name -cne $repo) { throw 'Provider identity changed' }
$ref=gh api --method GET "repos/$repo/git/ref/tags/$tag" | ConvertFrom-Json
if ($LASTEXITCODE -ne 0 -or $ref.object.type -cne 'commit' -or
    $ref.object.sha -cne '76256aa2eeda43a8ccb017f3e4431a4a921d3374') {
  throw 'Source tag identity changed'
}
$release=gh api --method GET "repos/$repo/releases/tags/$tag" | ConvertFrom-Json
$assets=@($release.assets | Where-Object { $_.name -ceq $name })
if ($LASTEXITCODE -ne 0 -or $release.id -ne 182821763 -or
    $release.tag_name -cne $tag -or $release.draft -ne $false -or
    $release.prerelease -ne $false -or $assets.Count -ne 1 -or
    $assets[0].id -ne 203009337 -or $assets[0].size -ne 163732 -or
    $assets[0].browser_download_url -cne $sourceUrl -or
    $assets[0].state -cne 'uploaded' -or $assets[0].digest) {
  throw 'Original provider Release/asset identity changed'
}

$pgroot=[IO.Path]::GetFullPath($env:PGROOT).TrimEnd([IO.Path]::DirectorySeparatorChar)
$pgconfig=Join-Path $pgroot 'bin/pg_config.exe'
if (-not (Test-Path -LiteralPath $pgconfig)) { throw 'PG16 pg_config.exe absent' }
$ver=(& $pgconfig --version | Out-String).Trim()
if ($LASTEXITCODE -ne 0 -or $ver -notmatch '^PostgreSQL 16(?:[.]|\s)') {
  throw "Wrong EDB PG16 runtime: $ver"
}
$lib=(& $pgconfig --pkglibdir | Out-String).Trim()
$share=(& $pgconfig --sharedir | Out-String).Trim()
foreach ($dest in @($lib, $share)) {
  $canonical=[IO.Path]::GetFullPath($dest)
  if (-not $canonical.StartsWith($pgroot+[IO.Path]::DirectorySeparatorChar,
                                [StringComparison]::OrdinalIgnoreCase)) {
    throw 'pg_config points outside disposable PGROOT'
  }
}
$zip=Join-Path $env:RUNNER_TEMP 'issue112-portalcorp-original-pg16.zip'
try {
  Invoke-WebRequest -Uri $sourceUrl -OutFile $zip -MaximumRedirection 3 -TimeoutSec 90
  if ((Get-Item -LiteralPath $zip).Length -ne 163732) {
    throw 'Actual provider-original size drift'
  }
  $actual=(Get-FileHash -LiteralPath $zip -Algorithm SHA256).Hash.ToLowerInvariant()
  if ($actual -cne $expectedSha) { throw 'Original SHA256 drift' }
  python scripts/issue112_portalcorp_windows_private.py --original "$zip" --pkglibdir "$lib" --sharedir "$share"
  if ($LASTEXITCODE -ne 0) { throw 'Shared ZIP auditor or vetted staging failed' }
  Write-Output "PORTALCORP_ORIGINAL_PG16_HASH=PASS BYTES=163732 SHA256=$actual"
} finally {
  Remove-Item -LiteralPath $zip -Force -ErrorAction SilentlyContinue
}

$vswhere=Join-Path ([Environment]::GetFolderPath('ProgramFilesX86')) 'Microsoft Visual Studio/Installer/vswhere.exe'
if (-not (Test-Path -LiteralPath $vswhere)) { throw 'Dependency inspection tool absent' }
$vsroot=(& $vswhere -latest -property installationPath | Out-String).Trim()
$dumpbin=Get-ChildItem -LiteralPath (Join-Path $vsroot 'VC/Tools/MSVC') -Filter dumpbin.exe -Recurse -File |
  Where-Object { $_.FullName -match 'Hostx64[\\/]x64[\\/]dumpbin[.]exe$' } |
  Select-Object -First 1
if (-not $dumpbin) { throw 'AMD64 dumpbin unavailable' }
$dependencies=@(& $dumpbin.FullName /DEPENDENTS (Join-Path $lib 'vector.dll'))
if ($LASTEXITCODE -ne 0 -or $dependencies.Count -eq 0) {
  throw 'PE import audit failed'
}
Write-Output "PORTALCORP_PG16_PE_IMPORTS=INSPECTED TRANSITIVE_DEPENDENCIES=NOT_FULLY_VERIFIED"

$bin=Join-Path $pgroot 'bin'
$data=Join-Path $env:RUNNER_TEMP 'issue112-portalcorp-pg16-data'
$log=Join-Path $env:RUNNER_TEMP 'issue112-portalcorp-pg16.log'
$initdb=Join-Path $bin 'initdb.exe'
$ctl=Join-Path $bin 'pg_ctl.exe'
$psql=Join-Path $bin 'psql.exe'
$started=$false
try {
  & $initdb -D $data -A trust -U postgres --no-instructions
  if ($LASTEXITCODE -ne 0) { throw 'Disposable PG16 initdb failed' }
  & $ctl -D $data -l $log -o '-h 127.0.0.1 -p 55447' -w start
  if ($LASTEXITCODE -ne 0) { throw 'Disposable PG16 start failed' }
  $started=$true
  $args=@('-X','-A','-t','-v','ON_ERROR_STOP=1','-h','127.0.0.1',
          '-p','55447','-U','postgres','-d','postgres')
  & $psql @args -c 'CREATE EXTENSION vector;'
  if ($LASTEXITCODE -ne 0) { throw 'Actual provider DLL CREATE EXTENSION failed' }
  $installed=(& $psql @args -c "SELECT extversion FROM pg_extension WHERE extname='vector';" | Out-String).Trim()
  if ($LASTEXITCODE -ne 0 -or $installed -cne '0.8.0') {
    throw "Installed pgvector version mismatch: $installed"
  }
  & $psql @args -c "CREATE TABLE issue112_vectors (id integer PRIMARY KEY, embedding vector(3)); INSERT INTO issue112_vectors VALUES (1, '[1,2,3]'),(2,'[4,5,6]'); CREATE INDEX issue112_vectors_hnsw ON issue112_vectors USING hnsw (embedding vector_l2_ops);"
  if ($LASTEXITCODE -ne 0) { throw 'Actual pgvector HNSW functional setup failed' }
  $found=(& $psql @args -c "SELECT id FROM issue112_vectors ORDER BY embedding <-> '[1,2,3]'::vector LIMIT 1;" | Out-String).Trim()
  if ($LASTEXITCODE -ne 0 -or $found -cne '1') {
    throw "Actual pgvector distance result mismatch: $found"
  }
  Write-Output 'PORTALCORP_PG16_ACTUAL_WINDOWS_SQL=PASS CREATE_EXTENSION=YES VERSION=0.8.0 HNSW=PASS VECTOR_DISTANCE=PASS'
  Write-Output 'CANDIDATE_ONLY=YES GET_AUTHORIZED=NO MIRROR=DENY REDISTRIBUTION=DENY'
} finally {
  if ($started) {
    & $ctl -D $data -m immediate -w stop | Out-Null
    if ($LASTEXITCODE -ne 0) { Write-Warning 'Disposable PostgreSQL stop failed' }
  }
}
