# Issue #112: Windows runner nonpublishing, pinned original-asset inspection.
# pgvector also runs on a disposable PostgreSQL 18 database; Oracle client
# is intentionally neither downloaded nor redistributed.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false

if (-not $env:RUNNER_TEMP -or -not $env:PGROOT) {
    throw 'Use only an ephemeral Windows CI runner with validated PGROOT'
}
$root = [IO.Path]::GetFullPath($env:PGROOT)
$pgConfig = Join-Path $root 'bin/pg_config.exe'
if (-not (Test-Path -LiteralPath $pgConfig)) { throw 'PostgreSQL binary missing' }
$ver = (& $pgConfig --version | Out-String).Trim()
if ($LASTEXITCODE -ne 0 -or $ver -notmatch '^PostgreSQL 18(?:[.]|\s)') {
    throw "Wrong PostgreSQL installation: $ver"
}
Add-Type -AssemblyName System.IO.Compression

$specs = @(
    @{
        Kind = 'oracle_fdw'
        Repository = 'laurenz/oracle_fdw'
        AssetId = 442625860
        Url = 'https://github.com/laurenz/oracle_fdw/releases/download/ORACLE_FDW_2_9_0/oracle_fdw-2.9.0-pg18-win64.zip'
        Bytes = 365101
        Sha256 = 'ad1fc057888b89f968de34f14bd7088c2b05d674a8df4b40ba47ed772c317678'
    },
    @{
        Kind = 'pgvector'
        Repository = 'andreiramani/pgvector_pgsql_windows'
        AssetId = 661612613
        Url = 'https://github.com/andreiramani/pgvector_pgsql_windows/releases/download/0.8.7/vector.v0.8.7-pg18.zip'
        Bytes = 174796
        Sha256 = '7c4ae0e2b2cb1e547779209a34a7d3f05b82fd7912818bf3d7042266eda87e7d'
    }
)

function Get-PinnedPackage([hashtable]$spec) {
    $uri = [Uri]$spec.Url
    if ($uri.Scheme -cne 'https' -or $uri.Host -cne 'github.com' -or
        -not $uri.AbsolutePath.StartsWith("/$($spec.Repository)/releases/download/", [StringComparison]::Ordinal)) {
        throw 'Original provider URL mismatch'
    }
    $file = Join-Path $env:RUNNER_TEMP ("issue112-" + $spec.Kind + "-original.zip")
    Invoke-WebRequest -Uri $spec.Url -OutFile $file -MaximumRedirection 3 -TimeoutSec 90
    $size = (Get-Item -LiteralPath $file).Length
    $hash = (Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($size -ne $spec.Bytes -or $hash -cne $spec.Sha256) {
        throw "$($spec.Kind): original bytes do not match pinned asset"
    }
    Write-Host "ORIGINAL_BYTES=PASS SOURCE=$($spec.Repository) ASSET=$($spec.AssetId) SHA256=$hash"
    return $file
}

function Inspect-Package([string]$file, [string]$extensionName) {
    $archive = [IO.Compression.ZipFile]::OpenRead($file)
    try {
        if ($archive.Entries.Count -lt 3 -or $archive.Entries.Count -gt 200) {
            throw 'Invalid ZIP member count'
        }
        $names = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        $byLeaf = @{}
        [long]$expanded = 0
        foreach ($entry in $archive.Entries) {
            $name = $entry.FullName
            if (-not $name -or $name.StartsWith('/') -or $name.Contains('\') -or
                $name.Contains(':') -or $name -match '(^|/)[.][.]?(/|$)' -or
                -not $names.Add($name)) {
                throw "Unsafe or duplicate ZIP path: $name"
            }
            $expanded += $entry.Length
            if ($expanded -gt 10000000 -or $entry.Length -gt (200 * [Math]::Max(1, $entry.CompressedLength))) {
                throw 'Unsafe ZIP expanded length'
            }
            if ($entry.Name -eq '') { continue }
            $leaf = $entry.Name
            if ($leaf -match '^(vector|oracle_fdw)([.]dll|[.]control|--.+[.]sql)$') {
                if ($byLeaf.ContainsKey($leaf.ToLowerInvariant())) {
                    throw "Duplicate extension payload: $leaf"
                }
                $byLeaf[$leaf.ToLowerInvariant()] = $entry
            }
        }
        if (-not $byLeaf.ContainsKey("$extensionName.dll") -or
            -not $byLeaf.ContainsKey("$extensionName.control") -or
            @($byLeaf.Keys | Where-Object { $_ -like "$extensionName--*.sql" }).Count -lt 1) {
            throw "Missing core extension DLL/control/SQL: $extensionName"
        }
        Write-Host "WINDOWS_PACKAGE_LAYOUT=PASS EXTENSION=$extensionName ENTRIES=$($archive.Entries.Count) EXPANDED=$expanded FILES=$($byLeaf.Count)"
        # Stage allowlisted files only. Never recursively extract unknown paths,
        # rename/repackage third-party binaries, or upload the original ZIP.
        if ($extensionName -eq 'vector') {
            foreach ($key in $byLeaf.Keys) {
                $targetDir = if ($key -eq 'vector.dll') {
                    Join-Path $root 'lib'
                } else {
                    Join-Path $root 'share/extension'
                }
                $target = Join-Path $targetDir $key
                if (Test-Path -LiteralPath $target) {
                    throw "Refuse to overwrite pre-existing extension file: $target"
                }
                $inputStream = $byLeaf[$key].Open()
                $outputStream = $null
                try {
                    $outputStream = [IO.File]::Create($target)
                    $inputStream.CopyTo($outputStream)
                } finally {
                    if ($outputStream) { $outputStream.Dispose() }
                    $inputStream.Dispose()
                }
            }
        }
    } finally {
        $archive.Dispose()
    }
}

# Official Oracle ZIP: structural evidence only. OCI runtime is not installed,
# and this is explicitly NOT an oracle_fdw runtime/ABI success.
Inspect-Package (Get-PinnedPackage $specs[0]) 'oracle_fdw'
Write-Host 'ORACLE_FDW=STRUCTURAL_ONLY OCI_CLIENT=NOT_INSTALLED ABI=NOT_APPROVED'

# Unofficial community ZIP: test actual PostgreSQL 18 Windows load and SQL.
Inspect-Package (Get-PinnedPackage $specs[1]) 'vector'
$data = Join-Path $env:RUNNER_TEMP 'pgextwin-issue112-pg18-data'
$log = Join-Path $env:RUNNER_TEMP 'pgextwin-issue112-pg18.log'
$port = 55443
$bin = Join-Path $root 'bin'
$initdb = Join-Path $bin 'initdb.exe'
$ctl = Join-Path $bin 'pg_ctl.exe'
$psql = Join-Path $bin 'psql.exe'
$started = $false
try {
    & $initdb -D $data -A trust -U postgres --no-instructions
    if ($LASTEXITCODE -ne 0) { throw 'initdb failed' }
    & $ctl -D $data -l $log -o "-h 127.0.0.1 -p $port" -w start
    if ($LASTEXITCODE -ne 0) { throw 'PostgreSQL server start failed' }
    $started = $true
    $common = @('-X', '-A', '-t', '-v', 'ON_ERROR_STOP=1',
                '-h', '127.0.0.1', '-p', [string]$port,
                '-U', 'postgres', '-d', 'postgres')
    & $psql @common -c 'CREATE EXTENSION vector;'
    if ($LASTEXITCODE -ne 0) { throw 'CREATE EXTENSION vector failed' }
    $loaded = (& $psql @common -c "SELECT extversion FROM pg_extension WHERE extname='vector';" | Out-String).Trim()
    if ($LASTEXITCODE -ne 0 -or $loaded -ne '0.8.7') {
        throw "Wrong pgvector extension version: $loaded"
    }
    $probe = (& $psql @common -c "SELECT CASE WHEN ('[1,2,3]'::vector <-> '[1,2,3]'::vector) = 0 THEN 'PASS' ELSE 'FAIL' END;" | Out-String).Trim()
    if ($LASTEXITCODE -ne 0 -or $probe -ne 'PASS') { throw "pgvector SQL operation failed: $probe" }
    Write-Host "PGVECTOR_PG18_WINDOWS_RUNTIME=PASS VERSION=$loaded SQL_VECTOR_DISTANCE=PASS"
} finally {
    if ($started) {
        & $ctl -D $data -m immediate -w stop
        if ($LASTEXITCODE -ne 0) { Write-Warning 'Disposable test server stop failed' }
    }
}
Write-Host 'PGEXTWIN_EXTERNAL_DOWNLOAD_AUTHORIZED=NO MIRROR_AUTHORIZED=NO PUBLICATION=DENY'
