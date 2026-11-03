# Nonpublishing Oracle OCI load smoke: official oracle_fdw 2.9.0 + OCI Basic Light.
# No Oracle server/credentials/remote DB access, Release, mirror, or upload.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false
if (-not $env:RUNNER_TEMP -or -not $env:PGROOT -or -not $IsWindows) {
    throw 'Disposable Windows runner and PGROOT required'
}
$root = [IO.Path]::GetFullPath($env:PGROOT)
$bin = Join-Path $root 'bin'
$ver = (& (Join-Path $bin 'pg_config.exe') --version | Out-String).Trim()
if ($LASTEXITCODE -ne 0 -or $ver -notmatch '^PostgreSQL 18(?:[.]|\s)') {
    throw "Wrong PostgreSQL environment: $ver"
}
Add-Type -AssemblyName System.IO.Compression

function Get-Original([string]$url, [string]$name, [long]$size, [string]$digest) {
    $uri = [Uri]$url
    if ($uri.Scheme -cne 'https' -or
        $uri.Host -cnotin @('github.com', 'download.oracle.com') -or
        $uri.UserInfo -or $uri.Query -or $uri.Fragment) {
        throw 'Unapproved provider URL'
    }
    $file = Join-Path $env:RUNNER_TEMP $name
    if (Test-Path -LiteralPath $file) { throw 'Refuse to reuse ZIP' }
    Invoke-WebRequest -Uri $url -OutFile $file -MaximumRedirection 3 -TimeoutSec 180
    $actualSize = (Get-Item -LiteralPath $file).Length
    $actualHash = (Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actualSize -ne $size -or $actualHash -cne $digest) {
        throw "Wrong original provider bytes: $name"
    }
    Write-Host "ORIGINAL_SHA256=PASS FILE=$name HASH=$actualHash"
    return $file
}

# Official SHA256 from Oracle's published Windows x64 Basic Light download page.
# Use under Oracle's own license for ephemeral testing; never redistribute OCI.
$ociPackage = Get-Original -url 'https://download.oracle.com/otn_software/nt/instantclient/2326400/instantclient-basiclite-windows.x64-23.26.4.0.0.zip' -name 'issue112-oci-original.zip' -size 60406433 -digest '7586c02a2926f619a0b16a9ae32e85bb3605798aa177155b065fffb48a1ee0b8'
$clientDir = Join-Path $env:RUNNER_TEMP 'issue112-oci'
if (Test-Path -LiteralPath $clientDir) { throw 'Refuse OCI reuse' }
$ociArchive = [IO.Compression.ZipFile]::OpenRead($ociPackage)
try {
    if ($ociArchive.Entries.Count -lt 5 -or $ociArchive.Entries.Count -gt 1500) {
        throw 'Unexpected OCI package layout'
    }
    $seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    [long]$expanded = 0
    foreach ($entry in $ociArchive.Entries) {
        $name = $entry.FullName
        if (-not $name -or $name.StartsWith('/') -or $name.Contains('\') -or
            $name.Contains(':') -or $name -match '(^|/)[.][.]?(/|$)' -or
            -not $seen.Add($name)) { throw 'Unsafe OCI ZIP path' }
        $expanded += $entry.Length
        if ($expanded -gt 1000000000) { throw 'OCI expanded size too large' }
    }
} finally {
    $ociArchive.Dispose()
}
[IO.Compression.ZipFile]::ExtractToDirectory($ociPackage, $clientDir)
$oci = @(Get-ChildItem -LiteralPath $clientDir -Recurse -File -Filter 'oci.dll')
if ($oci.Count -ne 1) { throw 'Expected one OCI client DLL' }
$env:PATH = "$($oci[0].DirectoryName);$bin;$env:PATH"
Write-Host 'OCI=OFFICIAL_HASHED_BASIC_LIGHT DISTRIBUTION=NONE'

$fdwPackage = Get-Original -url 'https://github.com/laurenz/oracle_fdw/releases/download/ORACLE_FDW_2_9_0/oracle_fdw-2.9.0-pg18-win64.zip' -name 'issue112-oracle-fdw-original.zip' -size 365101 -digest 'ad1fc057888b89f968de34f14bd7088c2b05d674a8df4b40ba47ed772c317678'
$archive = [IO.Compression.ZipFile]::OpenRead($fdwPackage)
try {
    if ($archive.Entries.Count -ne 10) { throw 'Changed oracle_fdw ZIP layout' }
    $files = @{}
    $names = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    [long]$total = 0
    foreach ($entry in $archive.Entries) {
        $name = $entry.FullName
        if (-not $name -or $name.StartsWith('/') -or $name.Contains('\') -or
            $name.Contains(':') -or $name -match '(^|/)[.][.]?(/|$)' -or
            -not $names.Add($name)) { throw 'Unsafe oracle_fdw ZIP path' }
        $total += $entry.Length
        if ($total -gt 10000000) { throw 'oracle_fdw ZIP too large' }
        if ($entry.Name -cmatch '^oracle_fdw(?:[.]dll|[.]control|--[0-9].*[.]sql)$') {
            $key = $entry.Name.ToLowerInvariant()
            if ($files.ContainsKey($key)) { throw 'Duplicate extension payload' }
            $files[$key] = $entry
        }
    }
    if ($files.Count -ne 5 -or -not $files.ContainsKey('oracle_fdw.dll') -or
        -not $files.ContainsKey('oracle_fdw.control') -or
        @($files.Keys | Where-Object { $_ -like 'oracle_fdw--*.sql' }).Count -lt 1) {
        throw 'Missing oracle_fdw DLL/control/SQL'
    }
    foreach ($key in $files.Keys) {
        $dir = if ($key -eq 'oracle_fdw.dll') { 'lib' } else { 'share/extension' }
        $dest = Join-Path (Join-Path $root $dir) $key
        if (Test-Path -LiteralPath $dest) { throw 'Refuse overwrite' }
        $stream = $files[$key].Open()
        $out = $null
        try {
            $out = [IO.File]::Create($dest)
            $stream.CopyTo($out)
        } finally {
            if ($out) { $out.Dispose() }
            $stream.Dispose()
        }
    }
} finally {
    $archive.Dispose()
}

# Local PostgreSQL only; no Oracle CREATE SERVER, connection or credentials.
$data = Join-Path $env:RUNNER_TEMP 'issue112-oracle-pg18-data'
$log = Join-Path $env:RUNNER_TEMP 'issue112-oracle-pg18.log'
$ctl = Join-Path $bin 'pg_ctl.exe'
$psql = Join-Path $bin 'psql.exe'
$started = $false
try {
    & (Join-Path $bin 'initdb.exe') -D $data -A trust -U postgres --no-instructions
    if ($LASTEXITCODE -ne 0) { throw 'initdb failed' }
    & $ctl -D $data -l $log -o '-h 127.0.0.1 -p 55445' -w start
    if ($LASTEXITCODE -ne 0) { throw 'pg_ctl failed' }
    $started = $true
    $opts = @('-X', '-A', '-t', '-v', 'ON_ERROR_STOP=1',
        '-h', '127.0.0.1', '-p', '55445', '-U', 'postgres', '-d', 'postgres')
    & $psql @opts -c 'CREATE EXTENSION oracle_fdw;'
    if ($LASTEXITCODE -ne 0) { throw 'CREATE EXTENSION failed' }
    $installed = (& $psql @opts -c "SELECT extname FROM pg_extension WHERE extname='oracle_fdw';" | Out-String).Trim()
    if ($LASTEXITCODE -ne 0 -or $installed -ne 'oracle_fdw') {
        throw 'oracle_fdw not installed'
    }
    # The no-argument diagnostic does not connect to a remote Oracle server.
    $diag = (& $psql @opts -c 'SELECT oracle_diag();' | Out-String).Trim()
    if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($diag)) {
        throw 'OCI diagnostic failed'
    }
    Write-Host 'ORACLE_FDW_PG18_LOAD=PASS OCI=PASS REMOTE_ORACLE_DB=NOT_TESTED'
} finally {
    if ($started) {
        & $ctl -D $data -m immediate -w stop
        if ($LASTEXITCODE -ne 0) { Write-Warning 'Disposable shutdown failed' }
    }
}
Write-Host 'DOWNLOAD_AUTHORIZED=NO MIRROR=NO RELEASE=NO PUBLICATION=DENY'
