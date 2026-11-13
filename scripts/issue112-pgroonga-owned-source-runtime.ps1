# PG18 first-party PGroonga private source-owned build smoke; no provider ZIP.
[CmdletBinding()]
param([ValidateSet(18)][int]$Major = 18)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false

if ($env:GITHUB_ACTIONS -cne 'true' -or $env:GITHUB_REPOSITORY -cne 'pgextwin/catalog' -or
    $env:RUNNER_OS -cne 'Windows' -or -not $env:PGROOT -or -not $env:RUNNER_TEMP -or
    -not $env:PGEXTWIN_OWNED_PREFIX -or -not $env:GITHUB_WORKSPACE) {
    throw 'Owned-source smoke requires ephemeral pgextwin/catalog Windows Actions'
}
$root = [IO.Path]::GetFullPath($env:PGROOT).TrimEnd('\')
$prefix = [IO.Path]::GetFullPath($env:PGEXTWIN_OWNED_PREFIX).TrimEnd('\')
$temp = [IO.Path]::GetFullPath($env:RUNNER_TEMP).TrimEnd('\')
if ($prefix -ceq $root -or -not $prefix.StartsWith($temp + '\', [StringComparison]::OrdinalIgnoreCase)) {
    throw 'Source-owned output must remain within the ephemeral runner'
}
$src = Join-Path $env:GITHUB_WORKSPACE 'pinned-pgroonga'
if (-not (Test-Path -LiteralPath (Join-Path $src 'meson.build') -PathType Leaf)) {
    throw 'Missing immutable PGroonga input'
}
$head = (& git -C $src rev-parse HEAD | Out-String).Trim()
if ($LASTEXITCODE -ne 0 -or $head -cne '47d0252f76dccbdc2ebeee9ed6cf941dd9552bcc') {
    throw 'Wrong PGroonga source commit'
}
$bin = Join-Path $root 'bin'
$config = Join-Path $bin 'pg_config.exe'
$pgVersion = (& $config --version | Out-String).Trim()
if ($LASTEXITCODE -ne 0 -or $pgVersion -notmatch '^PostgreSQL 18([.]|\s)') {
    throw "Wrong PostgreSQL major: $pgVersion"
}
foreach ($required in @('bin\libgroonga.dll','lib\pgroonga.dll','share\extension\pgroonga.control')) {
    if (-not (Test-Path -LiteralPath (Join-Path $prefix $required) -PathType Leaf)) {
        throw "Missing newly compiled source-owned payload: $required"
    }
}
$installed = [System.Collections.Generic.List[string]]::new()
$staged = 0
try {
    foreach ($area in @('bin','lib','share','include')) {
        $from = Join-Path $prefix $area
        if (-not (Test-Path -LiteralPath $from -PathType Container)) { continue }
        $entries = @(Get-ChildItem -LiteralPath $from -File -Recurse -Force)
        if ($entries.Count -gt 25000) { throw 'Source-built output file cap' }
        foreach ($file in $entries) {
            if ($file.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Linked output denied' }
            $real = [IO.Path]::GetFullPath($file.FullName)
            if (-not $real.StartsWith($prefix + '\', [StringComparison]::OrdinalIgnoreCase)) {
                throw 'Compiled file escaped source-owned prefix'
            }
            $relative = $real.Substring($prefix.Length + 1)
            $destination = [IO.Path]::GetFullPath((Join-Path $root $relative))
            if (-not $destination.StartsWith($root + '\', [StringComparison]::OrdinalIgnoreCase)) {
                throw 'Compiled output path escaped PostgreSQL installation'
            }
            if (Test-Path -LiteralPath $destination) {
                if ($area -cne 'bin') { throw "Existing PostgreSQL target collision: $relative" }
                Write-Host "PRESERVE_EXISTING_EDB_BIN=$relative"
                continue
            }
            [IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($destination)) | Out-Null
            Copy-Item -LiteralPath $real -Destination $destination -ErrorAction Stop
            $installed.Add($destination)
            $staged++
        }
    }
    if ($staged -lt 15 -or
        -not (Test-Path -LiteralPath (Join-Path $root 'lib\pgroonga.dll') -PathType Leaf) -or
        -not (Test-Path -LiteralPath (Join-Path $root 'share\extension\pgroonga.control') -PathType Leaf)) {
        throw "Source-built PGroonga was not completely staged: $staged"
    }
    $data = Join-Path $temp 'pgroonga-owned-pg18-data'
    $log = Join-Path $temp 'pgroonga-owned-pg18.log'
    $ctl = Join-Path $bin 'pg_ctl.exe'
    $psql = Join-Path $bin 'psql.exe'
    $started = $false
    try {
        & (Join-Path $bin 'initdb.exe') -D $data -A trust -U postgres --no-instructions
        if ($LASTEXITCODE -ne 0) { throw 'initdb failed' }
        & $ctl -D $data -l $log -o '-h 127.0.0.1 -p 55463' -w start
        if ($LASTEXITCODE -ne 0) { throw 'Owned-source PostgreSQL startup failed' }
        $started = $true
        $conn = @('-X','-A','-t','-v','ON_ERROR_STOP=1','-h','127.0.0.1',
                  '-p','55463','-U','postgres','-d','postgres')
        & $psql @conn -c 'CREATE EXTENSION pgroonga;'
        if ($LASTEXITCODE -ne 0) { throw 'Owned-source CREATE EXTENSION failed' }
        $version = (& $psql @conn -c "SELECT extversion FROM pg_extension WHERE extname='pgroonga';" | Out-String).Trim()
        if ($LASTEXITCODE -ne 0 -or $version -cne '4.1.0') { throw "Wrong extension version: $version" }
        & $psql @conn -c "CREATE TABLE issue112_owned_probe(id int, content text); INSERT INTO issue112_owned_probe VALUES (1,'hello world'),(2,'goodbye'),(3,'hello moon'); CREATE INDEX issue112_owned_idx ON issue112_owned_probe USING pgroonga (content);"
        if ($LASTEXITCODE -ne 0) { throw 'Owned-source index failed' }
        $count = (& $psql @conn -c "SELECT count(*) FROM issue112_owned_probe WHERE content &@ 'hello';" | Out-String).Trim()
        if ($LASTEXITCODE -ne 0 -or $count -cne '2') { throw "Owned-source indexed search mismatch: $count" }
        Write-Host "PGROONGA_OWNED_SOURCE_WINDOWS_PG18=PASS VERSION=$version SEARCH=$count FILES=$staged"
        Write-Host 'COMPILER_TOOLCHAIN_ATTESTATION=DENY RIGHTS_NOTICE=DENY PUBLIC_GET=DENY MIRROR=DENY RELEASE=DENY'
    } finally {
        if ($started) {
            & $ctl -D $data -m immediate -w stop
            if ($LASTEXITCODE -ne 0) { Write-Warning 'Disposable server shutdown failed' }
        }
    }
} catch {
    Write-Host "PGROONGA_OWNED_SOURCE_WINDOWS_PG18=FAIL ERROR=$($_.Exception.Message)"
    if (Test-Path -LiteralPath (Join-Path $temp 'pgroonga-owned-pg18.log')) {
        Get-Content -LiteralPath (Join-Path $temp 'pgroonga-owned-pg18.log') -Tail 60
    }
    throw
} finally {
    foreach ($p in $installed) { Remove-Item -LiteralPath $p -ErrorAction SilentlyContinue }
}
