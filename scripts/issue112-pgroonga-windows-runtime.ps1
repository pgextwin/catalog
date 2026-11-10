# Issue #112: exact upstream PGroonga Windows ZIP runtime qualification.
# No mirror, artifact upload, public GET admission, signing or publication.
[CmdletBinding()]
param([Parameter(Mandatory=$true)][ValidateSet(14,15,16,17,18)][int]$Major)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false

if ($env:GITHUB_ACTIONS -cne 'true' -or $env:GITHUB_REPOSITORY -cne 'pgextwin/catalog' -or
    $env:RUNNER_OS -cne 'Windows' -or -not $env:RUNNER_TEMP -or -not $env:PGROOT) {
    throw 'Requires ephemeral pgextwin/catalog GitHub Windows CI and PGROOT'
}
$pg = [string]$Major
$pins = @{
    '14' = @{ bytes=53806600; sha='39d2685f234c8b45563f57f113bd8c84cc1ae4e8c0c22e6826bf168ba1c0ab39' }
    '15' = @{ bytes=53863529; sha='fbc73734028b0b2372a6ee6538863999c2f9f06ec9f1be633ac460c7d8a0d4f1' }
    '16' = @{ bytes=53751780; sha='40c71f7890e6ceb46f79fdc10e596da21bfb622f7c9d1f8be7784175d96df7e8' }
    '17' = @{ bytes=53836587; sha='dcbd356ab8a7c8fc3a3cc7082b4f99a1884b5a68674e25ef4bbe56583c38147b' }
    '18' = @{ bytes=53826667; sha='3ccbfaf771ec7a0edf61dabe0eb60188dcc22feff8449a7e96afdb87641630ab' }
}
$pin = $pins[$pg]
$root = [IO.Path]::GetFullPath($env:PGROOT).TrimEnd('\')
$bin = Join-Path $root 'bin'
$config = Join-Path $bin 'pg_config.exe'
$pgVersion = (& $config --version | Out-String).Trim()
if ($LASTEXITCODE -ne 0 -or $pgVersion -notmatch ('^PostgreSQL\s+' + $pg + '(?:\.|\s)')) {
    throw "Installed PostgreSQL major mismatch: $pgVersion"
}
$filename = "pgroonga-4.1.0-postgresql-$pg-x64.zip"
$url = "https://github.com/pgroonga/pgroonga/releases/download/4.1.0/$filename"
$original = Join-Path $env:RUNNER_TEMP $filename
try {
    & curl.exe --fail --silent --show-error --location --max-redirs 3 --proto '=https' --proto-redir '=https' --retry 2 --max-time 150 --max-filesize $pin.bytes --output $original $url
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $original -PathType Leaf)) {
        throw 'Official PGroonga original ZIP GET failed'
    }
    $size = (Get-Item -LiteralPath $original).Length
    if ($size -ne $pin.bytes) { throw "Original ZIP size mismatch: $size" }
    $sha = (Get-FileHash -LiteralPath $original -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($sha -cne $pin.sha) { throw "Original ZIP SHA256 mismatch: $sha" }
    Write-Host "PGROONGA_ORIGINAL_WINDOWS_BYTES=PASS PG=$pg SIZE=$size SHA256=$sha"

    Add-Type -AssemblyName System.IO.Compression
    $archive = [IO.Compression.ZipFile]::OpenRead($original)
    $count = 0
    $expanded = [long]0
    $staged = 0
    try {
        foreach ($entry in $archive.Entries) {
            $count++
            if ($count -gt 20000) { throw 'ZIP entry cap exceeded' }
            $expanded += [long]$entry.Length
            if ($expanded -gt 1073741824) { throw 'ZIP expanded byte cap exceeded' }
            $name = $entry.FullName.Replace('\','/')
            if ($name.StartsWith('/') -or $name.Contains(':') -or
                $name -match '(^|/)\.\.?(/|$)' -or
                $name -match '[\x00-\x1f]' -or
                ($entry.ExternalAttributes -shr 16 -band 61440) -eq 40960) {
                throw "Unsafe ZIP entry: $name"
            }
            if ($name.EndsWith('/')) { continue }
            $first = $name.Split('/')[0].ToLowerInvariant()
            # Upstream package is a PostgreSQL tree; omit root documentation.
            if ($first -notin @('bin','lib','share','include')) { continue }
            $destination = [IO.Path]::GetFullPath((Join-Path $root $name.Replace('/','\')))
            if (-not $destination.StartsWith($root + '\', [StringComparison]::OrdinalIgnoreCase)) {
                throw "ZIP escaped PGROOT: $name"
            }
            if (Test-Path -LiteralPath $destination) {
                # Never replace PostgreSQL's own runtime DLLs. Actual SQL must
                # prove compatibility with the retained EDB host dependencies.
                if ($first -ne 'bin') { throw "Existing non-bin target collision: $name" }
                Write-Host "EDB_BIN_PREEXISTING_PRESERVED=$name"
                continue
            }
            [IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($destination)) | Out-Null
            $read = $null
            $write = $null
            try {
                $read = $entry.Open()
                $write = [IO.File]::CreateNew($destination)
                $read.CopyTo($write)
            } finally {
                if ($write) { $write.Dispose() }
                if ($read) { $read.Dispose() }
            }
            $staged++
        }
    } finally {
        $archive.Dispose()
    }
    if ($staged -lt 5 -or
        -not (Test-Path -LiteralPath (Join-Path $root 'lib\pgroonga.dll')) -or
        -not (Test-Path -LiteralPath (Join-Path $root 'share\extension\pgroonga.control'))) {
        throw "PGroonga extension payload not staged: $staged"
    }
    Write-Host "PGROONGA_ZIP_STAGED=PASS PG=$pg ENTRIES=$count FILES=$staged EXPANDED=$expanded"
} finally {
    Remove-Item -LiteralPath $original -Force -ErrorAction SilentlyContinue
}

$data = Join-Path $env:RUNNER_TEMP "pgroonga-issue112-pg$pg-data"
$log = Join-Path $env:RUNNER_TEMP "pgroonga-issue112-pg$pg.log"
$initdb = Join-Path $bin 'initdb.exe'
$ctl = Join-Path $bin 'pg_ctl.exe'
$psql = Join-Path $bin 'psql.exe'
$started = $false
try {
    & $initdb -D $data -A trust -U postgres --no-instructions
    if ($LASTEXITCODE -ne 0) { throw 'initdb failed' }
    & $ctl -D $data -l $log -o '-h 127.0.0.1 -p 55452' -w start
    if ($LASTEXITCODE -ne 0) { throw 'PostgreSQL startup failed' }
    $started = $true
    $common = @('-X','-A','-t','-v','ON_ERROR_STOP=1','-h','127.0.0.1','-p','55452','-U','postgres','-d','postgres')
    & $psql @common -c 'CREATE EXTENSION pgroonga;'
    if ($LASTEXITCODE -ne 0) { throw 'CREATE EXTENSION pgroonga failed' }
    $version = (& $psql @common -c "SELECT extversion FROM pg_extension WHERE extname='pgroonga';" | Out-String).Trim()
    if ($LASTEXITCODE -ne 0 -or $version -cne '4.1.0') { throw "Wrong installed extension version: $version" }
    & $psql @common -c "CREATE TABLE issue112_pgroonga_probe(id int, content text); INSERT INTO issue112_pgroonga_probe VALUES (1,'hello world'),(2,'goodbye'),(3,'hello moon'); CREATE INDEX issue112_pgroonga_idx ON issue112_pgroonga_probe USING pgroonga (content);"
    if ($LASTEXITCODE -ne 0) { throw 'PGroonga index creation failed' }
    $query = "SELECT COUNT(*) FROM issue112_pgroonga_probe WHERE content &@ 'hello';"
    $found = (& $psql @common -c $query | Out-String).Trim()
    if ($LASTEXITCODE -ne 0 -or $found -cne '2') { throw "PGroonga indexed search failed: $found" }
    & $psql @common -c 'SET enable_seqscan=off; EXPLAIN SELECT * FROM issue112_pgroonga_probe WHERE content &@ ''hello'';'
    if ($LASTEXITCODE -ne 0) { throw 'PGroonga index planner smoke failed' }
    Write-Host "PGROONGA_WINDOWS_REAL_SQL=PASS PG=$pg VERSION=$version CREATE_EXTENSION=PASS INDEX_CREATE=PASS SEARCH=PASS"
} catch {
    Write-Host "PGROONGA_WINDOWS_REAL_SQL=FAIL PG=$pg DETAIL=$($_.Exception.Message)"
    if (Test-Path -LiteralPath $log) { Get-Content -LiteralPath $log -Tail 80 | ForEach-Object { Write-Host $_ } }
    throw
} finally {
    if ($started) {
        & $ctl -D $data -m immediate -w stop
        if ($LASTEXITCODE -ne 0) { Write-Warning 'Disposable PostgreSQL shutdown failed' }
    }
}
Write-Host 'CANDIDATE_ONLY=YES SIGNED_PUBLIC_GET=DENY MIRROR=DENY ARTIFACT_UPLOAD=NONE RELEASE=DENY'
