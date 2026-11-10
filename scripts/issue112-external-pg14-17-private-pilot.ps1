# Issue #112: PG14-17 newest upstream original ZIPs, private Windows pilot only.
# pgvector also runs on each disposable PostgreSQL major; Oracle client
# is intentionally neither downloaded nor redistributed.
[CmdletBinding()]
param([Parameter(Mandatory=$true)][ValidateSet(14,15,16,17)][int]$Major)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false

if ($env:GITHUB_ACTIONS -cne 'true' -or $env:GITHUB_REPOSITORY -cne 'pgextwin/catalog' -or
    $env:RUNNER_OS -cne 'Windows' -or -not $env:RUNNER_TEMP -or -not $env:PGROOT) {
    throw 'Use only an ephemeral Windows CI runner with validated PGROOT'
}
$root = [IO.Path]::GetFullPath($env:PGROOT)
$pgConfig = Join-Path $root 'bin/pg_config.exe'
if (-not (Test-Path -LiteralPath $pgConfig)) { throw 'PostgreSQL binary missing' }
$ver = (& $pgConfig --version | Out-String).Trim()
if ($LASTEXITCODE -ne 0 -or $ver -notmatch "^PostgreSQL $Major(?:[.]|\s)") {
    throw "Wrong PostgreSQL installation: $ver"
}
Add-Type -AssemblyName System.IO.Compression

$pins = @{
    '14' = @(
        @{
            Kind = 'oracle_fdw'
            Repository = 'laurenz/oracle_fdw'
            RepositoryId = 14332609
            ReleaseId = 335861225
            ReleaseTag = 'ORACLE_FDW_2_9_0'
            AssetId = 442625883
            AssetName = 'oracle_fdw-2.9.0-pg14-win64.zip'
            Bytes = 375533
            Sha256 = '91a9857041c3e78981f4f554fa03cb606ff8cd0347b7cc3e3604b215f9655b2d'
        },
        @{
            Kind = 'pgvector'
            Repository = 'andreiramani/pgvector_pgsql_windows'
            RepositoryId = 838202416
            ReleaseId = 419235203
            ReleaseTag = '0.8.7'
            AssetId = 661612126
            AssetName = 'vector.v0.8.7-pg14.zip'
            Bytes = 174619
            Sha256 = '51dd3626905d31509e06552d16ddcc8eda2ac47d1e84eb923d2aff9207716ee7'
        }
    )
    '15' = @(
        @{
            Kind = 'oracle_fdw'
            Repository = 'laurenz/oracle_fdw'
            RepositoryId = 14332609
            ReleaseId = 335861225
            ReleaseTag = 'ORACLE_FDW_2_9_0'
            AssetId = 442625869
            AssetName = 'oracle_fdw-2.9.0-pg15-win64.zip'
            Bytes = 363671
            Sha256 = '3894a25a80cf2d3ac672894ba5cbcbc11c9533ad72cd25d31235285b73182f7a'
        },
        @{
            Kind = 'pgvector'
            Repository = 'andreiramani/pgvector_pgsql_windows'
            RepositoryId = 838202416
            ReleaseId = 419235203
            ReleaseTag = '0.8.7'
            AssetId = 661612214
            AssetName = 'vector.v0.8.7-pg15.zip'
            Bytes = 174667
            Sha256 = '33562f2d2bab702a7d6f68b7d53c98e52480eb039c6635164d6b4cfcfdf40cc9'
        }
    )
    '16' = @(
        @{
            Kind = 'oracle_fdw'
            Repository = 'laurenz/oracle_fdw'
            RepositoryId = 14332609
            ReleaseId = 335861225
            ReleaseTag = 'ORACLE_FDW_2_9_0'
            AssetId = 442625866
            AssetName = 'oracle_fdw-2.9.0-pg16-win64.zip'
            Bytes = 365436
            Sha256 = 'b9e8826d11c794c03bd49874100712f2ee446a01294b4c1d3632053bbaee8290'
        },
        @{
            Kind = 'pgvector'
            Repository = 'andreiramani/pgvector_pgsql_windows'
            RepositoryId = 838202416
            ReleaseId = 419235203
            ReleaseTag = '0.8.7'
            AssetId = 661612305
            AssetName = 'vector.v0.8.7-pg16.zip'
            Bytes = 174594
            Sha256 = '69dee8f237966a5b87ec109ec8ed619613432940a8e6150a1d0da627fc0f2f7e'
        }
    )
    '17' = @(
        @{
            Kind = 'oracle_fdw'
            Repository = 'laurenz/oracle_fdw'
            RepositoryId = 14332609
            ReleaseId = 335861225
            ReleaseTag = 'ORACLE_FDW_2_9_0'
            AssetId = 442625846
            AssetName = 'oracle_fdw-2.9.0-pg17-win64.zip'
            Bytes = 371386
            Sha256 = 'a67d0582e855ef5a1099039528cfdfd25b7e31938dab29c5bfb0366d0a368fc7'
        },
        @{
            Kind = 'pgvector'
            Repository = 'andreiramani/pgvector_pgsql_windows'
            RepositoryId = 838202416
            ReleaseId = 419235203
            ReleaseTag = '0.8.7'
            AssetId = 661612406
            AssetName = 'vector.v0.8.7-pg17.zip'
            Bytes = 174653
            Sha256 = 'acd9d678200e856623f0b7416f6d132ef8606a2273ff37f0fdf8a7f2c5d7d2'
        }
    )
}
$specs = $pins[[string]$Major]
foreach ($spec in $specs) {
    $spec.Url = "https://github.com/$($spec.Repository)/releases/download/$($spec.ReleaseTag)/$($spec.AssetName)"
}

function Get-PinnedPackage([hashtable]$spec) {
    $uri = [Uri]$spec.Url
    if ($uri.Scheme -cne 'https' -or $uri.Host -cne 'github.com' -or
        -not $uri.AbsolutePath.StartsWith("/$($spec.Repository)/releases/download/", [StringComparison]::Ordinal)) {
        throw 'Original provider URL mismatch'
    }
    $provider = gh api --method GET "repos/$($spec.Repository)" | ConvertFrom-Json
    if ($LASTEXITCODE -ne 0 -or $provider.id -ne $spec.RepositoryId -or
        $provider.full_name -cne $spec.Repository) {
        throw 'Original provider identity changed'
    }
    $release = gh api --method GET "repos/$($spec.Repository)/releases/tags/$($spec.ReleaseTag)" | ConvertFrom-Json
    $assets = @($release.assets | Where-Object { $_.name -ceq $spec.AssetName })
    if ($LASTEXITCODE -ne 0 -or $release.id -ne $spec.ReleaseId -or
        $release.tag_name -cne $spec.ReleaseTag -or $release.draft -ne $false -or
        $release.prerelease -ne $false -or $assets.Count -ne 1 -or
        $assets[0].id -ne $spec.AssetId -or $assets[0].size -ne $spec.Bytes -or
        $assets[0].state -cne 'uploaded' -or
        $assets[0].browser_download_url -cne $spec.Url -or
        $assets[0].digest -cne ("sha256:" + $spec.Sha256)) {
        throw 'Original release/asset metadata or SHA256 identity changed'
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
                -not $names.Add($name) -or
                ((($entry.ExternalAttributes -shr 16) -band 0xF000) -eq 0xA000)) {
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
Write-Host "ORACLE_FDW=STRUCTURAL_ONLY PG=$Major OCI_CLIENT=NOT_INSTALLED ABI=NOT_APPROVED"

# Unofficial community ZIP: test actual PostgreSQL 18 Windows load and SQL.
Inspect-Package (Get-PinnedPackage $specs[1]) 'vector'
$data = Join-Path $env:RUNNER_TEMP "pgextwin-issue112-pg$Major-data"
$log = Join-Path $env:RUNNER_TEMP "pgextwin-issue112-pg$Major.log"
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
    Write-Host "PGVECTOR_WINDOWS_RUNTIME=PASS PG=$Major VERSION=$loaded SQL_VECTOR_DISTANCE=PASS"
} finally {
    if ($started) {
        & $ctl -D $data -m immediate -w stop
        if ($LASTEXITCODE -ne 0) { Write-Warning 'Disposable test server stop failed' }
    }
}
Write-Host "PGEXTWIN_EXTERNAL_PG${Major}_CANDIDATE_ONLY=YES ORIGINAL_ZIP_HASH=PASS GET_AUTHORIZED=NO MIRROR_AUTHORIZED=NO PUBLICATION=DENY"
