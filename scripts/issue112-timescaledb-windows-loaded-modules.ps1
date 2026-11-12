# Issue #112: sample actual loaded modules in disposable PostgreSQL while reusing
# the existing genuine original TimescaleDB Windows SQL test. NONPUBLISHING ONLY.
[CmdletBinding()]
param([Parameter(Mandatory=$true)][ValidateSet(16,17,18)][int]$Major)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false
if ($env:GITHUB_ACTIONS -cne 'true' -or $env:GITHUB_REPOSITORY -cne 'pgextwin/catalog' -or
    $env:RUNNER_OS -cne 'Windows' -or -not $env:PGROOT -or -not $env:RUNNER_TEMP) {
    throw 'DENY: ephemeral pgextwin/catalog Windows runner and PGROOT required'
}
$pg = [string]$Major
$bin = Join-Path ([IO.Path]::GetFullPath($env:PGROOT)) 'bin'
$targetExe = Join-Path $bin 'postgres.exe'
if (-not (Test-Path -LiteralPath $targetExe -PathType Leaf)) { throw 'Expected postgres.exe missing' }
$dir = Join-Path $env:RUNNER_TEMP "issue112-loaded-modules-pg$pg"
if (Test-Path -LiteralPath $dir) { throw 'Create-only receipt directory already exists' }
New-Item -ItemType Directory -Path $dir -ErrorAction Stop | Out-Null
$stop = Join-Path $dir 'stop'
$raw = Join-Path $dir 'module-paths.json'
$importsFile = Join-Path $dir 'imports.json'
$runtimeFile = Join-Path $dir 'live.json'
$job = $null
try {
    $importsText = & python scripts/issue112_timescaledb_pe_imports.py --pg $pg
    if ($LASTEXITCODE -ne 0) { throw 'Pinned original per-DLL import check failed' }
    $jsonLines = @($importsText | Where-Object { $_ -is [string] -and $_.StartsWith('{') })
    if ($jsonLines.Count -ne 1) { throw 'Expected exactly one original JSON evidence record' }
    Set-Content -LiteralPath $importsFile -Value $jsonLines[0] -Encoding utf8
    $static = Get-Content -LiteralPath $importsFile -Raw | ConvertFrom-Json
    if (-not $static.allImportTablesParsed) { throw 'Original PE import tables are not all parsed' }
    $interesting = [System.Collections.Generic.HashSet[string]]::new(
        [StringComparer]::OrdinalIgnoreCase)
    foreach ($r in $static.unbundledImportTriage) { [void]$interesting.Add([string]$r.name) }
    foreach ($r in $static.dllImportReceipts) {
        [void]$interesting.Add([IO.Path]::GetFileName([string]$r.path))
    }
    # The same pinned installer and actual SQL execution are run unchanged,
    # while a separate read-only process sampler collects module paths.
    $job = Start-Job -ArgumentList $targetExe, $stop, $raw -ScriptBlock {
        param($expectedExe, $stopPath, $outPath)
        $seen = [System.Collections.Generic.HashSet[string]]::new(
            [StringComparer]::OrdinalIgnoreCase)
        $pids = [System.Collections.Generic.HashSet[int]]::new()
        $errors = 0
        for ($i = 0; $i -lt 1800; $i++) {
            if (Test-Path -LiteralPath $stopPath) { break }
            try {
                $ps = @(Get-CimInstance Win32_Process -Filter "name='postgres.exe'" -ErrorAction Stop)
                foreach ($p in $ps) {
                    if (-not $p.ExecutablePath -or
                        -not [string]::Equals([string]$p.ExecutablePath,
                                              [string]$expectedExe,
                                              [StringComparison]::OrdinalIgnoreCase)) {
                        continue
                    }
                    [void]$pids.Add([int]$p.ProcessId)
                    try {
                        foreach ($m in (Get-Process -Id $p.ProcessId -ErrorAction Stop).Modules) {
                            if ($m.FileName) { [void]$seen.Add([string]$m.FileName) }
                        }
                    } catch { $errors++ }
                }
            } catch { $errors++ }
            Start-Sleep -Milliseconds 200
        }
        $receipt = [ordered]@{
            sampledProcessCount = $pids.Count
            moduleEnumerationErrors = $errors
            paths = @($seen)
        }
        $receipt | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $outPath -Encoding utf8
    }
    # Existing genuine original SQL path is not modified or replaced.
    & ./scripts/issue112-timescaledb-windows-runtime.ps1 -Major $Major
    if ($LASTEXITCODE -ne 0) { throw 'Original Windows PostgreSQL SQL test failed' }
} finally {
    Set-Content -LiteralPath $stop -Value 'stop'
    if ($null -ne $job) {
        $completed = $job | Wait-Job -Timeout 40
        if ($null -eq $completed) { $job | Stop-Job -ErrorAction SilentlyContinue }
        $job | Receive-Job | Out-Host
        $job | Remove-Job -Force -ErrorAction SilentlyContinue
    }
}
try {
    if (-not (Test-Path -LiteralPath $raw -PathType Leaf)) { throw 'Module sampler did not complete' }
    $sample = Get-Content -LiteralPath $raw -Raw | ConvertFrom-Json
    $rows = @()
    foreach ($path in @($sample.paths)) {
        $name = [IO.Path]::GetFileName([string]$path).ToLowerInvariant()
        if (-not $interesting.Contains($name)) { continue }
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { continue }
        $digest = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
        $signature = try {
            [string](Get-AuthenticodeSignature -LiteralPath $path).Status
        } catch { 'UNREADABLE' }
        $rows += [ordered]@{
            name = $name; path = [string]$path
            sha256 = $digest; authenticodeStatus = $signature
        }
    }
    $report = [ordered]@{
        pgMajor = $pg
        sampledProcessCount = [int]$sample.sampledProcessCount
        modules = @($rows)
    }
    $report | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $runtimeFile -Encoding utf8
    & python scripts/issue112_timescaledb_windows_loaded_modules.py --pg $pg --imports $importsFile --runtime $runtimeFile
    if ($LASTEXITCODE -ne 0) { throw 'Live process receipt join failed' }
} finally {
    Remove-Item -LiteralPath $dir -Recurse -Force -ErrorAction SilentlyContinue
}
Write-Host 'NONPUBLISHING_ORIGINAL_RUNTIME_OBSERVATION=YES RIGHTS=UNVERIFIED PRODUCER_ATTESTATION=UNVERIFIED SIGNED_ADMISSION=DENY PUBLIC_GET=DENY MIRROR=DENY RELEASE=DENY PUBLISH=DENY'
