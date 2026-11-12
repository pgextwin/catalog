[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][ValidateSet(14,15,16,17,18)][int]$Major,
    [Parameter(Mandatory = $true)][string]$UpstreamDir,
    [Parameter(Mandatory = $true)][string]$BuildTools
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# This is a disposable native MSVC/runtime pilot. No output is published,
# uploaded, signed, mirrored, or admitted into the public CLI.
$edb = @{
    14 = '14.24.0'; 15 = '15.19.0'; 16 = '16.15.5'
    17 = '17.11.4'; 18 = '18.6.5'
}
$port = 15449
$runTemp = $env:RUNNER_TEMP
if ([string]::IsNullOrWhiteSpace($runTemp)) { throw 'Runner temp unavailable' }
$source = (Resolve-Path $UpstreamDir).Path
$installer = Join-Path $BuildTools 'scripts/install-postgresql.ps1'
if (-not (Test-Path $installer)) { throw 'Missing fixed PostgreSQL installer' }

python scripts/issue112_pg_show_plans_native_pilot.py --source $source --msvc-adapt
if ($LASTEXITCODE -ne 0) { throw 'Exact signed-tag source-pin verification failed' }

& $installer -Major $Major -ChocolateyPackage "postgresql$Major" -ChocolateyVersion $edb[$Major] -TestPort $port
if (-not $env:PGROOT -or -not (Test-Path (Join-Path $env:PGROOT 'include/server/postgres.h'))) {
    throw 'Disposable PostgreSQL C server headers missing'
}
$pgRoot = $env:PGROOT
$vswhere = Join-Path ([Environment]::GetFolderPath('ProgramFilesX86')) 'Microsoft Visual Studio/Installer/vswhere.exe'
if (-not (Test-Path $vswhere)) { throw 'MSVC discovery tool missing' }
$vs = @(& $vswhere -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath |
    Select-Object -First 1)
if (-not $vs -or -not $vs[0].Trim()) { throw 'MSVC x64 toolchain missing' }
$devCmd = Join-Path $vs[0].Trim() 'Common7/Tools/VsDevCmd.bat'
if (-not (Test-Path $devCmd)) { throw 'VsDevCmd unavailable' }

$exports = @('Pg_magic_func', '_PG_init', 'pg_show_plans', 'pg_finfo_pg_show_plans')
$def = Join-Path $runTemp 'pg_show_plans-private.def'
@('LIBRARY pg_show_plans','EXPORTS') + ($exports | ForEach-Object { "    $_" }) |
    Set-Content -Path $def -Encoding ascii
$dll = Join-Path $runTemp 'pg_show_plans.dll'
$obj = Join-Path $runTemp 'pg_show_plans.obj'
$sourceFile = Join-Path $source 'pg_show_plans.c'
$buildCmd = Join-Path $runTemp 'pg-show-plans-private-build.cmd'
@"
@echo off
call "$devCmd" -arch=x64 -host_arch=x64 >nul
if errorlevel 1 exit /b %errorlevel%
cl /nologo /O2 /MD /DWIN32 /DWIN32_NO_STATUS /D_CRT_SECURE_NO_WARNINGS ^
 /I"$pgRoot\include\server\port\win32_msvc" ^
 /I"$pgRoot\include\server\port\win32" ^
 /I"$pgRoot\include\server" /I"$pgRoot\include" ^
 /c "$sourceFile" /Fo"$obj"
if errorlevel 1 exit /b %errorlevel%
link /nologo /DLL /OUT:"$dll" /DEF:"$def" ^
 "$obj" "$pgRoot\lib\postgres.lib" "$pgRoot\lib\libintl.lib"
if errorlevel 1 exit /b %errorlevel%
dumpbin /nologo /exports "$dll"
if errorlevel 1 exit /b %errorlevel%
"@ | Set-Content -Path $buildCmd -Encoding ascii
$buildLog = @(& cmd.exe /d /c $buildCmd 2>&1)
$buildLog | ForEach-Object { Write-Host "$_" }
if ($LASTEXITCODE -ne 0 -or -not (Test-Path $dll)) { throw 'Pinned native MSVC DLL compile/link failed' }
$exportDump = $buildLog -join [Environment]::NewLine
foreach ($name in $exports) {
    if ($exportDump -notmatch "(?m)\b$([regex]::Escape($name))\b") {
        throw "Required Windows DLL export absent: $name"
    }
}
$majorOut = (Get-Item $dll).Length
if ($majorOut -lt 1000) { throw 'Implausibly small MSVC binary' }
Write-Host ("PG{0}_PRIVATE_DLL_BYTES={1} SHA256={2}" -f $Major,$majorOut,(Get-FileHash $dll -Algorithm SHA256).Hash.ToLowerInvariant())

# Create-only, deterministic private ZIP; verify exact contents and reinstall
# from the validated ZIP rather than from a loose build-tree DLL. No upload.
$privateZip = Join-Path $runTemp "pg_show_plans-v2.1.8-pg$Major-private.zip"
$privateStage = Join-Path $runTemp "pg_show_plans-private-stage-pg$Major"
python scripts/issue112_pg_show_plans_private_package.py --mode create --source $source --dll $dll --major $Major --zip $privateZip
if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $privateZip)) {
    throw 'Private Windows ZIP packaging failed'
}
python scripts/issue112_pg_show_plans_private_package.py --mode verify-and-stage --source $source --dll $dll --major $Major --zip $privateZip --stage $privateStage
if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath (Join-Path $privateStage 'LICENSE'))) {
    throw 'Private ZIP independent source/DLL/rights rehash or extraction failed'
}

$extensionDir = Join-Path $pgRoot 'share/extension'
$libDir = Join-Path $pgRoot 'lib'
$zipExtensionDir = Join-Path $privateStage 'share/extension'
Copy-Item -LiteralPath (Join-Path $privateStage 'lib/pg_show_plans.dll') -Destination (Join-Path $libDir 'pg_show_plans.dll') -Force
Copy-Item -LiteralPath (Join-Path $zipExtensionDir 'pg_show_plans.control') -Destination $extensionDir -Force
$sql = @(Get-ChildItem -LiteralPath $zipExtensionDir -Filter 'pg_show_plans--*.sql' -File)
if ($sql.Count -ne 4) { throw 'Unexpected private ZIP install SQL count' }
foreach ($file in $sql) { Copy-Item -LiteralPath $file.FullName -Destination $extensionDir -Force }

$initdb = Join-Path $pgRoot 'bin/initdb.exe'
$pgCtl = Join-Path $pgRoot 'bin/pg_ctl.exe'
$psql = Join-Path $pgRoot 'bin/psql.exe'
$pgData = Join-Path $runTemp "issue112-pg-show-plans-$Major"
$pgLog = Join-Path $runTemp "issue112-pg-show-plans-$Major.log"
if (Test-Path $pgData) { throw 'Refuse to overwrite existing cluster' }
$serverStarted = $false
try {
    & $initdb -D $pgData -U postgres -A trust --encoding=UTF8 --no-locale
    if ($LASTEXITCODE -ne 0) { throw 'initdb failed' }
    & $pgCtl -D $pgData -l $pgLog -o "-p $port -c shared_preload_libraries=pg_show_plans" start
    if ($LASTEXITCODE -ne 0) { throw 'Preloaded extension failed to start PostgreSQL' }
    $serverStarted = $true

    $setup = @(& $psql -h 127.0.0.1 -p $port -U postgres -d postgres -X -Atq -v ON_ERROR_STOP=1 -c 'CREATE EXTENSION pg_show_plans; SELECT CASE WHEN extversion = ''2.1'' THEN 1 ELSE 0 END FROM pg_extension WHERE extname = ''pg_show_plans'';')
    if ($LASTEXITCODE -ne 0 -or '1' -notin $setup) { throw 'CREATE EXTENSION or SQL default-version check failed' }

    $load = @(& $psql -h 127.0.0.1 -p $port -U postgres -d postgres -X -Atq -v ON_ERROR_STOP=1 -c 'SHOW shared_preload_libraries;')
    if ($LASTEXITCODE -ne 0 -or 'pg_show_plans' -notin $load) { throw 'Expected shared preload not active' }

    # Invoke both extension C function and SQL wrapper in the real server.
    $plans = @(& $psql -h 127.0.0.1 -p $port -U postgres -d postgres -X -Atq -v ON_ERROR_STOP=1 -c 'SELECT count(*) FROM pg_show_plans(); SELECT count(*) FROM pg_show_plans_q;')
    $invalidPlans = @($plans | Where-Object { $_ -notmatch '^\d+$' })
    if ($LASTEXITCODE -ne 0 -or $plans.Count -lt 2 -or $invalidPlans.Count -gt 0) {
        throw 'PostgreSQL did not execute pg_show_plans C/SQL functions'
    }
    Write-Host "PG$Major=PASS MSVC=PASS PRELOAD=PASS SQL=PASS PUBLIC_GET=DENY MIRROR=DENY RELEASE=DENY PUBLISH=DENY"
}
catch {
    if (Test-Path $pgLog) { Get-Content $pgLog -Tail 150 | ForEach-Object { Write-Host "$_" } }
    throw
}
finally {
    if ($serverStarted) {
        & $pgCtl -D $pgData -m immediate stop
    }
}
