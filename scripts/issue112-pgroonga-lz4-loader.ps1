# Exact-original PGroonga 4.1.0 EDB liblz4 loader-path evidence only.
# Nonpublishing: never grants signed provider GET, ZIP upload, mirror or Release.
[CmdletBinding()]
param([Parameter(Mandatory=$true)][ValidateSet(14,15,16,17,18)][int]$Major, [switch]$SelfTest, [switch]$AuditModuleOrigins)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false

function Test-LoadedModuleSet {
    param([object[]]$Processes, [string]$PgModule, [string]$GroongaModule, [string]$Lz4Module)
    # All THREE full paths must be loaded in ONE process.
    foreach ($process in $Processes) {
        $paths = @($process.Modules | ForEach-Object { $_.FileName })
        $all = $true
        foreach ($target in @($PgModule, $GroongaModule, $Lz4Module)) {
            if (@($paths | Where-Object { [string]::Equals($_, $target, [StringComparison]::OrdinalIgnoreCase) }).Count -eq 0) {
                $all = $false
                break
            }
        }
        if ($all) { return $process.Id }
    }
    return $null
}


# One same-backend sampled DLL is not an exhaustive dynamic dependency proof.
function Review-ModuleOrigins {
    param([object[]]$Observed,[hashtable]$Original,[string]$PgRoot,[string]$HostLz4,[string]$HostSha)
    $required=@((Join-Path $PgRoot 'lib\pgroonga.dll'),(Join-Path $PgRoot 'bin\libgroonga.dll'))
    foreach($p in $required) {if(-not $Original.ContainsKey($p)){throw 'Missing exact original core receipt'}}
    $seen=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $counts=[ordered]@{exact=0;preservedHost=0;differentBytes=0;unmapped=0}
    $details=@()
    foreach($item in $Observed) {
        $path=[string]$item.path;$digest=[string]$item.sha256
        if(-not $path.StartsWith($PgRoot.TrimEnd('\')+'\',[StringComparison]::OrdinalIgnoreCase) -or
           $path -notmatch '(?i)[.]dll$' -or $digest -cnotmatch '^[0-9a-f]{64}$' -or
           -not $seen.Add($path)){throw 'Invalid or duplicate loaded DLL receipt'}
        if([string]::Equals($path,$HostLz4,[StringComparison]::OrdinalIgnoreCase)){
            if($digest -cne $HostSha){throw 'Preserved EDB LZ4 changed'}
            $status='PRESERVED_EDB_HOST_UNATTESTED';$counts.preservedHost++
        }elseif($Original.ContainsKey($path)){
            if($Original[$path] -ceq $digest){
                $status='EXACT_ORIGINAL_ZIP_MEMBER';$counts.exact++
            }else{
                $status='DIFFERENT_BYTES_HOST_COLLISION_UNVERIFIED';$counts.differentBytes++
            }
        }else{$status='UNMAPPED_HOST_NOT_ORIGINAL';$counts.unmapped++}
        if($path -in $required -and $status -cne 'EXACT_ORIGINAL_ZIP_MEMBER'){
            throw 'Core observed DLL differs from original bytes'
        }
        $details += [ordered]@{path=$path;sha256=$digest;originClass=$status}
    }
    foreach($p in @($required[0],$required[1],$HostLz4)){
        if(-not $seen.Contains($p)){throw 'Required root/host module not actually observed'}
    }
    return [ordered]@{
        schemaVersion='pgextwin-pgroonga-live-pg-dll-origins-deny-only/v1'
        originCounts=$counts;sampledPgDlls=$details
        originalDllMembersNotObserved=($Original.Count-$counts.exact)
        signedProducerInputsVerified=$false
        allPossibleDynamicDllsObserved=$false
        thirdPartyRightsAndNoticesVerified=$false
        ownerSignedAdmission=$false
        publicGetAuthorized=$false
        mirrorAuthorized=$false
        releaseAuthorized=$false
        publisherAuthorized=$false
    }
}


# PR #370 has 22 external static import *names*. This is only a same-PID
# module sample, never a claim of binding a particular PE import to a file.
function Review-ExternalImportSample {
    param([object[]]$Observed,[string]$PgRoot,[int]$BackendPid,[string]$HostLz4Sha)
    $groups=[ordered]@{
        WINDOWS_CRT_API_SET=@(
            'api-ms-win-crt-convert-l1-1-0.dll','api-ms-win-crt-environment-l1-1-0.dll',
            'api-ms-win-crt-filesystem-l1-1-0.dll','api-ms-win-crt-heap-l1-1-0.dll',
            'api-ms-win-crt-locale-l1-1-0.dll','api-ms-win-crt-math-l1-1-0.dll',
            'api-ms-win-crt-runtime-l1-1-0.dll','api-ms-win-crt-stdio-l1-1-0.dll',
            'api-ms-win-crt-string-l1-1-0.dll','api-ms-win-crt-time-l1-1-0.dll',
            'api-ms-win-crt-utility-l1-1-0.dll')
        WINDOWS_OS_IMAGE=@('advapi32.dll','dbghelp.dll','kernel32.dll','psapi.dll','ws2_32.dll')
        VC_RUNTIME_IMAGE=@('msvcp140.dll','vcomp140.dll','vcruntime140.dll','vcruntime140_1.dll')
        HOST_IMAGE=@('liblz4.dll')
        POSTGRES_IMAGE=@('postgres.exe')
    }
    $types=@{}
    foreach($type in $groups.Keys){
        foreach($name in $groups[$type]){
            if($types.ContainsKey($name)){throw 'Duplicate expected import name'}
            $types[$name]=$type
        }
    }
    if($types.Count -ne 22){throw 'Static import classification drift'}
    $images=@{}
    foreach($item in @($Observed)){
        $name=[string]$item.name
        $path=[string]$item.path
        $sha=[string]$item.sha256
        $status=[string]$item.authenticode
        if(-not $types.ContainsKey($name) -or $images.ContainsKey($name) -or
           [int]$item.pid -ne $BackendPid -or
           -not [IO.Path]::IsPathFullyQualified($path) -or
           $path -match '(?i)(^|\\)\.\.?\\' -or
           -not [string]::Equals([IO.Path]::GetFileName($path),$name,[StringComparison]::OrdinalIgnoreCase) -or
           $sha -cnotmatch '^[0-9a-f]{64}$' -or
           $status -cnotmatch '^[A-Za-z]{2,40}$'){
            throw 'Untrusted, duplicate, wrong-PID or incomplete module receipt'
        }
        $images[$name]=$item
    }
    foreach($required in @('liblz4.dll','postgres.exe')){
        if(-not $images.ContainsKey($required)){throw "Required same-PID image missing: $required"}
        $expectedPath=Join-Path $PgRoot ('bin\' + $required)
        if(-not [string]::Equals([string]$images[$required].path,$expectedPath,[StringComparison]::OrdinalIgnoreCase)){
            throw "Required same-PID image path mismatch: $required"
        }
    }
    if($images['liblz4.dll'].sha256 -cne $HostLz4Sha){throw 'EDB LZ4 SHA256 mismatch'}
    $entries=@();$physical=0;$missing=0
    foreach($name in @($types.Keys | Sort-Object)){
        $type=$types[$name];$found=$images.ContainsKey($name)
        $item=$null
        if($found){$item=$images[$name]}
        $observation=if($type -eq 'WINDOWS_CRT_API_SET'){
            'API_SET_CONTRACT_NOT_PHYSICAL_PATH_PROOF'
        }elseif($found){
            $physical++
            'SAME_BACKEND_MODULE_NAME_MATCH_NOT_DIRECT_IMPORT_PROOF'
        }else{
            $missing++
            'NOT_OBSERVED_IN_SAMPLED_BACKEND'
        }
        $entries += [ordered]@{
            name=$name;category=$type;observation=$observation
            imageObservedInSamePid=$found
            path=if($found){[string]$item.path}else{$null}
            sha256=if($found){[string]$item.sha256}else{$null}
            authenticodeStatus=if($found){[string]$item.authenticode}else{$null}
            exactPeImportBindingVerified=$false
            thirdPartyRightsVerified=$false
        }
    }
    return [ordered]@{
        schemaVersion='pgextwin-pgroonga-sampled-external-import-names-deny-only/v1'
        sampledBackendPid=$BackendPid
        externalImportNames=22
        virtualApiSetContracts=11
        sampledPhysicalNameMatches=$physical
        notSeenPhysicalNames=$missing
        perImport=$entries
        exactImportResolutionVerified=$false
        completeOptionalDynamicDependenciesVerified=$false
        binaryThirdPartyNoticeClosureVerified=$false
        signedProducerInputProvenanceVerified=$false
        ownerSignedAdmission=$false
        publicGetAuthorized=$false
        mirrorAuthorized=$false
        releaseAuthorized=$false
        publisherAuthorized=$false
    }
}

if ($SelfTest) {
    $one = [pscustomobject]@{ Id=5; Modules=@(
        [pscustomobject]@{ FileName='C:\pg\lib\pgroonga.dll' },
        [pscustomobject]@{ FileName='C:\pg\bin\libgroonga.dll' },
        [pscustomobject]@{ FileName='C:\pg\bin\liblz4.dll' }) }
    $wrong = [pscustomobject]@{ Id=6; Modules=@([pscustomobject]@{ FileName='C:\other\liblz4.dll' }) }
    $expect = @('C:\pg\lib\pgroonga.dll', 'C:\pg\bin\libgroonga.dll', 'C:\pg\bin\liblz4.dll')
    if ((Test-LoadedModuleSet -Processes @($one) -PgModule $expect[0] -GroongaModule $expect[1] -Lz4Module $expect[2]) -ne 5) { throw 'positive self-test failed' }
    if ($null -ne (Test-LoadedModuleSet -Processes @($one) -PgModule $expect[0] -GroongaModule $expect[1] -Lz4Module 'C:\other\liblz4.dll')) { throw 'wrong-path self-test failed' }
    if ($null -ne (Test-LoadedModuleSet -Processes @($one, $wrong) -PgModule $expect[0] -GroongaModule $expect[1] -Lz4Module 'C:\other\liblz4.dll')) { throw 'cross-process self-test failed' }

    $a='a'*64;$b='b'*64;$c='c'*64;$fake='C:\pg'
    $orig=@{'C:\pg\lib\pgroonga.dll'=$a;'C:\pg\bin\libgroonga.dll'=$b;'C:\pg\bin\extra.dll'=$c}
    $rows=@(
        [pscustomobject]@{path='C:\pg\lib\pgroonga.dll';sha256=$a},
        [pscustomobject]@{path='C:\pg\bin\libgroonga.dll';sha256=$b},
        [pscustomobject]@{path='C:\pg\bin\liblz4.dll';sha256=$c},
        [pscustomobject]@{path='C:\pg\bin\extra.dll';sha256=$a}
    )
    $positive=Review-ModuleOrigins -Observed $rows -Original $orig -PgRoot $fake -HostLz4 'C:\pg\bin\liblz4.dll' -HostSha $c
    if($positive.originCounts.exact -ne 2 -or $positive.originCounts.differentBytes -ne 1 -or
       $positive.originCounts.preservedHost -ne 1 -or $positive.publicGetAuthorized){
        throw 'Classifier positive control failed'
    }
    foreach($kind in @('root-hash','host-hash','duplicate','missing-host','foreign-path')){
        $altered=@($rows | ForEach-Object {[pscustomobject]@{path=$_.path;sha256=$_.sha256}})
        switch($kind){
            'root-hash' {$altered[0].sha256=$b}
            'host-hash' {$altered[2].sha256=$b}
            'duplicate' {$altered += $altered[0]}
            'missing-host' {$altered=@($altered | Where-Object {$_.path -ne 'C:\pg\bin\liblz4.dll'})}
            'foreign-path' {$altered[3].path='C:\outside\extra.dll'}
        }
        $denied=$false
        try{$null=Review-ModuleOrigins -Observed $altered -Original $orig -PgRoot $fake -HostLz4 'C:\pg\bin\liblz4.dll' -HostSha $c}catch{$denied=$true}
        if(-not $denied){throw "Forged sample accepted: $kind"}
    }
    $externalRows=@(
        [pscustomobject]@{name='liblz4.dll';path='C:\pg\bin\liblz4.dll';sha256=$c;authenticode='NotSigned';pid=5},
        [pscustomobject]@{name='postgres.exe';path='C:\pg\bin\postgres.exe';sha256=$a;authenticode='NotSigned';pid=5},
        [pscustomobject]@{name='kernel32.dll';path='C:\Windows\System32\kernel32.dll';sha256=$b;authenticode='Valid';pid=5}
    )
    $reviewExternal=Review-ExternalImportSample -Observed $externalRows -PgRoot $fake -BackendPid 5 -HostLz4Sha $c
    if($reviewExternal.externalImportNames -ne 22 -or $reviewExternal.virtualApiSetContracts -ne 11 -or
       $reviewExternal.sampledPhysicalNameMatches -ne 3 -or $reviewExternal.publicGetAuthorized -or
       @($reviewExternal.perImport | Where-Object {$_.exactPeImportBindingVerified}).Count -ne 0){
        throw 'External import positive control failed'
    }
    foreach($kind in @('wrong-pid','wrong-sha','wrong-lz4','missing-host','missing-exe','duplicate','unknown','traversal','wrong-exe')){
        $bad=@($externalRows | ForEach-Object {
            [pscustomobject]@{name=$_.name;path=$_.path;sha256=$_.sha256;authenticode=$_.authenticode;pid=$_.pid}
        })
        switch($kind){
            'wrong-pid' {$bad[2].pid=6}
            'wrong-sha' {$bad[2].sha256='invalid'}
            'wrong-lz4' {$bad[0].sha256=$b}
            'missing-host' {$bad=@($bad | Where-Object {$_.name -ne 'liblz4.dll'})}
            'missing-exe' {$bad=@($bad | Where-Object {$_.name -ne 'postgres.exe'})}
            'duplicate' {$bad+= $bad[0]}
            'unknown' {$bad[2].name='unlisted.dll'}
            'traversal' {$bad[2].path='C:\Windows\..\wrong\kernel32.dll'}
            'wrong-exe' {$bad[1].path='C:\other\postgres.exe'}
        }
        $rejected=$false
        try{$null=Review-ExternalImportSample -Observed $bad -PgRoot $fake -BackendPid 5 -HostLz4Sha $c}catch{$rejected=$true}
        if(-not $rejected){throw "Forged external import accepted: $kind"}
    }
    Write-Host 'PGROONGA_EXTERNAL_NAME_SAMPLE_OFFLINE=PASS HOSTILE_CASES=9 PUBLIC_GET=DENY'
    Write-Host 'PGROONGA_DLL_ORIGINS_OFFLINE=PASS HOSTILE_CASES=5 PUBLIC_GET=DENY'
    Write-Host 'PGROONGA_LZ4_MODULE_PAIR_OFFLINE=PASS PATH_AND_PID_REQUIRED=YES'
    return
}
if ($env:GITHUB_ACTIONS -cne 'true' -or $env:GITHUB_REPOSITORY -cne 'pgextwin/catalog' -or
    $env:RUNNER_OS -cne 'Windows' -or -not $env:RUNNER_TEMP -or -not $env:PGROOT) {
    throw 'Only ephemeral pgextwin/catalog Windows runner with pinned EDB PGROOT may execute'
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
$version = (& (Join-Path $bin 'pg_config.exe') --version | Out-String).Trim()
if ($LASTEXITCODE -ne 0 -or $version -notmatch ('^PostgreSQL\s+' + $pg + '(?:\.|\s)')) { throw "EDB major mismatch: $version" }
# EDB's own file must exist: never fetch or inject an unpinned LZ4 DLL.
$hostLz4 = Join-Path $bin 'liblz4.dll'
if (-not (Test-Path -LiteralPath $hostLz4 -PathType Leaf)) {
    throw "EDB_HOST_LZ4=ABSENT PG=$pg; real loader resolution remains unverified"
}
$before = (Get-FileHash -LiteralPath $hostLz4 -Algorithm SHA256).Hash.ToLowerInvariant()
$hostVersion = (Get-Item -LiteralPath $hostLz4).VersionInfo.FileVersion
$hostCompany = (Get-Item -LiteralPath $hostLz4).VersionInfo.CompanyName
$hostSignature = (Get-AuthenticodeSignature -FilePath $hostLz4).Status.ToString()
Write-Host "EDB_HOST_LZ4=OBSERVED PG=$pg FILE=$hostLz4 SHA256=$before FILE_VERSION=$hostVersion COMPANY=$hostCompany AUTHENTICODE=$hostSignature"

$name = "pgroonga-4.1.0-postgresql-$pg-x64.zip"
$url = "https://github.com/pgroonga/pgroonga/releases/download/4.1.0/$name"
$archivePath = Join-Path $env:RUNNER_TEMP $name
$zip = $null
try {
    & curl.exe --fail --silent --show-error --location --max-redirs 3 --proto '=https' --proto-redir '=https' --retry 2 --max-time 150 --max-filesize $pin.bytes --output $archivePath $url
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $archivePath -PathType Leaf)) { throw 'Pinned upstream GET failed' }
    if ((Get-Item -LiteralPath $archivePath).Length -ne $pin.bytes -or
        (Get-FileHash -LiteralPath $archivePath -Algorithm SHA256).Hash.ToLowerInvariant() -cne $pin.sha) {
        throw 'Exact official ZIP size/SHA256 mismatch'
    }
    Add-Type -AssemblyName System.IO.Compression
    $zip = [IO.Compression.ZipFile]::OpenRead($archivePath)
    $expanded = [long]0
    $seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $count = 0
    $copied = 0
    $originalDlls = @{}
    foreach ($entry in $zip.Entries) {
        $count++
        if ($count -gt 20000) { throw 'ZIP member count cap exceeded' }
        $expanded += [long]$entry.Length
        if ($expanded -gt 1073741824) { throw 'ZIP expansion cap exceeded' }
        $rel = $entry.FullName.Replace('\','/')
        if (-not $rel -or $rel.StartsWith('/') -or $rel.Contains(':') -or
            $rel -match '(^|/)\.\.?(/|$)' -or $rel -match '[\x00-\x1f]' -or
            ($entry.ExternalAttributes -shr 16 -band 61440) -eq 40960 -or
            -not $seen.Add($rel)) { throw "Unsafe/colliding ZIP path: $rel" }
        if ($rel.EndsWith('/')) { continue }
        $first = $rel.Split('/')[0].ToLowerInvariant()
        if ($first -notin @('bin','lib','share','include')) { continue }
        $target = [IO.Path]::GetFullPath((Join-Path $root $rel.Replace('/','\')))
        if (-not $target.StartsWith($root + '\', [StringComparison]::OrdinalIgnoreCase)) { throw 'Unsafe ZIP extraction target' }

        if($AuditModuleOrigins -and $rel -match '(?i)^(bin|lib)/.*[.]dll$'){
            if($originalDlls.ContainsKey($target)){throw 'Duplicate original DLL target'}
            $originalStream=$entry.Open()
            $digest=[Security.Cryptography.SHA256]::Create()
            try{$originalDlls[$target]=[Convert]::ToHexString($digest.ComputeHash($originalStream)).ToLowerInvariant()}
            finally{$originalStream.Dispose();$digest.Dispose()}
        }
        if (Test-Path -LiteralPath $target) {
            if ($first -ne 'bin') { throw "Host collision outside bin: $rel" }
            if ($rel -ieq 'bin/libgroonga.dll') { throw 'Competing host libgroonga.dll' }
            continue # never overwrite host PostgreSQL DLLs
        }
        [IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($target)) | Out-Null
        $inputStream = $null
        $outputStream = $null
        try {
            $inputStream = $entry.Open()
            $outputStream = [IO.File]::Open($target, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
            $inputStream.CopyTo($outputStream)
        } finally {
            if ($outputStream) { $outputStream.Dispose() }
            if ($inputStream) { $inputStream.Dispose() }
        }
        $copied++
    }
    if ($copied -lt 5 -or -not (Test-Path -LiteralPath (Join-Path $root 'lib\pgroonga.dll')) -or
        -not (Test-Path -LiteralPath (Join-Path $root 'bin\libgroonga.dll'))) { throw 'Original DLL staging failed' }
    if ((Get-FileHash -LiteralPath $hostLz4 -Algorithm SHA256).Hash.ToLowerInvariant() -cne $before) {
        throw 'Host liblz4 changed during original staging'
    }
    Write-Host "PGROONGA_EXACT_ORIGINAL_STAGED=PASS PG=$pg ZIP_SHA256=$($pin.sha) COUNT=$count COPIED=$copied"
} finally {
    if ($zip) { $zip.Dispose() }
    Remove-Item -LiteralPath $archivePath -Force -ErrorAction SilentlyContinue
}

# Inspect a live postgres backend during LOAD and pg_sleep. A static basename is insufficient.
$datadir = Join-Path $env:RUNNER_TEMP "pgroonga-loader-pg$pg-data"
$log = Join-Path $env:RUNNER_TEMP "pgroonga-loader-pg$pg.log"
$sql = Join-Path $env:RUNNER_TEMP "pgroonga-loader-pg$pg.sql"
$stdout = Join-Path $env:RUNNER_TEMP "pgroonga-loader-pg$pg.stdout"
$stderr = Join-Path $env:RUNNER_TEMP "pgroonga-loader-pg$pg.stderr"
$port = 55453
$started = $false
$client = $null
try {
    & (Join-Path $bin 'initdb.exe') -D $datadir -A trust -U postgres --no-instructions
    if ($LASTEXITCODE -ne 0) { throw 'initdb failed' }
    & (Join-Path $bin 'pg_ctl.exe') -D $datadir -l $log -o "-h 127.0.0.1 -p $port" -w start
    if ($LASTEXITCODE -ne 0) { throw 'pg_ctl start failed' }
    $started = $true
    Set-Content -LiteralPath $sql -Value "LOAD 'pgroonga'; SELECT pg_sleep(25);" -Encoding utf8
    $arguments = @('-X','-v','ON_ERROR_STOP=1','-h','127.0.0.1','-p',[string]$port,
                   '-U','postgres','-d','postgres','-f',('"'+$sql+'"'))
    $client = Start-Process -FilePath (Join-Path $bin 'psql.exe') -ArgumentList $arguments -PassThru -RedirectStandardOutput $stdout -RedirectStandardError $stderr
    $expectedPg = Join-Path $root 'lib\pgroonga.dll'
    $expectedGroonga = Join-Path $bin 'libgroonga.dll'
    $observedPid = $null
    $seenPaths = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    for ($attempt=0; $attempt -lt 100; $attempt++) {
        if ($client.HasExited) { break }
        $rows = @()
        foreach ($p in @(Get-Process -Name postgres -ErrorAction SilentlyContinue)) {
            try {
                $mods = @($p.Modules | ForEach-Object { [pscustomobject]@{FileName=$_.FileName} })
                $rows += [pscustomobject]@{Id=$p.Id; Modules=$mods}
                foreach ($m in $mods) {
                    if ($m.FileName -match '(?i)(pgroonga|libgroonga|liblz4)\.dll$') { [void]$seenPaths.Add("PID=$($p.Id) $($m.FileName)") }
                }
            } catch {
                Write-Host "POSTGRES_PROCESS_MODULE_QUERY=UNAVAILABLE PID=$($p.Id) DETAIL=$($_.Exception.Message)"
            }
        }
        $observedPid = Test-LoadedModuleSet -Processes $rows -PgModule $expectedPg -GroongaModule $expectedGroonga -Lz4Module $hostLz4
        if ($null -ne $observedPid) { break }
        Start-Sleep -Milliseconds 200
    }
    $seenPaths | Sort-Object | ForEach-Object { Write-Host "PGROONGA_ACTUAL_LOADED_MODULE=$_" }
    if ($null -eq $observedPid) { throw 'No single postgres.exe backend observed loading all three exact paths' }

    if($AuditModuleOrigins){
        $loaded=@((Get-Process -Id $observedPid -ErrorAction Stop).Modules)
        $observations=@();$external=0
        foreach($module in $loaded){
            $actualPath=[string]$module.FileName
            if($actualPath -notmatch '(?i)[.]dll$'){continue}
            if(-not $actualPath.StartsWith($root+'\',[StringComparison]::OrdinalIgnoreCase)){
                $external++;continue
            }
            if(-not (Test-Path -LiteralPath $actualPath -PathType Leaf)){
                throw "Live module vanished: $actualPath"
            }
            $observations += [pscustomobject]@{
                path=$actualPath
                sha256=(Get-FileHash -LiteralPath $actualPath -Algorithm SHA256).Hash.ToLowerInvariant()
            }
        }
        $review=Review-ModuleOrigins -Observed $observations -Original $originalDlls -PgRoot $root -HostLz4 $hostLz4 -HostSha $before
        $review['pgMajor']=$Major
        $review['observedBackendPid']=$observedPid
        $review['unsampledExternalWindowsDlls']=$external
        # PR #370 names: 11 API-set contracts cannot be inferred from
        # physical module paths. Other basenames are sampled in this exact PID.
        $importNames=@('advapi32.dll','dbghelp.dll','kernel32.dll','psapi.dll','ws2_32.dll',
                       'msvcp140.dll','vcomp140.dll','vcruntime140.dll','vcruntime140_1.dll',
                       'liblz4.dll')
        $importObserved=@()
        foreach($module in $loaded){
            $path=[string]$module.FileName
            $name=[IO.Path]::GetFileName($path).ToLowerInvariant()
            if($name -notin $importNames){continue}
            if(-not (Test-Path -LiteralPath $path -PathType Leaf)){throw "Module vanished: $path"}
            $importObserved += [pscustomobject]@{
                name=$name;path=$path
                sha256=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
                authenticode=(Get-AuthenticodeSignature -FilePath $path).Status.ToString()
                pid=$observedPid
            }
        }
        $backend=(Get-Process -Id $observedPid -ErrorAction Stop)
        $exe=[string]$backend.MainModule.FileName
        if(-not (Test-Path -LiteralPath $exe -PathType Leaf)){throw 'Backend EXE vanished'}
        $importObserved += [pscustomobject]@{
            name='postgres.exe';path=$exe
            sha256=(Get-FileHash -LiteralPath $exe -Algorithm SHA256).Hash.ToLowerInvariant()
            authenticode=(Get-AuthenticodeSignature -FilePath $exe).Status.ToString()
            pid=$observedPid
        }
        $externalReview=Review-ExternalImportSample -Observed $importObserved -PgRoot $root -BackendPid $observedPid -HostLz4Sha $before
        $externalReview['pgMajor']=$Major
        $externalReview | ConvertTo-Json -Depth 6 -Compress | Write-Host
        Write-Host "PGROONGA_EXTERNAL_22_IMPORT_NAMES=OBSERVED PG=$pg PHYSICAL_SAMPLED=$($externalReview.sampledPhysicalNameMatches) NOT_SEEN=$($externalReview.notSeenPhysicalNames) API_SET=11 EXACT_IMPORT_BINDING=DENY PUBLIC_GET=DENY"

        $review | ConvertTo-Json -Depth 5 -Compress | Write-Host
        Write-Host "PGROONGA_LIVE_DLL_ORIGINS=PASS PG=$pg EXACT=$($review.originCounts.exact) HOST=$($review.originCounts.preservedHost) DIFFERENT_BYTES=$($review.originCounts.differentBytes) UNMAPPED=$($review.originCounts.unmapped) EXTERNAL_UNVERIFIED=$external"
    }
    $client.WaitForExit(35000) | Out-Null
    if (-not $client.HasExited -or $client.ExitCode -ne 0) { throw 'Backend LOAD/pg_sleep probe exited abnormally' }
    if ((Get-FileHash -LiteralPath $hostLz4 -Algorithm SHA256).Hash.ToLowerInvariant() -cne $before) {
        throw 'EDB liblz4 changed after actual loader observation'
    }
    Write-Host "PGROONGA_EDB_LZ4_ACTUAL_PROCESS_LOAD=PASS PG=$pg PID=$observedPid PATH=$hostLz4 SHA256=$before"
} catch {
    if (Test-Path -LiteralPath $stderr) { Get-Content -LiteralPath $stderr -Tail 30 | ForEach-Object { Write-Host $_ } }
    if (Test-Path -LiteralPath $log) { Get-Content -LiteralPath $log -Tail 30 | ForEach-Object { Write-Host $_ } }
    throw
} finally {
    if ($client -and -not $client.HasExited) { Stop-Process -Id $client.Id -Force -ErrorAction SilentlyContinue }
    if ($started) { & (Join-Path $bin 'pg_ctl.exe') -D $datadir -m immediate -w stop }
}
Write-Host 'LZ4_RUNTIME_OBSERVATION_ONLY=YES ALL_DYNAMIC_DEPENDENCIES_VERIFIED=NO PRODUCER_PROVENANCE=UNVERIFIED NOTICE=UNVERIFIED PUBLIC_GET=DENY MIRROR=DENY RELEASE=DENY'
