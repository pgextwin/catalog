# Issue #112: independent Windows two-node pglogical replication acceptance.
# Each run obtains the exact original in its own ephemeral runner, and never uploads it.
# This is NOT an authorization, source/Sigstore attestation, or Publisher event.
[CmdletBinding()]
param([Parameter(Mandatory = $true)][ValidateSet(14,15,16,17,18)][int]$Major)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false

if ($env:GITHUB_ACTIONS -cne 'true' -or $env:GITHUB_EVENT_NAME -cne 'pull_request' -or
    $env:GITHUB_REPOSITORY -cne 'pgextwin/catalog' -or $env:RUNNER_OS -cne 'Windows' -or
    -not $env:RUNNER_TEMP -or -not $env:PGROOT) {
    throw 'Two-node candidate E2E is restricted to genuine ephemeral Windows PR CI'
}

$root = [IO.Path]::GetFullPath($env:PGROOT)
$stage = Join-Path $env:RUNNER_TEMP "issue112-pglogical-pg$Major-stage"
$bin = Join-Path $root 'bin'
$pgConfig = Join-Path $bin 'pg_config.exe'
$psql = Join-Path $bin 'psql.exe'
$initdb = Join-Path $bin 'initdb.exe'
$ctl = Join-Path $bin 'pg_ctl.exe'
foreach ($path in @($pgConfig, $psql, $initdb, $ctl, $stage)) {
    if (-not (Test-Path -LiteralPath $path)) { throw "Required pinned input missing: $path" }
}
$versionText = (& $pgConfig --version | Out-String).Trim()
if ($LASTEXITCODE -ne 0 -or $versionText -notmatch "^PostgreSQL $Major(?:[.]|\s)") {
    throw "PG version mismatch: expected $Major, received $versionText"
}

# Only the source-auditor allowlist from scripts/issue112_pglogical_original_windows.py
# may be copied; import .lib files, notices and other members stay outside PGROOT.
$members = @(Get-ChildItem -LiteralPath $stage -Recurse -File)
if ($members.Count -lt 5 -or $members.Count -gt 100) { throw 'Staged member count outside bounds' }
foreach ($member in $members) {
    $relative = [IO.Path]::GetRelativePath($stage, $member.FullName).Replace('\', '/')
    if ($relative -cnotmatch '^(lib/(pglogical|pglogical_output)\.dll|bin/pglogical_create_subscriber\.exe|share/extension/pglogical(_origin)?\.control|share/extension/pglogical(_origin)?--[A-Za-z0-9_.-]+\.sql)$') {
        throw "Refusing unreviewed installed member: $relative"
    }
    $destination = Join-Path $root ($relative.Replace('/', [IO.Path]::DirectorySeparatorChar))
    if (Test-Path -LiteralPath $destination) { throw "Refusing overwrite: $relative" }
    Copy-Item -LiteralPath $member.FullName -Destination $destination
}

$nodes = @(
    @{ Name = 'provider'; Port = 55462; Data = (Join-Path $env:RUNNER_TEMP "issue112-pglogical-pg$Major-provider"); Log = (Join-Path $env:RUNNER_TEMP "issue112-pglogical-pg$Major-provider.log") },
    @{ Name = 'subscriber'; Port = 55463; Data = (Join-Path $env:RUNNER_TEMP "issue112-pglogical-pg$Major-subscriber"); Log = (Join-Path $env:RUNNER_TEMP "issue112-pglogical-pg$Major-subscriber.log") }
)
$started = [System.Collections.Generic.List[object]]::new()

function Invoke-RequiredSql {
    param([Parameter(Mandatory = $true)][int]$Port, [Parameter(Mandatory = $true)][string]$Sql)
    $command = @('-X', '-w', '-A', '-t', '-v', 'ON_ERROR_STOP=1',
                 '-h', '127.0.0.1', '-p', [string]$Port, '-U', 'postgres',
                 '-d', 'postgres', '-c', $Sql)
    $result = (& $psql @command 2>&1 | Out-String).Trim()
    if ($LASTEXITCODE -ne 0) {
        throw "pglogical two-node SQL failed on port $Port: $($result.Substring(0, [Math]::Min($result.Length, 500)))"
    }
    return $result
}

function Wait-ForRow {
    param([Parameter(Mandatory = $true)][string]$Expected)
    for ($attempt = 0; $attempt -lt 40; $attempt++) {
        $value = Invoke-RequiredSql -Port 55463 -Sql "SELECT COALESCE((SELECT payload FROM public.pgextwin_replica_probe WHERE id = 1), '');"
        if ($value -ceq $Expected) { return }
        Start-Sleep -Seconds 3
    }
    throw "Two-node replication did not converge to '$Expected' in 120 seconds"
}

try {
    foreach ($node in $nodes) {
        if (Test-Path -LiteralPath $node.Data) { throw 'Refusing reused PostgreSQL data directory' }
        & $initdb -D $node.Data -A trust -U postgres --no-instructions
        if ($LASTEXITCODE -ne 0) { throw "initdb failed: $($node.Name)" }
        Add-Content -LiteralPath (Join-Path $node.Data 'postgresql.conf') -Value @(
            "listen_addresses = '127.0.0.1'"
            "shared_preload_libraries = 'pglogical'"
            'wal_level = logical'
            'max_replication_slots = 10'
            'max_wal_senders = 10'
            'max_worker_processes = 16'
            "output_plugin_libraries = 'pgoutput, test_decoding, pglogical_output'"
        )
        & $ctl -D $node.Data -l $node.Log -o "-h 127.0.0.1 -p $($node.Port)" -w start
        if ($LASTEXITCODE -ne 0) { throw "Windows native PostgreSQL startup failed: $($node.Name)" }
        $started.Add($node)
        [void](Invoke-RequiredSql -Port $node.Port -Sql 'CREATE EXTENSION pglogical;')
        $ext = Invoke-RequiredSql -Port $node.Port -Sql "SELECT extversion FROM pg_extension WHERE extname = 'pglogical';"
        if ($ext -cne '2.4.8') { throw "Wrong pglogical version on $($node.Name): $ext" }
        [void](Invoke-RequiredSql -Port $node.Port -Sql 'CREATE TABLE public.pgextwin_replica_probe (id integer PRIMARY KEY, payload text NOT NULL);')
    }

    # Two separate node identities, real loopback provider/subscriber connections,
    # initial-data sync and a subsequent logical UPDATE are required.
    [void](Invoke-RequiredSql -Port 55462 -Sql "SELECT pglogical.create_node(node_name := 'pgextwin_provider', dsn := 'host=127.0.0.1 port=55462 dbname=postgres user=postgres');")
    [void](Invoke-RequiredSql -Port 55463 -Sql "SELECT pglogical.create_node(node_name := 'pgextwin_subscriber', dsn := 'host=127.0.0.1 port=55463 dbname=postgres user=postgres');")
    [void](Invoke-RequiredSql -Port 55462 -Sql "SELECT pglogical.replication_set_add_table('default', 'public.pgextwin_replica_probe'::regclass, true);")
    [void](Invoke-RequiredSql -Port 55462 -Sql "INSERT INTO public.pgextwin_replica_probe VALUES (1, 'initial-replicated');")
    [void](Invoke-RequiredSql -Port 55463 -Sql "SELECT pglogical.create_subscription(subscription_name := 'pgextwin_link', provider_dsn := 'host=127.0.0.1 port=55462 dbname=postgres user=postgres', synchronize_structure := false, synchronize_data := true);")
    Wait-ForRow -Expected 'initial-replicated'
    [void](Invoke-RequiredSql -Port 55462 -Sql "UPDATE public.pgextwin_replica_probe SET payload = 'updated-replicated' WHERE id = 1;")
    Wait-ForRow -Expected 'updated-replicated'
    Write-Host "PGLOGICAL_TWO_NODE_REPLICATION=PASS PG=$Major INITIAL_SYNC=PASS UPDATE_STREAM=PASS"
} finally {
    # Stop only clusters started by this process; private originals are never uploaded.
    for ($index = $started.Count - 1; $index -ge 0; $index--) {
        $node = $started[$index]
        & $ctl -D $node.Data -m immediate -w stop
        if ($LASTEXITCODE -ne 0) { Write-Warning "Ephemeral $($node.Name) shutdown failed" }
    }
    Write-Host 'CANDIDATE_ONLY=YES SIGSTORE=UNVERIFIED RIGHTS=UNVERIFIED PE_DEPENDENCY_CLOSURE=UNVERIFIED GET=DENY MIRROR=DENY RELEASE=DENY'
}
