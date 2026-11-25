param(
    [Parameter(Mandatory)][string]$Source,
    [Parameter(Mandatory)][string]$Folder,
    [Parameter(Mandatory)]$Receipt
)

$catalog = "https://raw.githubusercontent.com/pgextwin/catalog/$Source"
$cohort = Invoke-RestMethod -Uri "$catalog/config/cli-feed-majors.json"
$required = [string[]]@($cohort.postgresqlMajors)
if ($cohort.schemaVersion -ne 1 -or $required.Count -lt 1) {
    throw 'Invalid signed Catalog PG cohort policy'
}

$extensions = @($Receipt.packages.extension | Sort-Object -Unique)
$optional = [string]$cohort.optionalPostgresqlMajor
if ($optional) {
    $index = Invoke-RestMethod -Uri "$catalog/index.json"
    $extensions = $index.extensions
}
$expected = @(
    foreach ($extension in $extensions) {
        foreach ($major in $required) { "$extension|$major" }
    }
)
$lastMajor = $required[-1]
if ($optional) {
    # Check the optional subset against immutable Catalog package-ledger availability.
    foreach ($extension in $extensions) {
        $ledger = Invoke-RestMethod -Uri "$catalog/packages/$extension.json"
        if ($ledger.schemaVersion -ne 1 -or
            ($ledger.latestReleaseId -isnot [int] -and $ledger.latestReleaseId -isnot [long]) -or
            $ledger.latestReleaseId -le 0) {
            throw "Invalid Catalog package ledger for $extension"
        }
        $latest = @($ledger.releases | Where-Object { $_.releaseId -eq $ledger.latestReleaseId })
        if ($latest.Count -ne 1 -or
            $null -ne $latest[0].PSObject.Properties['admission'] -or
            $null -ne $latest[0].PSObject.Properties['legacyInventoryCommit']) {
            throw "Invalid Catalog package ledger latest release for $extension"
        }
        $optionalRows = @($latest[0].packages | Where-Object { $_.pgMajor -is [string] -and $_.pgMajor -ceq $optional })
        if ($optionalRows.Count -gt 1) {
            throw "Duplicate PG$optional package row in Catalog ledger for $extension"
        }
        $unavailable = @($ledger.unavailableMajors | Where-Object { $_ -is [string] -and $_ -ceq $optional })
        if ($optionalRows.Count -eq 1 -and $unavailable.Count -gt 0) {
            throw "Conflicting PG$optional availability in Catalog ledger for $extension"
        }
        if ($optionalRows.Count -eq 1) {
            $expected += "$extension|$optional"
            $lastMajor = $optional
        }
    }
}

$actual = @($Receipt.packages | ForEach-Object { "$($_.extension)|$($_.pgMajor)" })
if ($Receipt.zipCount -ne $actual.Count -or
    (($actual | Sort-Object) -join ',') -cne (($expected | Sort-Object) -join ',') -or
    (Split-Path $Folder -Leaf) -cne "pgextwin-pg$($required[0])-$lastMajor") {
    throw 'Signed Catalog cohort and actual ZIP matrix differ'
}
