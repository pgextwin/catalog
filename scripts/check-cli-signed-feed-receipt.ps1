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
    # Check the optional subset against immutable Catalog availability.
    foreach ($extension in $extensions) {
        $record = Invoke-RestMethod -Uri "$catalog/extensions/$extension.json"
        if ($record.postgresql.PSObject.Properties[$optional].Value.available -eq $true) {
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
