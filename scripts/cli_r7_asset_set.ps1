[CmdletBinding()]
param([Parameter(Mandatory = $true)][string]$Directory)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Source/release identity is checked separately. This validates only exact local
# release candidate files, independently of Windows culture-dependent sorting.
$expected = [string[]]@(
  'pgextwin.exe',
  'pgextwin.spdx.json',
  'DOTNET-LICENSE.txt',
  'DOTNET-THIRD-PARTY-NOTICES.txt',
  'SHA256SUMS.txt'
)
$entries = @(Get-ChildItem -LiteralPath $Directory -Force)
if (@($entries | Where-Object { $_.PSIsContainer }).Count -ne 0) { throw 'R7 unexpected directory' }
$files = @($entries | Where-Object { -not $_.PSIsContainer })
if ($files.Count -ne $expected.Count) {
  throw "R7 asset count mismatch: found $($files.Count), expected $($expected.Count)"
}
foreach ($file in $files) {
  if ($expected -cnotcontains $file.Name) { throw "R7 unexpected asset: $($file.Name)" }
  if (($file.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
    throw "R7 asset link denied: $($file.Name)"
  }
}
foreach ($name in $expected) {
  if (-not (Test-Path -LiteralPath (Join-Path $Directory $name) -PathType Leaf)) {
    throw "R7 asset missing: $name"
  }
}

$lines = @(Get-Content -LiteralPath (Join-Path $Directory 'SHA256SUMS.txt'))
if ($lines.Count -ne 4) { throw "R7 checksum entry count mismatch" }
$seen = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
foreach ($line in $lines) {
  if ($line -cnotmatch '^([A-Fa-f0-9]{64})  (pgextwin.exe|pgextwin.spdx.json|DOTNET-LICENSE.txt|DOTNET-THIRD-PARTY-NOTICES.txt)$') {
    throw "R7 checksum entry malformed"
  }
  $sha = $Matches[1].ToLowerInvariant()
  $filename = $Matches[2]
  if (-not $seen.Add($filename)) { throw "R7 duplicate checksum entry" }
  $actual = (Get-FileHash -LiteralPath (Join-Path $Directory $filename) -Algorithm SHA256).Hash.ToLowerInvariant()
  if ($sha -cne $actual) { throw "R7 checksum mismatch for $filename" }
}
if ($seen.Count -ne 4) { throw "R7 checksums incomplete" }
Write-Output "CLI_R7_EXACT_RELEASE_ASSET_SET=PASS COUNT=$($files.Count) SHA256SUMS=4"
