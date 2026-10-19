Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$dir = Join-Path $env:RUNNER_TEMP ('cli-r7-assets-hostile-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $dir | Out-Null
try {
  $files = @('pgextwin.exe','pgextwin.spdx.json','DOTNET-LICENSE.txt','DOTNET-THIRD-PARTY-NOTICES.txt')
  foreach ($name in $files) {
    [IO.File]::WriteAllText((Join-Path $dir $name), 'synthetic fixture only: ' + $name)
  }
  function Write-Checksums {
    $lines = @($files | ForEach-Object {
      $h = (Get-FileHash -LiteralPath (Join-Path $dir $_) -Algorithm SHA256).Hash.ToLowerInvariant()
      "$h  $_"
    })
    $lines | Set-Content -LiteralPath (Join-Path $dir 'SHA256SUMS.txt') -Encoding ascii
  }
  function Expect-Denied([string]$case) {
    $denied = $false
    try {
      & ./scripts/cli_r7_asset_set.ps1 -Directory $dir | Out-Null
    }
    catch {
      $denied = $true
    }
    if (-not $denied) { throw "R7 assets accepted an adversarial $case" }
  }
  Write-Checksums
  & ./scripts/cli_r7_asset_set.ps1 -Directory $dir
  if ($LASTEXITCODE -ne 0) { throw 'Positive asset fixture failed' }

  [IO.File]::WriteAllText((Join-Path $dir 'unexpected.txt'), 'inject')
  Expect-Denied 'extra file'
  Remove-Item -LiteralPath (Join-Path $dir 'unexpected.txt') -Force

  Add-Content -LiteralPath (Join-Path $dir 'pgextwin.exe') -Value 'mutation'
  Expect-Denied 'modified original bytes'
  [IO.File]::WriteAllText((Join-Path $dir 'pgextwin.exe'), 'synthetic fixture only: pgextwin.exe')

  $lines = @(Get-Content -LiteralPath (Join-Path $dir 'SHA256SUMS.txt'))
  Set-Content -LiteralPath (Join-Path $dir 'SHA256SUMS.txt') -Value @($lines[0], $lines[0], $lines[2], $lines[3]) -Encoding ascii
  Expect-Denied 'duplicate checksum'

  Write-Checksums
  Remove-Item -LiteralPath (Join-Path $dir 'DOTNET-LICENSE.txt') -Force
  Expect-Denied 'missing license'
  Write-Output 'CLI_R7_ASSET_HOSTILE_TESTS=PASS'
}
finally {
  if (Test-Path -LiteralPath $dir) { Remove-Item -LiteralPath $dir -Recurse -Force }
}
