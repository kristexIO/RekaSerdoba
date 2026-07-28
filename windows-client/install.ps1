param(
    [Parameter(Mandatory = $true)]
    [string]$Bundle
)
$ErrorActionPreference = "Stop"
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run PowerShell as Administrator"
}
$source = $PSScriptRoot
$target = Join-Path $env:ProgramFiles "RekaSerdoba"
New-Item -ItemType Directory -Path $target -Force | Out-Null
Copy-Item -LiteralPath (Join-Path $source "reka-service.exe") -Destination $target -Force
Copy-Item -LiteralPath (Join-Path $source "h3_bridge.exe") -Destination $target -Force
Copy-Item -LiteralPath (Join-Path $source "wintun.dll") -Destination $target -Force
$service = Join-Path $target "reka-service.exe"
& $service import (Resolve-Path -LiteralPath $Bundle)
& $service check
& $service install
& $service start
Get-Service RekaSerdoba
