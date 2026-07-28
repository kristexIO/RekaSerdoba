$ErrorActionPreference = "Stop"
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run PowerShell as Administrator"
}
$target = Join-Path $env:ProgramFiles "RekaSerdoba"
$service = Join-Path $target "reka-service.exe"
if (Test-Path -LiteralPath $service) {
    & $service stop
    Start-Sleep -Seconds 2
    & $service recover
    & $service remove
}
Write-Output "RekaSerdoba service removed. Program files and the DPAPI device bundle were retained for recovery."
