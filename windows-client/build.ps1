param(
    [string]$Bundle,
    [string]$Python,
    [string]$SigningCertificateThumbprint,
    [string]$TimestampServer = "http://timestamp.digicert.com"
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
if (-not $Python) {
    $Python = (Get-Command python.exe -ErrorAction Stop).Source
}
if (-not $Bundle) {
    $Bundle = Join-Path $root "deliverables\RekaSerdoba_client_bundle.json"
}
$Bundle = [System.IO.Path]::GetFullPath($Bundle)
if (-not (Test-Path -LiteralPath $Bundle -PathType Leaf)) {
    throw "Device bundle not found. Pass -Bundle C:\secure\client-bundle.json"
}
$python = $Python
$dependencies = Join-Path $root ".codex-temp\clientdeps"
$output = Join-Path $PSScriptRoot "dist"
function Invoke-Sign {
    param([string[]]$Paths)
    if (-not $SigningCertificateThumbprint) {
        return
    }
    $signTool = (Get-Command signtool.exe -ErrorAction Stop).Source
    foreach ($path in $Paths) {
        & $signTool sign /sha1 $SigningCertificateThumbprint /fd SHA256 /tr $TimestampServer /td SHA256 $path
        if ($LASTEXITCODE -ne 0) {
            throw "Authenticode signing failed: $path"
        }
        $signature = Get-AuthenticodeSignature -LiteralPath $path
        if ($signature.Status -ne "Valid") {
            throw "Authenticode verification failed: $path"
        }
    }
}
& $python -m pip install --disable-pip-version-check --upgrade --target $dependencies "pyinstaller==6.21.0" "pywin32==311" "h2==4.3.0"
$env:PYTHONPATH = "$dependencies;$(Join-Path $dependencies 'win32');$(Join-Path $dependencies 'win32\lib');$root;$PSScriptRoot"
& $python -m PyInstaller `
    --noconfirm `
    --clean `
    --onefile `
    --name reka-service `
    --distpath $output `
    --workpath (Join-Path $root ".codex-temp\pyinstaller-build") `
    --specpath (Join-Path $root ".codex-temp") `
    --paths $root `
    --paths $PSScriptRoot `
    --paths $dependencies `
    --paths (Join-Path $dependencies "win32") `
    --paths (Join-Path $dependencies "win32\lib") `
    --hidden-import win32timezone `
    --hidden-import servicemanager `
    --collect-submodules h2 `
    --collect-submodules hpack `
    --collect-submodules hyperframe `
    (Join-Path $PSScriptRoot "reka_service.py")
& $python -m PyInstaller `
    --noconfirm `
    --clean `
    --onefile `
    --windowed `
    --uac-admin `
    --name RekaSerdoba `
    --distpath $output `
    --workpath (Join-Path $root ".codex-temp\pyinstaller-gui-build") `
    --specpath (Join-Path $root ".codex-temp") `
    --paths $PSScriptRoot `
    (Join-Path $PSScriptRoot "gui.py")
Invoke-Sign -Paths @(
    (Join-Path $output "RekaSerdoba.exe"),
    (Join-Path $output "reka-service.exe"),
    (Join-Path $PSScriptRoot "h3_bridge.exe")
)
& $python -m PyInstaller `
    --noconfirm `
    --clean `
    --onefile `
    --windowed `
    --name RekaSerdoba_Setup `
    --distpath $output `
    --workpath (Join-Path $root ".codex-temp\pyinstaller-setup-build") `
    --specpath (Join-Path $root ".codex-temp") `
    --paths $PSScriptRoot `
    --add-data "$(Join-Path $output 'RekaSerdoba.exe');." `
    --add-data "$(Join-Path $output 'reka-service.exe');." `
    --add-data "$(Join-Path $PSScriptRoot 'h3_bridge.exe');." `
    --add-data "$(Join-Path $PSScriptRoot 'wintun.dll');." `
    --add-data "$Bundle;." `
    --add-data "$(Join-Path $PSScriptRoot 'WINTUN_LICENSE.txt');." `
    (Join-Path $PSScriptRoot "setup.py")
Invoke-Sign -Paths @((Join-Path $output "RekaSerdoba_Setup.exe"))
$setup = Join-Path $output "RekaSerdoba_Setup.exe"
$selfTest = Start-Process -FilePath $setup -ArgumentList "--self-test" -WindowStyle Hidden -PassThru
if (-not $selfTest.WaitForExit(60000)) {
    & taskkill.exe /PID $selfTest.Id /T /F | Out-Null
    throw "Installer self-test timed out"
}
if ($selfTest.ExitCode -ne 0) {
    throw "Installer self-test failed with exit code $($selfTest.ExitCode)"
}
Copy-Item -LiteralPath (Join-Path $PSScriptRoot "h3_bridge.exe") -Destination $output
Copy-Item -LiteralPath (Join-Path $PSScriptRoot "wintun.dll") -Destination $output
Copy-Item -LiteralPath (Join-Path $PSScriptRoot "install.ps1") -Destination $output
Copy-Item -LiteralPath (Join-Path $PSScriptRoot "uninstall.ps1") -Destination $output
Copy-Item -LiteralPath (Join-Path $PSScriptRoot "README_RU.md") -Destination $output
Copy-Item -LiteralPath (Join-Path $PSScriptRoot "WINTUN_LICENSE.txt") -Destination $output
$artifacts = Get-FileHash -Algorithm SHA256 (Join-Path $output "RekaSerdoba_Setup.exe"), (Join-Path $output "RekaSerdoba.exe"), (Join-Path $output "reka-service.exe"), (Join-Path $output "h3_bridge.exe"), (Join-Path $output "wintun.dll")
$artifacts | ForEach-Object { "$($_.Hash.ToLowerInvariant())  $(Split-Path -Leaf $_.Path)" } | Set-Content -Encoding ascii (Join-Path $output "SHA256SUMS.txt")
$artifacts
