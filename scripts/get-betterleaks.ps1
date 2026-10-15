#Requires -Version 5.1
<#
.SYNOPSIS
    Download a pinned Betterleaks release for aiscan's secrets-scan. Opt-in;
    aiscan never runs this for you.

.DESCRIPTION
    1. Downloads betterleaks_<version>_windows_<arch>.zip from the official
       GitHub release (github.com/betterleaks/betterleaks).
    2. Checks its SHA256 against the hash pinned in this script and stops on
       a mismatch.
    3. Extracts betterleaks.exe to %LOCALAPPDATA%\aiscan\tools\betterleaks\<version>.
    4. Prints how to point aiscan at it with BETTERLEAKS_PATH.

    No admin rights. PATH and other environment variables are not changed.
    Delete %LOCALAPPDATA%\aiscan\tools\betterleaks to remove it.

    aiscan always runs Betterleaks with credential validation forced off, so
    found secrets are never sent to outside services.

.EXAMPLE
    .\scripts\get-betterleaks.ps1
#>
[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"

# Pinned release. To move to a new version, update all three values from the
# release's checksums.txt.
$Version = "1.9.0"
$Sha256 = @{
    "x64"   = "b765daec9fda475b031b5a5159798cbe4294a3f2a50683cbc0471226e376d3da"
    "arm64" = "3e5b9b6cdbfe8d486ae2dd2fa137473dc9ab42bf50317f051b73561121861816"
}

$arch = if ($env:PROCESSOR_ARCHITECTURE -eq "ARM64") { "arm64" } else { "x64" }
$zipName = "betterleaks_${Version}_windows_${arch}.zip"
$url = "https://github.com/betterleaks/betterleaks/releases/download/v$Version/$zipName"
$base = if ($env:LOCALAPPDATA) { $env:LOCALAPPDATA } else { [IO.Path]::GetTempPath() }
$installDir = Join-Path $base "aiscan\tools\betterleaks\$Version"
$exe = Join-Path $installDir "betterleaks.exe"

if (Test-Path -LiteralPath $exe) {
    Write-Host "Betterleaks $Version is already installed at:"
    Write-Host "  $exe"
}
else {
    # Windows PowerShell 5.1 may default to TLS 1.0; GitHub needs TLS 1.2.
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

    New-Item -ItemType Directory -Force -Path $installDir | Out-Null
    $zipPath = Join-Path $installDir $zipName
    Write-Host "Downloading $url"
    $ProgressPreference = "SilentlyContinue"
    Invoke-WebRequest -UseBasicParsing -Uri $url -OutFile $zipPath

    $actual = (Get-FileHash -Algorithm SHA256 -LiteralPath $zipPath).Hash.ToLowerInvariant()
    if ($actual -ne $Sha256[$arch]) {
        Remove-Item -LiteralPath $zipPath -Force
        throw "SHA256 mismatch for $zipName (expected $($Sha256[$arch]), got $actual). Nothing was installed."
    }
    Write-Host "SHA256 OK"

    Expand-Archive -LiteralPath $zipPath -DestinationPath $installDir -Force
    Remove-Item -LiteralPath $zipPath -Force
    if (-not (Test-Path -LiteralPath $exe)) {
        throw "betterleaks.exe was not found in $zipName"
    }
    # Clear the "downloaded from the internet" mark. Best effort.
    try { Get-ChildItem -LiteralPath $installDir -File | Unblock-File } catch { }
    Write-Host "Installed Betterleaks $Version at:"
    Write-Host "  $exe"
}

Write-Host ""
Write-Host "Point aiscan at it for this PowerShell window:"
Write-Host "  `$env:BETTERLEAKS_PATH = `"$exe`""
Write-Host "Or for every new window (your user account only):"
Write-Host "  [Environment]::SetEnvironmentVariable(`"BETTERLEAKS_PATH`", `"$exe`", `"User`")"
