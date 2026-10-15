#Requires -Version 5.1
<#
.SYNOPSIS
    Download a released aiscan zip, verify it, and run it. No repo checkout,
    no admin rights, and no machine-wide execution policy change.

.DESCRIPTION
    1. Finds the latest GitHub release of robrounsavall/ai-agent-audit
       (or the one named by -Version).
    2. Downloads aiscan-<version>.zip and its .sha256 file to
       %LOCALAPPDATA%\aiscan\<version>.
    3. Checks the zip's SHA256 against the .sha256 file and stops on mismatch.
    4. Extracts the zip and clears the "downloaded from the internet" mark
       (Unblock-File) on the extracted files.
    5. Runs aiscan.ps1 in a child PowerShell with -ExecutionPolicy Bypass for
       that one process, passing through every other argument.

    A version that is already installed and verified is reused, not downloaded
    again. Delete %LOCALAPPDATA%\aiscan to remove everything.

.PARAMETER Version
    Release to use, e.g. 0.2.0 (a leading "v" is fine). Default: latest.

.PARAMETER InstallOnly
    Download, verify and extract, print the install path, and stop.

.EXAMPLE
    & ([scriptblock]::Create((irm https://github.com/robrounsavall/ai-agent-audit/releases/latest/download/get-aiscan.ps1))) all -Briefing

.EXAMPLE
    .\get-aiscan.ps1 -Version 0.2.0 -InstallOnly
#>
[CmdletBinding(PositionalBinding = $false)]
param(
    [string]$Version,
    [switch]$InstallOnly,
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$AiscanArgs
)

$Repo = "robrounsavall/ai-agent-audit"

# Windows PowerShell 5.1 may default to TLS 1.0; GitHub needs TLS 1.2.
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

if ($Version) {
    $Version = $Version.TrimStart("v")
}
else {
    $latest = Invoke-RestMethod -UseBasicParsing -ErrorAction Stop -Uri "https://api.github.com/repos/$Repo/releases/latest"
    $Version = "$($latest.tag_name)".TrimStart("v")
}
if ($Version -notmatch '^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$') {
    throw "Unexpected version string: '$Version'"
}

$name = "aiscan-$Version"
$base = "https://github.com/$Repo/releases/download/v$Version"
$installDir = Join-Path $env:LOCALAPPDATA "aiscan\$Version"
$zipPath = Join-Path $installDir "$name.zip"
$shaPath = "$zipPath.sha256"
$aiscan = Join-Path $installDir "$name\aiscan.ps1"

function Test-ZipHash {
    if (-not ((Test-Path -LiteralPath $zipPath) -and (Test-Path -LiteralPath $shaPath))) { return $false }
    $expected = ((Get-Content -LiteralPath $shaPath -TotalCount 1) -split '\s+')[0]
    $actual = (Get-FileHash -LiteralPath $zipPath -Algorithm SHA256).Hash
    return ($expected -and $actual -ieq $expected)
}

if (-not ((Test-Path -LiteralPath $aiscan) -and (Test-ZipHash))) {
    New-Item -ItemType Directory -Force -Path $installDir | Out-Null
    Write-Host "Downloading aiscan $Version ..." -ForegroundColor Cyan
    $oldProgress = $ProgressPreference
    $ProgressPreference = "SilentlyContinue"   # 5.1's progress bar makes downloads very slow
    try {
        Invoke-WebRequest -UseBasicParsing -ErrorAction Stop -Uri "$base/$name.zip" -OutFile $zipPath
        Invoke-WebRequest -UseBasicParsing -ErrorAction Stop -Uri "$base/$name.zip.sha256" -OutFile $shaPath
    }
    finally {
        $ProgressPreference = $oldProgress
    }
    if (-not (Test-ZipHash)) {
        Remove-Item -LiteralPath $zipPath, $shaPath -Force -ErrorAction SilentlyContinue
        throw "SHA256 mismatch for $name.zip. Nothing was extracted or run."
    }
    Write-Host "SHA256 verified." -ForegroundColor Green
    $extracted = Join-Path $installDir $name
    if (Test-Path -LiteralPath $extracted) { Remove-Item -LiteralPath $extracted -Recurse -Force }
    Expand-Archive -LiteralPath $zipPath -DestinationPath $installDir -Force -ErrorAction Stop
    Get-ChildItem -LiteralPath $extracted -Recurse -File | Unblock-File -ErrorAction SilentlyContinue
}

Write-Host "aiscan $Version installed at: $(Split-Path -Parent $aiscan)" -ForegroundColor Cyan
if ($InstallOnly) {
    Write-Host "Run it with: powershell -ExecutionPolicy Bypass -File `"$aiscan`" all" -ForegroundColor DarkGray
    return
}

# Same PowerShell host that is running this script (powershell.exe or pwsh).
# -ExecutionPolicy Bypass applies to that child process only.
$psExe = (Get-Process -Id $PID).Path
& $psExe -NoProfile -ExecutionPolicy Bypass -File $aiscan @AiscanArgs
