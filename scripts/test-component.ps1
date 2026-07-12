#Requires -Version 5.1
<#
.SYNOPSIS
    Run unit tests for one component (or core / integration).

.PARAMETER Name
    Component name: claude, cowork, cursor, codex, copilot, grok, chat-history,
    git-posture, secrets-scan, pii-scan, core, integration, all.

.EXAMPLE
    .\scripts\test-component.ps1 -Name codex
    .\scripts\test-component.ps1 -Name all
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [ValidateSet(
        "claude", "cowork", "cursor", "codex", "copilot", "grok",
        "chat-history", "git-posture", "secrets-scan", "pii-scan",
        "core", "integration", "all"
    )]
    [string]$Name
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = Split-Path -Parent $ScriptDir
$CoreDir = Join-Path $RepoRoot "core"
$env:PYTHONPATH = if ($env:PYTHONPATH) { "$CoreDir;$env:PYTHONPATH" } else { $CoreDir }
$env:PYTHONUTF8 = "1"

function Invoke-Discover {
    param([string]$StartDir, [string]$Label)
    if (-not (Test-Path -LiteralPath $StartDir)) {
        Write-Host "$Label : no tests directory at $StartDir (skip)" -ForegroundColor DarkGray
        return 0
    }
    $pyFiles = Get-ChildItem -LiteralPath $StartDir -Filter "test_*.py" -ErrorAction SilentlyContinue
    if (-not $pyFiles) {
        Write-Host "$Label : no test_*.py files (skip)" -ForegroundColor DarkGray
        return 0
    }
    Write-Host "=== $Label ===" -ForegroundColor Cyan
    Push-Location $RepoRoot
    try {
        # unittest writes its progress to stderr. Windows PowerShell 5.1 wraps
        # native stderr lines in ErrorRecords, which $ErrorActionPreference=Stop
        # turns into a bogus NativeCommandError even when every test passes.
        # Merge the streams and stringify so 5.1 and pwsh behave the same.
        $eap = $ErrorActionPreference
        $ErrorActionPreference = "Continue"
        & python -m unittest discover -s $StartDir -p "test_*.py" -v 2>&1 |
            ForEach-Object { Write-Host "$_" }
        $code = $LASTEXITCODE
        $ErrorActionPreference = $eap
        return $code
    }
    finally {
        Pop-Location
    }
}

$failed = 0

if ($Name -eq "all") {
    $order = @(
        "core", "claude", "cowork", "cursor", "codex", "copilot", "grok",
        "chat-history", "git-posture", "secrets-scan", "pii-scan", "integration"
    )
    foreach ($n in $order) {
        & $PSCommandPath -Name $n
        if ($LASTEXITCODE -ne 0) { $failed = 1 }
    }
    # mcp-visibility is already a component-like tree
    $code = Invoke-Discover -StartDir (Join-Path $RepoRoot "tools\mcp-visibility\tests") -Label "mcp-visibility"
    if ($code -ne 0) { $failed = 1 }
    exit $failed
}

if ($Name -eq "core") {
    $code = Invoke-Discover -StartDir (Join-Path $RepoRoot "core\tests") -Label "core"
    exit $code
}

if ($Name -eq "integration") {
    $code = Invoke-Discover -StartDir (Join-Path $RepoRoot "tests\integration") -Label "integration"
    exit $code
}

$dir = Join-Path $RepoRoot "components\$Name\tests"
$code = Invoke-Discover -StartDir $dir -Label $Name
exit $code
