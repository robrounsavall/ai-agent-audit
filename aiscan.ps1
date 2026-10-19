#Requires -Version 5.1
<#
.SYNOPSIS
    Local AI coding agent posture scan (one collector or all stdlib collectors).

.DESCRIPTION
    Runs the collectors against a throwaway temp directory and prints results to
    the console. Read-only against tool data. The collectors in 'all' are offline
    and make no network calls. 'cloud-agents' and 'telemetry' are opt-in and are
    not part of 'all'. cloud-agents sends HTTPS GET requests only to the Cursor
    Cloud Agents API. telemetry reads local export files. A briefing run also
    writes evidence\changes.json from the previous scan before building HTML.

    Every collector runs on stock Python 3.11+ with no install. secrets-scan needs
    a scanner: betterleaks.exe (BETTERLEAKS_PATH or PATH), gitleaks.exe, or
    trufflehog.exe. aiscan never turns on Betterleaks credential validation.

.PARAMETER Collector
    One of: claude cowork cursor codex copilot chat-history git-posture
    secrets-scan pii-scan grok grok-bot cloud-agents telemetry discover all.
    Defaults to 'all' when omitted.

    'discover' is read-only and writes nothing.
    'all' runs the 11 offline collectors and prints a combined summary.
    'cloud-agents' and 'telemetry' are not included in 'all'. cloud-agents
    reads CURSOR_API_KEY and never prints that key. telemetry reads export
    files you pass with -OtelFile and -SplunkExport.

.PARAMETER Json
    Dump raw collector JSON instead of pretty-printed PowerShell formatting.

.PARAMETER RepoRoots
    Comma-separated repo roots for git-posture, secrets-scan, Cursor project
    .cursor/mcp.json, and Grok project .grok/config.toml discovery.

.PARAMETER Keep
    Keep the temp evidence directory and print its path instead of deleting it.

.PARAMETER Redact
    Mask secrets and hash paths in the output. Off by default: aiscan runs on your
    own machine, where masking only hides what you came to inspect. Use this if
    you intend to share aiscan output.

.PARAMETER LocalLinks
    With -Briefing, show full local file paths in the briefing with Copy path
    buttons and folder links, and write briefing\briefing-local.html. The file
    contains local paths: do not share it. Ignored (with a warning) when -Redact
    is set.

.PARAMETER OutDir
    Persistent output root instead of the throwaway temp directory. Creates
    <OutDir>\evidence and <OutDir>\raw and writes collector output there. Implies
    -Keep: the directory is never deleted. Omit for the default throwaway-temp
    behavior.

.PARAMETER Here
    Write persistent output to the current working directory. Creates
    .\evidence, .\raw, and optionally .\briefing. Mutually exclusive with -OutDir.

.PARAMETER Briefing
    After collectors finish, build an HTML briefing from the evidence root with
    report\build-briefing.py and open it (Start-Process). Written to
    <root>\briefing\briefing.html. Implies -Keep (the briefing lives inside the
    evidence root). Failures print a warning and do not stop the scan.

.PARAMETER Customer
    Customer / engagement name shown on the briefing hero and footer. Passed to
    build-briefing.py as --customer.

.PARAMETER Operator
    Operator name shown on the briefing hero and attestation. Passed to
    build-briefing.py as --operator.

.PARAMETER IncludeRunResult
    cloud-agents only. Store the latest run's result text in evidence. Off by
    default because that text can contain source code or secrets. When set,
    the text follows the same -Redact behavior as other collectors. The API
    key is never written either way.

.PARAMETER OtelFile
    telemetry only. Repeatable path to an OTLP JSON or JSON-lines export of
    Claude Code tool_decision events. Not used by 'all'.

.PARAMETER SplunkExport
    telemetry only. Repeatable path to a Splunk JSON or CSV export (approval
    rows and/or Cursor dashboard usage rows). Not used by 'all'.

.PARAMETER Previous
    Evidence root of the prior scan. When -Briefing is set, aiscan runs
    core\\scan_diff.py against this folder before building the HTML. Omit to
    let scan_diff pick the newest earlier sibling of -OutDir.

.PARAMETER HistoryRoot
    Folder of dated scan directories. Passed to scan_diff as --history-root
    when -Previous is omitted. Default is the parent of the scan folder.

.PARAMETER AgentMode
    Print paths relative to the scan folder and omit the closing
    "Evidence kept at" line. The summary table and error lines stay.
    For agent runs that must not repeat absolute paths. Messages this
    script prints are scrubbed. Stderr from a collector process is not,
    and can still contain a path.

.NOTES
    Exit codes: 0 the scan finished, including "platform not detected".
    1 usage error (-Here and -OutDir together). 2 a collector failed,
    wrote nothing, or wrote evidence that is not a readable envelope.
    3 every collector was fine and only the briefing failed to generate.

.EXAMPLE
    .\aiscan.ps1
    Runs every stdlib collector, unredacted unless -Redact, and prints a combined summary.

.EXAMPLE
    .\aiscan.ps1 claude

.EXAMPLE
    .\aiscan.ps1 all -Redact

.EXAMPLE
    .\aiscan.ps1 git-posture -RepoRoots C:\Users\me\source -Keep

.EXAMPLE
    .\aiscan.ps1 all -OutDir C:\scans\2026-07-06 -Briefing
    Runs every stdlib collector into a persistent directory, then builds and
    opens an HTML briefing from that evidence.

.EXAMPLE
    .\aiscan.ps1 all -OutDir C:\scans\today -Briefing -LocalLinks
    Builds briefing\briefing-local.html with full paths, Copy path buttons and
    folder links. Local use only.

.EXAMPLE
    .\aiscan.ps1 all -Here -Briefing -Customer "Acme Corp" -Operator "Jane Doe"

.EXAMPLE
    $env:CURSOR_API_KEY = "crsr_..."
    .\aiscan.ps1 cloud-agents -OutDir C:\scans\today
    Opt-in inventory of Cursor cloud agents. Not part of 'all'.

.EXAMPLE
    .\aiscan.ps1 telemetry -OutDir C:\scans\today -OtelFile C:\exports\otel.json -SplunkExport C:\exports\usage.csv
    Opt-in import of local telemetry exports. Not part of 'all'.

.EXAMPLE
    .\aiscan.ps1 all -OutDir C:\scans\2026-10-07 -Previous C:\scans\2026-10-01 -Briefing
    Offline collectors, then a changes envelope versus the previous scan, then the HTML briefing.

.EXAMPLE
    .\aiscan.ps1 all -OutDir C:\scans\today -AgentMode
    Summary table and errors stay. Paths are relative to that folder, and the
    closing "Evidence kept at" line is omitted.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $false, Position = 0)]
    [ValidateSet("claude", "cowork", "cursor", "codex", "copilot", "chat-history",
        "git-posture", "secrets-scan", "pii-scan", "grok", "grok-bot",
        "cloud-agents", "telemetry", "discover", "all")]
    [string]$Collector = "all",

    [switch]$Json,

    [string]$RepoRoots,

    [switch]$Keep,

    [switch]$Redact,

    [switch]$LocalLinks,

    [string]$OutDir,

    [switch]$Here,

    [switch]$Briefing,

    [string]$Customer,

    [string]$Operator,

    [switch]$IncludeRunResult,

    [string[]]$OtelFile,

    [string[]]$SplunkExport,

    [string]$Previous,

    [string]$HistoryRoot,

    [switch]$AgentMode
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Continue"

if ($Here -and $OutDir) {
    Write-Host "-Here and -OutDir are mutually exclusive. Use one output target." -ForegroundColor Red
    exit 1
}

# aiscan runs on your own machine, so it shows real rules/paths/samples by default.
# The collectors read AISCAN_REDACT centrally (sanitize_text). -Redact turns on
# masking for output you intend to share.
if ($Redact) { $env:AISCAN_REDACT = "1" } else { $env:AISCAN_REDACT = $null }
if ($AgentMode) { $env:AISCAN_AGENT_MODE = "1" } else { $env:AISCAN_AGENT_MODE = $null }
$UseLocalLinks = [bool]$LocalLinks
if ($LocalLinks -and $Redact) {
    Write-Host "-Redact turns off -LocalLinks; building a shareable briefing without local paths." -ForegroundColor Yellow
    $UseLocalLinks = $false
}
$env:PYTHONUTF8 = "1"
$env:PYTHONIOENCODING = "utf-8"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$CoreDir = Join-Path $ScriptDir "core"
$ComponentsDir = Join-Path $ScriptDir "components"
$Python = "python"

# tomllib is stdlib only in Python 3.11+. Stop here so an older python fails
# with a clear message instead of dying inside the first collector that imports it.
# The -c script contains no double quotes: Windows PowerShell 5.1 drops those
# when it rebuilds a native command line.
if (-not (Get-Command -Name $Python -ErrorAction SilentlyContinue)) {
    Write-Host "Python 3.11 or newer is required, and 'python' was not found on PATH." -ForegroundColor Red
    exit 1
}
# A function or alias named python does not set $LASTEXITCODE. Under
# Set-StrictMode an unset $LASTEXITCODE throws, and a stale code from an
# earlier native command would be blamed on this probe. Zero it, keep what
# the probe itself wrote, then clear it so later steps are not affected.
$global:LASTEXITCODE = 0
$versionText = & $Python -c "import sys; sys.stdout.write('%d.%d.%d' % (sys.version_info[0], sys.version_info[1], sys.version_info[2]))" 2>$null
$pythonExit = $global:LASTEXITCODE
if ($null -eq $pythonExit) { $pythonExit = 0 }
$global:LASTEXITCODE = 0
$versionText = "$versionText".Trim()
$parsed = $versionText -match '^(\d+)\.(\d+)\.\d+$'
$tooOld = $false
if ($parsed) {
    $pyMajor = [int]$Matches[1]
    $pyMinor = [int]$Matches[2]
    $tooOld = ($pyMajor -lt 3) -or (($pyMajor -eq 3) -and ($pyMinor -lt 11))
}
if ($pythonExit -ne 0 -or -not $parsed -or $tooOld) {
    if ($tooOld) {
        Write-Host "Python $versionText is too old. aiscan needs Python 3.11 or newer (it uses tomllib)." -ForegroundColor Red
    }
    else {
        Write-Host "Python 3.11 or newer is required, but 'python' did not report a usable version." -ForegroundColor Red
    }
    exit 1
}

# core/ holds shared common.py + paths.py; every collector script imports them.
# Prepend so child Python processes resolve imports without an install step.
$env:PYTHONPATH = if ($env:PYTHONPATH) { "$CoreDir;$env:PYTHONPATH" } else { $CoreDir }

# Map collector name -> components/<name>/<script>.py
$ScriptFor = @{
    "claude"       = "claude\claude.py"
    "cowork"       = "cowork\cowork.py"
    "cursor"       = "cursor\cursor.py"
    "codex"        = "codex\codex.py"
    "copilot"      = "copilot\copilot.py"
    "chat-history" = "chat-history\chat-history.py"
    "git-posture"  = "git-posture\git-posture.py"
    "secrets-scan" = "secrets-scan\secrets-scan.py"
    "pii-scan"     = "pii-scan\pii-scan.py"
    "grok"         = "grok\grok.py"
    "grok-bot"     = "grok-bot\grok-bot.py"
    "cloud-agents" = "cloud-agents\cloud-agents.py"
    "telemetry"    = "telemetry-import\telemetry-import.py"
}

# Opt-in collectors stay out of $StdlibOrder: cloud-agents (network) and
# telemetry (local export files). A GitHub access inventory, if added later,
# is the same kind of opt-in and must not be appended here.

# Collectors run by 'all', in order. pii-scan runs last so it can pick up the
# chat-history export under raw/ from the same run.
$StdlibOrder = @("claude", "cowork", "cursor", "codex", "copilot", "chat-history",
    "git-posture", "secrets-scan", "grok", "grok-bot", "pii-scan")

# Resolve real tool-history paths via the shared discover.py so coverage
# includes override locations. The --json output is SENSITIVE (raw filesystem
# paths). It is used transiently to build child-process args only; it is never
# printed or written.
$script:PathArgs = @()
$script:NativeRoots = @()
function Resolve-Discovery {
    $script:PathArgs = @()
    $script:NativeRoots = @()
    try {
        $discJson = & $Python (Join-Path $CoreDir "discover.py") "--json"
        if ($LASTEXITCODE -eq 0 -and $discJson) {
            $disc = ($discJson | Out-String) | ConvertFrom-Json
            if ($disc.PSObject.Properties.Name -contains "cli_args" -and $disc.cli_args) {
                $script:PathArgs = @($disc.cli_args)
            }
            if ($disc.PSObject.Properties.Name -contains "native_dirs" -and $disc.native_dirs) {
                foreach ($d in @($disc.native_dirs.claude_projects, $disc.native_dirs.codex_sessions, $disc.native_dirs.cursor_projects, $disc.native_dirs.grok_sessions)) {
                    if ($d) { $script:NativeRoots += @("--native-roots", $d) }
                }
            }
        }
        else {
            Write-Host "Path discovery returned no data; collectors use defaults." -ForegroundColor DarkGray
        }
    }
    catch {
        Write-Host "Path discovery failed; collectors use defaults." -ForegroundColor DarkGray
    }
}

function Get-CollectorExtras {
    param([string]$Name)
    $extra = @()
    switch ($Name) {
        { $_ -in @("claude", "codex") } {
            $extra += $script:PathArgs
        }
        "cursor" {
            $extra += $script:PathArgs
            if ($RepoRoots) { $extra += @("--repo-roots", $RepoRoots) }
        }
        "grok" {
            $extra += $script:PathArgs
            if ($RepoRoots) { $extra += @("--repo-roots", $RepoRoots) }
        }
        "chat-history" {
            $extra += $script:PathArgs
            $extra += "--include-tool-details"
        }
        "git-posture" {
            if ($RepoRoots) { $extra += @("--repo-roots", $RepoRoots) }
        }
        "secrets-scan" {
            if ($RepoRoots) { $extra += @("--repo-roots", $RepoRoots) }
            $extra += $script:NativeRoots
        }
        "pii-scan" {
            # Path overrides only; pii-scan resolves its own default targets
            # (raw\chat-history export + native chat locations) from these.
            $extra += $script:PathArgs
        }
        "cloud-agents" {
            if ($IncludeRunResult) { $extra += "--include-run-result" }
        }
        "telemetry" {
            if ($OtelFile) {
                foreach ($path in @($OtelFile)) {
                    if ($path) { $extra += @("--otel-file", $path) }
                }
            }
            if ($SplunkExport) {
                foreach ($path in @($SplunkExport)) {
                    if ($path) { $extra += @("--splunk-export", $path) }
                }
            }
        }
    }
    return $extra
}

# Drop a previous run's envelope before this collector starts. A reused
# -OutDir must not keep an old file when the new run fails to write one.
function Clear-CollectorEvidence {
    param(
        [string]$Name,
        [string]$EvidenceRoot
    )
    $script:StaleEvidenceRemained = $false
    $evidenceFile = Join-Path $EvidenceRoot "evidence\$Name.json"
    if (-not (Test-Path -LiteralPath $evidenceFile)) { return }
    Remove-Item -LiteralPath $evidenceFile -Force -ErrorAction SilentlyContinue
    if (Test-Path -LiteralPath $evidenceFile) {
        $script:StaleEvidenceRemained = $true
        Write-Host "Could not clear previous evidence for $Name." -ForegroundColor Red
    }
}

# A readable envelope is a JSON object with findings and platform_detected.
# null, an array, or any other JSON is not evidence.
function Read-EvidenceEnvelope {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return $null }
    try {
        $raw = Read-EvidenceText -Path $Path
        if ($null -eq $raw -or "$raw".Trim() -eq "") { return $null }
        $parsedJson = $raw | ConvertFrom-Json -ErrorAction Stop
    }
    catch {
        return $null
    }
    if ($null -eq $parsedJson) { return $null }
    if ($parsedJson -is [System.Array]) { return $null }
    $names = @($parsedJson.PSObject.Properties.Name)
    if (($names -notcontains "findings") -or ($names -notcontains "platform_detected")) {
        return $null
    }
    return $parsedJson
}

# Runs one collector against $EvidenceRoot. Returns the exit code.
function Invoke-OneCollector {
    param(
        [string]$Name,
        [string]$EvidenceRoot
    )
    Clear-CollectorEvidence -Name $Name -EvidenceRoot $EvidenceRoot
    if ($script:StaleEvidenceRemained) { return 1 }
    $scriptPath = Join-Path $ComponentsDir $ScriptFor[$Name]
    if (-not (Test-Path -LiteralPath $scriptPath)) {
        $shown = Format-AiscanPath -Path $scriptPath -Root $ScriptDir
        Write-Host "Collector script missing: $shown" -ForegroundColor Yellow
        return 1
    }

    $args = @(
        $scriptPath,
        "--evidence-root", $EvidenceRoot,
        "--raw-root", (Join-Path $EvidenceRoot "raw")
    )
    $args += Get-CollectorExtras -Name $Name

    # Suppress the collector's own stdout ("Wrote <path>" line); we print the JSON
    # ourselves. stderr passes through. Out-Null keeps it out of the return value.
    & $Python @args | Out-Null
    return $LASTEXITCODE
}

# Banner version. core/tool_version.py is the source of truth. The fallback
# covers a machine where that helper cannot run: VERSION file, then "dev".
function Get-AiscanVersion {
    $helper = Join-Path $CoreDir "tool_version.py"
    if ((Test-Path -LiteralPath $helper) -and (Get-Command $Python -ErrorAction SilentlyContinue)) {
        $out = & $Python $helper 2>$null
        if ($LASTEXITCODE -eq 0 -and $out) {
            $text = "$($out | Select-Object -Last 1)".Trim()
            if ($text) { return $text }
        }
    }
    $versionFile = Join-Path $ScriptDir "VERSION"
    if (Test-Path -LiteralPath $versionFile) {
        $line = "$(Get-Content -LiteralPath $versionFile -TotalCount 1)".Trim().TrimStart([char]0xFEFF)
        if ($line) { return $line }
    }
    return "dev"
}

# One collector, in the form core/run_status.py reads:
# "<exit>,<1 if an evidence file exists>,<1 if that file parsed>".
function New-CollectorStatusRow {
    param(
        [int]$ExitCode,
        [bool]$HasEvidence,
        [bool]$Parsed
    )
    $hasFlag = if ($HasEvidence) { "1" } else { "0" }
    $parsedFlag = if ($Parsed) { "1" } else { "0" }
    return "$ExitCode,$hasFlag,$parsedFlag"
}

# 2 when any collector errors or its evidence does not parse.
# 3 when collectors were fine and only the briefing failed.
# 0 otherwise, including "platform not detected".
function Get-AiscanScanExitCode {
    param(
        [string[]]$Rows,
        [bool]$BriefingFailed
    )
    $helper = Join-Path $CoreDir "run_status.py"
    $brief = if ($BriefingFailed) { "1" } else { "0" }
    $argList = @($helper)
    if ($Rows) { $argList += $Rows }
    $argList += @("--briefing", $brief)
    $out = & $Python @argList
    if ($LASTEXITCODE -eq 0 -and $null -ne $out) {
        return [int]("$($out | Select-Object -Last 1)".Trim())
    }
    Write-Host "Could not compute the scan exit code." -ForegroundColor Yellow
    return 2
}

# In -AgentMode, paths under the scan folder are printed relative to it.
function Format-AiscanPath {
    param(
        [string]$Path,
        [string]$Root
    )
    if (-not $AgentMode -or -not $Path -or -not $Root) { return $Path }
    $sep = [System.IO.Path]::DirectorySeparatorChar
    $rootFull = [System.IO.Path]::GetFullPath($Root).TrimEnd('\', '/')
    $pathFull = [System.IO.Path]::GetFullPath($Path)
    if ($pathFull.Equals($rootFull, [System.StringComparison]::OrdinalIgnoreCase)) {
        return "."
    }
    $prefix = $rootFull + $sep
    if ($pathFull.StartsWith($prefix, [System.StringComparison]::OrdinalIgnoreCase)) {
        return $pathFull.Substring($prefix.Length)
    }
    return $Path
}

# Replace scan-folder and repo-folder prefixes inside a message. Used for
# exception text, where the path is in the middle of the sentence.
function Format-AiscanText {
    param(
        [string]$Text,
        [string[]]$Roots
    )
    if (-not $AgentMode -or -not $Text) { return $Text }
    $out = $Text
    foreach ($base in @($Roots)) {
        if (-not $base) { continue }
        try {
            $full = [System.IO.Path]::GetFullPath($base).TrimEnd('\', '/')
        }
        catch { continue }
        if (-not $full -or $full.Length -lt 3) { continue }
        $out = $out.Replace($full, ".")
        $slash = $full.Replace('\', '/')
        if ($slash -ne $full) { $out = $out.Replace($slash, ".") }
        $back = $full.Replace('/', '\')
        if ($back -ne $full) { $out = $out.Replace($back, ".") }
    }
    return $out
}

function New-PeekRoot {
    # -Here/-OutDir make the root persistent (same evidence/raw layout);
    # otherwise fall back to a throwaway temp directory, same as always.
    $root = if ($OutDir) {
        $OutDir
    }
    elseif ($Here) {
        (Get-Location).ProviderPath
    }
    else {
        # Seconds alone collide when two runs start together. -Force would
        # then let them share the folder, and one cleanup would delete the other.
        $stamp = Get-Date -Format "yyyyMMdd-HHmmss"
        $nonce = [guid]::NewGuid().ToString("N").Substring(0, 8)
        Join-Path $env:TEMP "aiscan-$stamp-$nonce"
    }
    New-Item -ItemType Directory -Force -Path (Join-Path $root "evidence") | Out-Null
    New-Item -ItemType Directory -Force -Path (Join-Path $root "raw") | Out-Null
    return $root
}

function Remove-PeekRoot {
    param([string]$Root)
    # -Briefing implies keep: the briefing.html lives inside the root and the
    # browser opens it asynchronously; deleting the root would race the open.
    if ($Keep -or $OutDir -or $Here -or $Briefing) {
        Write-Host ""
        # -AgentMode drops this absolute path. The warning line stays.
        if (-not $AgentMode) {
            Write-Host "Evidence kept at: $Root" -ForegroundColor Cyan
        }
        if ($Redact) {
            # Only files written by this run are redacted. A reused -OutDir can
            # still hold an older unredacted evidence file or briefing.
            Write-Host "Redaction was on for this run: evidence and the briefing written now are redacted. raw\ is NOT redacted, keep it local. Files left from earlier runs in this folder are not re-redacted." -ForegroundColor DarkGray
        }
        else {
            Write-Host "(unredacted by default: real secrets / paths / transcript metadata - delete when done)" -ForegroundColor DarkGray
        }
    }
    else {
        Remove-Item -LiteralPath $Root -Recurse -Force -ErrorAction SilentlyContinue
    }
}

function Read-EvidenceText {
    param([string]$Path)
    # Windows PowerShell 5.1 reads a BOM-less file with the ANSI code page.
    # Collectors write UTF-8. -Encoding UTF8 is that code page on 5.1 and
    # UTF-8 on PowerShell 7.
    return Get-Content -LiteralPath $Path -Encoding UTF8 -Raw
}

# Writes evidence\changes.json by comparing this scan with the previous one.
# Failures warn and fall through; the briefing then says changes were not collected.
function Invoke-ScanDiff {
    param([string]$Root)
    $diffScript = Join-Path $CoreDir "scan_diff.py"
    if (-not (Test-Path -LiteralPath $diffScript)) {
        Write-Host "scan_diff.py not found; changes will be marked not collected." -ForegroundColor Yellow
        return
    }
    Write-Host ""
    Write-Host "Computing changes versus the previous scan..." -ForegroundColor Cyan
    $diffArgs = @($diffScript, "--current", $Root)
    if ($Previous) {
        $diffArgs += @("--previous", $Previous)
    }
    elseif ($HistoryRoot) {
        $diffArgs += @("--history-root", $HistoryRoot)
    }
    elseif (-not $OutDir -and -not $Here) {
        # A throwaway folder's parent is TEMP. Do not treat other temp dirs as scan history.
        $diffArgs += @("--history-root", $Root)
    }
    & $Python @diffArgs
    if ($LASTEXITCODE -ne 0) {
        Write-Host "Scan diff failed (exit $LASTEXITCODE). The briefing will say changes were not collected." -ForegroundColor Yellow
    }
}

# Builds the HTML briefing from the evidence root. Failures warn and fall
# through; a briefing is a nice-to-have on a local scan, not a gate.
function Invoke-AiscanBriefing {
    param([string]$Root)
    # Stays true until the HTML is written. Opening the browser is separate:
    # a failed Start-Process does not fail the briefing.
    $script:AiscanBriefingFailed = $true
    $briefingScript = Join-Path $ScriptDir "report\build-briefing.py"
    $briefingName = if ($UseLocalLinks) { "briefing-local.html" } else { "briefing.html" }
    $briefingOut = Join-Path $Root "briefing\$briefingName"
    if (-not (Test-Path -LiteralPath $briefingScript)) {
        Write-Host "build-briefing.py not found; skipping briefing." -ForegroundColor Yellow
        return
    }
    New-Item -ItemType Directory -Force -Path (Split-Path $briefingOut) | Out-Null
    Write-Host ""
    Write-Host "Building briefing..." -ForegroundColor Cyan
    $briefingArgs = @(
        $briefingScript,
        "--evidence-root", $Root,
        "--out", $briefingOut
    )
    if ($UseLocalLinks) { $briefingArgs += "--local-links" }
    if ($Customer) { $briefingArgs += @("--customer", $Customer) }
    if ($Operator) { $briefingArgs += @("--operator", $Operator) }
    try {
        & $Python @briefingArgs
        $code = $LASTEXITCODE
    }
    catch {
        $detail = Format-AiscanText -Text "$_" -Roots @($Root, $ScriptDir)
        Write-Host "Briefing generation threw: $detail" -ForegroundColor Yellow
        return
    }
    if ($code -ne 0) {
        Write-Host "Briefing generation failed (exit $code)." -ForegroundColor Yellow
        return
    }
    Write-Host ("Briefing written: {0}" -f (Format-AiscanPath -Path $briefingOut -Root $Root)) -ForegroundColor Green
    try {
        # Continue would swallow a non-terminating Start-Process error and
        # still print the success line. Stop makes that error hit the catch.
        Start-Process -FilePath $briefingOut -ErrorAction Stop
        Write-Host "Opened briefing in default browser" -ForegroundColor Green
    }
    catch {
        $detail = Format-AiscanText -Text "$_" -Roots @($Root, $ScriptDir)
        Write-Host "Could not open briefing automatically: $detail" -ForegroundColor Yellow
    }
    $script:AiscanBriefingFailed = $false
}

function Get-SevColor {
    param([string]$Severity)
    switch ("$Severity".ToLower()) {
        "critical" { "Red" }
        "high"     { "Red" }
        "medium"   { "Yellow" }
        "low"      { "DarkGray" }
        default    { "Gray" }
    }
}

# Truncate a single-line string to $Max chars with an ellipsis.
function Limit-Str {
    param([string]$Text, [int]$Max = 64)
    $t = ("$Text" -replace "\s+", " ").Trim()
    if ($t.Length -gt $Max) { return $t.Substring(0, $Max - 3) + "..." }
    return $t
}

# Human-readable console rendering of one collector result object.
function Show-Peek {
    param([Parameter(Mandatory = $true)] $Result)

    $hasProp = { param($obj, $name) $obj.PSObject.Properties.Name -contains $name }

    # --- header ---
    $detected = if ((& $hasProp $Result "platform_detected")) { $Result.platform_detected } else { "?" }
    $ranAt = if ((& $hasProp $Result "ran_at")) { $Result.ran_at } else { "" }
    $host_ = if ((& $hasProp $Result "host")) { $Result.host } else { "" }
    $scope = if ((& $hasProp $Result "scope_hash")) { "$($Result.scope_hash)".Substring(0, [Math]::Min(12, "$($Result.scope_hash)".Length)) } else { "" }

    Write-Host ("{0}  " -f $Result.collector) -ForegroundColor Cyan -NoNewline
    Write-Host ("v{0}  detected={1}  host={2}  scope={3}" -f $Result.version, $detected, $host_, $scope) -ForegroundColor DarkGray
    Write-Host ("ran {0}" -f $ranAt) -ForegroundColor DarkGray

    # --- summary ---
    if ((& $hasProp $Result "summary") -and $null -ne $Result.summary) {
        Write-Host ""
        Write-Host "Summary" -ForegroundColor White
        foreach ($p in $Result.summary.PSObject.Properties) {
            Write-Host ("  {0,-18} {1}" -f $p.Name, $p.Value)
        }
    }

    # --- findings ---
    # Direct assignment (not an if-expression): an if/else block that emits an
    # empty array unrolls to $null, and $null.Count throws under StrictMode.
    $findings = @()
    if ((& $hasProp $Result "findings") -and $null -ne $Result.findings) {
        $findings = @($Result.findings)
    }
    Write-Host ""
    Write-Host ("Findings ({0})" -f $findings.Count) -ForegroundColor White
    if ($findings.Count -gt 0) {
        $sevRank = @{ critical = 0; high = 1; medium = 2; low = 3 }
        $sorted = $findings | Sort-Object @{ Expression = { if ($sevRank.ContainsKey("$($_.severity)".ToLower())) { $sevRank["$($_.severity)".ToLower()] } else { 9 } } }
        foreach ($f in $sorted) {
            $sev = "$($f.severity)".ToUpper()
            Write-Host ("  [{0,-8}] " -f $sev) -ForegroundColor (Get-SevColor $f.severity) -NoNewline
            Write-Host ("{0}" -f $f.title)
            Write-Host ("             {0}  |  {1}  |  evidence={2}" -f $f.category, $f.id, $f.evidence_count) -ForegroundColor DarkGray
            if ((& $hasProp $f "sample_redacted") -and $f.sample_redacted) {
                Write-Host ("             {0}" -f (Limit-Str $f.sample_redacted 80)) -ForegroundColor DarkGray
            }
        }
    }

    # --- rules ---
    $rules = @()
    if ((& $hasProp $Result "rules") -and $null -ne $Result.rules) {
        $rules = @($Result.rules)
    }
    if ($rules.Count -gt 0) {
        Write-Host ""
        Write-Host ("Rules ({0})" -f $rules.Count) -ForegroundColor White
        $rules |
            Select-Object `
                @{ N = "Decision"; E = { $_.decision } },
                @{ N = "Risk"; E = { $_.risk } },
                @{ N = "Type"; E = { $_.rule_type } },
                @{ N = "Category"; E = { $_.exposure_category } },
                @{ N = "Rule"; E = { Limit-Str $_.rule 60 } } |
            Format-Table -AutoSize
    }

    # --- raw pointers ---
    if ((& $hasProp $Result "raw_pointers") -and $null -ne $Result.raw_pointers) {
        $rp = @($Result.raw_pointers)
        if ($rp.Count -gt 0) {
            Write-Host ("Raw pointers: {0}" -f $rp.Count) -ForegroundColor DarkGray
        }
    }
    Write-Host ""
}

# --- discover: read-only, no temp dir ---
if ($Collector -eq "discover") {
    & $Python (Join-Path $CoreDir "discover.py")
    exit $LASTEXITCODE
}

# Banner version, also stamped on every evidence envelope via AISCAN_VERSION.
# After discover returns, so a path listing does not spawn git.
$AiscanVersion = Get-AiscanVersion
$env:AISCAN_VERSION = $AiscanVersion

# Resolve real history paths once (skipped for the 'discover' command above).
# Feeds the shared path overrides into every collector.
Resolve-Discovery

# --- all: run collectors, combined summary ---
if ($Collector -eq "all") {
    $root = New-PeekRoot
    Write-Host "aiscan $AiscanVersion" -ForegroundColor DarkGray
    $rows = @()
    $statusRows = @()
    foreach ($name in $StdlibOrder) {
        Write-Host "Running $name..." -ForegroundColor Cyan
        $code = Invoke-OneCollector -Name $name -EvidenceRoot $root
        if ($null -eq $code) { $code = 1 }
        $jsonPath = Join-Path $root "evidence\$name.json"
        $findings = "-"
        $detected = "-"
        $hasEvidence = $false
        $parsed = $false
        # Collectors write their evidence envelope even when the platform is not
        # detected (exit 2). Exit 2 WITHOUT an envelope is a real failure (e.g.
        # argparse rejects bad args with exit 2), not "not detected". A file
        # left from an earlier run was removed before this collector started.
        if ($script:StaleEvidenceRemained) {
            $detected = "error (exit $code)"
        }
        else {
            $hasEvidence = Test-Path -LiteralPath $jsonPath
            if ($hasEvidence) {
                $j = Read-EvidenceEnvelope -Path $jsonPath
                if ($null -ne $j) {
                    $parsed = $true
                    if ($j.PSObject.Properties.Name -contains "findings") { $findings = @($j.findings).Count }
                    if ($j.PSObject.Properties.Name -contains "platform_detected") { $detected = $j.platform_detected }
                    if ($code -eq 2) { $detected = "not detected" }
                    elseif ($code -ne 0) { $detected = "error (exit $code)" }
                }
                else { $detected = "parse error" }
            }
            elseif ($code -ne 0) {
                $detected = "error (exit $code)"
            }
            else {
                $detected = "error (no evidence)"
            }
        }
        $statusRows += (New-CollectorStatusRow -ExitCode $code -HasEvidence $hasEvidence -Parsed $parsed)
        $rows += [PSCustomObject]@{ Collector = $name; Detected = $detected; Findings = $findings }
    }
    Write-Host ""
    $rows | Format-Table -AutoSize
    $script:AiscanBriefingFailed = $false
    if ($Briefing) {
        Invoke-ScanDiff -Root $root
        Invoke-AiscanBriefing -Root $root
    }
    Remove-PeekRoot -Root $root
    exit (Get-AiscanScanExitCode -Rows $statusRows -BriefingFailed $script:AiscanBriefingFailed)
}

# --- single collector ---
$root = New-PeekRoot
$code = Invoke-OneCollector -Name $Collector -EvidenceRoot $root
if ($null -eq $code) { $code = 1 }
$jsonPath = Join-Path $root "evidence\$Collector.json"
$hasEvidence = $false
$parsed = $false
$j = $null
if (-not $script:StaleEvidenceRemained) {
    $hasEvidence = Test-Path -LiteralPath $jsonPath
    if ($hasEvidence) {
        $j = Read-EvidenceEnvelope -Path $jsonPath
        if ($null -ne $j) { $parsed = $true }
    }
}

# Exit 2 with a readable envelope means "platform not detected". Exit 2
# without one is a real failure (argparse errors also exit 2). No file at
# all is a failure too, including exit 0: the collector wrote nothing.
if ($script:StaleEvidenceRemained) {
    Write-Host ""
    Write-Host "$Collector failed (exit $code)." -ForegroundColor Red
}
elseif ($parsed -and $code -eq 2) {
    Write-Host ""
    Write-Host "${Collector}: platform not detected (tool not installed, no local data, or no telemetry export)." -ForegroundColor Yellow
}
elseif ($hasEvidence -and -not $parsed) {
    Write-Host ""
    Write-Host "$Collector evidence could not be parsed." -ForegroundColor Red
}
elseif ($code -ne 0) {
    Write-Host ""
    Write-Host "$Collector failed (exit $code)." -ForegroundColor Red
}
elseif (-not $hasEvidence) {
    Write-Host ""
    Write-Host "$Collector produced no evidence file." -ForegroundColor Yellow
}

if ($parsed -and $code -eq 0) {
    Write-Host ""
    if ($Json) {
        Read-EvidenceText -Path $jsonPath
    }
    else {
        Show-Peek -Result $j
    }
}

$script:AiscanBriefingFailed = $false
# A hard failure or a parse error skips the briefing; those already exit 2.
if ($Briefing -and -not $parsed) {
    Write-Host "Briefing skipped because $Collector did not write a readable evidence file." -ForegroundColor Yellow
}
if ($Briefing -and $parsed -and ($code -eq 0 -or $code -eq 2)) {
    Invoke-ScanDiff -Root $root
    Invoke-AiscanBriefing -Root $root
}
Remove-PeekRoot -Root $root
exit (Get-AiscanScanExitCode -Rows @((New-CollectorStatusRow -ExitCode $code -HasEvidence $hasEvidence -Parsed $parsed)) -BriefingFailed $script:AiscanBriefingFailed)
