#Requires -Version 5.1
<#
.SYNOPSIS
    Local AI coding agent posture scan (one collector or all stdlib collectors).

.DESCRIPTION
    Runs the collectors against a throwaway temp directory and prints results to
    the console. Read-only against tool data, offline, no network calls. Use this
    to see what the collectors find on your own machine.

    Only pii-scan needs the venv + presidio deps. Every other collector runs on
    stock Python with no install. secrets-scan needs gitleaks.exe on PATH.

.PARAMETER Collector
    One of: claude cowork cursor codex copilot chat-history git-posture
    secrets-scan pii-scan grok discover all. Defaults to 'all' when omitted.

    'discover' is read-only and writes nothing.
    'all' runs the 9 stdlib collectors and prints a combined summary (skips pii-scan).

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

.EXAMPLE
    .\aiscan.ps1
    Runs every stdlib collector, unredacted, and prints a combined summary.

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
    .\aiscan.ps1 all -Here -Briefing -Customer "Acme Corp" -Operator "Jane Doe"
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $false, Position = 0)]
    [ValidateSet("claude", "cowork", "cursor", "codex", "copilot", "chat-history",
        "git-posture", "secrets-scan", "pii-scan", "grok", "discover", "all")]
    [string]$Collector = "all",

    [switch]$Json,

    [string]$RepoRoots,

    [switch]$Keep,

    [switch]$Redact,

    [string]$OutDir,

    [switch]$Here,

    [switch]$Briefing,

    [string]$Customer,

    [string]$Operator
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
$env:PYTHONUTF8 = "1"
$env:PYTHONIOENCODING = "utf-8"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$CoreDir = Join-Path $ScriptDir "core"
$ComponentsDir = Join-Path $ScriptDir "components"
$Python = "python"

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
}

# Stdlib collectors run by 'all' (pii-scan excluded: needs the venv).
$StdlibOrder = @("claude", "cowork", "cursor", "codex", "copilot", "chat-history",
    "git-posture", "secrets-scan", "grok")

function Test-Presidio {
    & $Python -c "import presidio_analyzer" 2>$null
    return ($LASTEXITCODE -eq 0)
}

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
    }
    return $extra
}

# Runs one collector against $EvidenceRoot. Returns the exit code.
function Invoke-OneCollector {
    param(
        [string]$Name,
        [string]$EvidenceRoot
    )
    $scriptPath = Join-Path $ComponentsDir $ScriptFor[$Name]
    if (-not (Test-Path -LiteralPath $scriptPath)) {
        Write-Host "Collector script missing: $scriptPath" -ForegroundColor Yellow
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
        Join-Path $env:TEMP "aiscan-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
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
        Write-Host "Evidence kept at: $Root" -ForegroundColor Cyan
        Write-Host "(unredacted by default: real secrets / paths / transcript metadata - delete when done)" -ForegroundColor DarkGray
    }
    else {
        Remove-Item -LiteralPath $Root -Recurse -Force -ErrorAction SilentlyContinue
    }
}

# Builds the HTML briefing from the evidence root. Failures warn and fall
# through; a briefing is a nice-to-have on a local scan, not a gate.
function Invoke-AiscanBriefing {
    param([string]$Root)
    $briefingScript = Join-Path $ScriptDir "report\build-briefing.py"
    $briefingOut = Join-Path $Root "briefing\briefing.html"
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
    if ($Customer) { $briefingArgs += @("--customer", $Customer) }
    if ($Operator) { $briefingArgs += @("--operator", $Operator) }
    try {
        & $Python @briefingArgs
        $code = $LASTEXITCODE
    }
    catch {
        Write-Host "Briefing generation threw: $_" -ForegroundColor Yellow
        return
    }
    if ($code -ne 0) {
        Write-Host "Briefing generation failed (exit $code)." -ForegroundColor Yellow
        return
    }
    Write-Host "Briefing written: $briefingOut" -ForegroundColor Green
    try {
        Start-Process -FilePath $briefingOut
    }
    catch {
        Write-Host "Could not open briefing automatically: $_" -ForegroundColor Yellow
    }
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

# Resolve real history paths once (skipped for the 'discover' command above).
# Feeds the shared path overrides into every collector.
Resolve-Discovery

# --- pii-scan preflight ---
if ($Collector -eq "pii-scan") {
    if (-not (Test-Presidio)) {
        Write-Host "pii-scan needs Presidio (venv + deps). It is the only collector that does." -ForegroundColor Yellow
        Write-Host "Set up:  python -m venv .venv; .\.venv\Scripts\Activate.ps1; pip install -r requirements.txt" -ForegroundColor Yellow
        Write-Host "Then:    python -m spacy download en_core_web_lg   (and re-run inside the venv)" -ForegroundColor Yellow
        exit 1
    }
}

# --- all: run stdlib collectors, combined summary ---
if ($Collector -eq "all") {
    $root = New-PeekRoot
    $rows = @()
    foreach ($name in $StdlibOrder) {
        Write-Host "Running $name..." -ForegroundColor Cyan
        $code = Invoke-OneCollector -Name $name -EvidenceRoot $root
        $jsonPath = Join-Path $root "evidence\$name.json"
        $findings = "-"
        $detected = "-"
        # Collectors write their evidence envelope even when the platform is not
        # detected (exit 2). Exit 2 WITHOUT an envelope is a real failure (e.g.
        # argparse rejects bad args with exit 2), not "not detected".
        if (Test-Path -LiteralPath $jsonPath) {
            try {
                $j = Get-Content -LiteralPath $jsonPath -Raw | ConvertFrom-Json
                if ($j.PSObject.Properties.Name -contains "findings") { $findings = @($j.findings).Count }
                if ($j.PSObject.Properties.Name -contains "platform_detected") { $detected = $j.platform_detected }
                if ($code -eq 2) { $detected = "not detected" }
            }
            catch { $detected = "parse error" }
        }
        elseif ($code -ne 0) {
            $detected = "error (exit $code)"
        }
        $rows += [PSCustomObject]@{ Collector = $name; Detected = $detected; Findings = $findings }
    }
    $rows += [PSCustomObject]@{ Collector = "pii-scan"; Detected = "skipped (needs venv + Presidio; run .\aiscan.ps1 pii-scan)"; Findings = "-" }
    Write-Host ""
    $rows | Format-Table -AutoSize
    if ($Briefing) { Invoke-AiscanBriefing -Root $root }
    Remove-PeekRoot -Root $root
    exit 0
}

# --- single collector ---
$root = New-PeekRoot
$code = Invoke-OneCollector -Name $Collector -EvidenceRoot $root

# Exit 2 with an evidence envelope means "platform not detected". Exit 2
# without one is a real failure (argparse errors also exit 2).
$evidenceWritten = Test-Path -LiteralPath (Join-Path $root "evidence\$Collector.json")
if ($code -eq 2 -and $evidenceWritten) {
    Write-Host ""
    Write-Host "${Collector}: platform not detected (tool not installed or no local data)." -ForegroundColor Yellow
    Remove-PeekRoot -Root $root
    exit 0
}
if ($code -ne 0) {
    Write-Host ""
    Write-Host "$Collector failed (exit $code)." -ForegroundColor Red
    Remove-PeekRoot -Root $root
    exit $code
}

$jsonPath = Join-Path $root "evidence\$Collector.json"
if (-not (Test-Path -LiteralPath $jsonPath)) {
    Write-Host "$Collector produced no evidence file." -ForegroundColor Yellow
    Remove-PeekRoot -Root $root
    exit 0
}

Write-Host ""
if ($Json) {
    Get-Content -LiteralPath $jsonPath -Raw
}
else {
    $j = Get-Content -LiteralPath $jsonPath -Raw | ConvertFrom-Json
    Show-Peek -Result $j
}

if ($Briefing) { Invoke-AiscanBriefing -Root $root }
Remove-PeekRoot -Root $root
exit 0
