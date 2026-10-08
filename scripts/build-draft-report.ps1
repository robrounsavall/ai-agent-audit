#Requires -Version 5.1
<#
.SYNOPSIS
    Build the report v2 HTML briefing from an evidence root.

.DESCRIPTION
    Computes scan-to-scan changes, optionally imports telemetry export files
    into the evidence root, then writes one offline HTML file.

    With no -EvidenceRoot, builds the synthetic draft from samples\synthetic-demo
    (current), samples\synthetic-previous (previous), and the sample telemetry
    exports. That is how samples\report-v2-draft.html is produced. The synthetic
    files in the repo are not modified; the script copies them to a temp folder.

.PARAMETER EvidenceRoot
    Folder that contains an evidence\ directory from a real scan.

.PARAMETER Previous
    Earlier evidence root. When omitted on a real scan, scan_diff picks the
    newest earlier sibling under the parent of -EvidenceRoot (or -HistoryRoot).

.PARAMETER HistoryRoot
    Folder of dated scan directories. Used only when -Previous is omitted.

.PARAMETER Out
    HTML path to write. Default for a real scan is
    <EvidenceRoot>\briefing\report-v2.html. Default for the synthetic draft is
    samples\report-v2-draft.html.

.PARAMETER OtelFile
    Repeatable path to an OTLP JSON or JSON-lines tool_decision export.

.PARAMETER SplunkExport
    Repeatable path to a Splunk JSON or CSV export (approvals and/or Cursor
    dashboard usage). Cursor cost_cents is labeled as coming from that export.

.PARAMETER Customer
    Name shown on the briefing. Synthetic default is "Test User".

.PARAMETER Operator
    Name shown on the briefing. Synthetic default is "Demo operator".

.EXAMPLE
    .\scripts\build-draft-report.ps1 -EvidenceRoot C:\scans\2026-10-07 -Previous C:\scans\2026-10-01 -Out C:\scans\2026-10-07\briefing\report-v2.html -OtelFile C:\exports\otel.json -SplunkExport C:\exports\cursor-usage.csv

.EXAMPLE
    .\scripts\build-draft-report.ps1
    Regenerates samples\report-v2-draft.html from the synthetic fixtures.
#>
[CmdletBinding()]
param(
    [string]$EvidenceRoot,

    [string]$Previous,

    [string]$HistoryRoot,

    [string]$Out,

    [string[]]$OtelFile,

    [string[]]$SplunkExport,

    [string]$Customer,

    [string]$Operator
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = Split-Path -Parent $ScriptDir
$Python = "python"
$CoreDir = Join-Path $RepoRoot "core"
$env:PYTHONPATH = if ($env:PYTHONPATH) { "$CoreDir;$env:PYTHONPATH" } else { $CoreDir }
$env:PYTHONUTF8 = "1"
$env:PYTHONIOENCODING = "utf-8"

$synthetic = -not $EvidenceRoot
$workRoot = $EvidenceRoot
$cleanup = $null

if ($synthetic) {
    $cleanup = Join-Path ([System.IO.Path]::GetTempPath()) ("aiscan-draft-" + [guid]::NewGuid().ToString("N"))
    # The scan folder's own name is what changes.json records as the label.
    $workRoot = Join-Path $cleanup "synthetic-demo"
    New-Item -ItemType Directory -Force -Path $workRoot | Out-Null
    Copy-Item -Path (Join-Path $RepoRoot "samples\synthetic-demo\*") -Destination $workRoot -Recurse -Force
    if (-not $Previous) {
        $Previous = Join-Path $RepoRoot "samples\synthetic-previous"
    }
    if (-not $OtelFile) {
        $OtelFile = @((Join-Path $RepoRoot "samples\telemetry-import\otel-tool-decisions.json"))
    }
    if (-not $SplunkExport) {
        $SplunkExport = @((Join-Path $RepoRoot "samples\telemetry-import\splunk-cursor-usage.csv"))
    }
    if (-not $Out) {
        $Out = Join-Path $RepoRoot "samples\report-v2-draft.html"
    }
    if (-not $Customer) { $Customer = "Test User" }
    if (-not $Operator) { $Operator = "Demo operator" }
}
elseif (-not $Out) {
    $Out = Join-Path $EvidenceRoot "briefing\report-v2.html"
}

if (-not (Test-Path -LiteralPath (Join-Path $workRoot "evidence"))) {
    Write-Host "No evidence directory under $workRoot" -ForegroundColor Red
    exit 1
}

try {
    $telemetryScript = Join-Path $RepoRoot "components\telemetry-import\telemetry-import.py"
    $haveTelemetry = @($OtelFile + $SplunkExport | Where-Object { $_ })
    if ($haveTelemetry.Count -gt 0) {
        $telArgs = @($telemetryScript, "--evidence-root", $workRoot)
        foreach ($path in @($OtelFile)) {
            if ($path) { $telArgs += @("--otel-file", $path) }
        }
        foreach ($path in @($SplunkExport)) {
            if ($path) { $telArgs += @("--splunk-export", $path) }
        }
        & $Python @telArgs
        if ($LASTEXITCODE -ne 0 -and $LASTEXITCODE -ne 2) {
            Write-Host "Telemetry import failed (exit $LASTEXITCODE)." -ForegroundColor Red
            exit $LASTEXITCODE
        }
    }

    $diffArgs = @(
        (Join-Path $CoreDir "scan_diff.py"),
        "--current", $workRoot
    )
    if ($Previous) {
        $diffArgs += @("--previous", $Previous)
    }
    elseif ($HistoryRoot) {
        $diffArgs += @("--history-root", $HistoryRoot)
    }
    & $Python @diffArgs
    if ($LASTEXITCODE -ne 0) {
        Write-Host "Scan diff failed (exit $LASTEXITCODE)." -ForegroundColor Red
        exit $LASTEXITCODE
    }

    $outDir = Split-Path -Parent $Out
    if ($outDir -and -not (Test-Path -LiteralPath $outDir)) {
        New-Item -ItemType Directory -Force -Path $outDir | Out-Null
    }
    $briefArgs = @(
        (Join-Path $RepoRoot "report\build-briefing.py"),
        "--evidence-root", $workRoot,
        "--out", $Out
    )
    if ($Customer) { $briefArgs += @("--customer", $Customer) }
    if ($Operator) { $briefArgs += @("--operator", $Operator) }
    & $Python @briefArgs
    if ($LASTEXITCODE -ne 0) {
        Write-Host "Briefing build failed (exit $LASTEXITCODE)." -ForegroundColor Red
        exit $LASTEXITCODE
    }
    Write-Host "Wrote $Out" -ForegroundColor Green
}
finally {
    if ($cleanup) {
        Remove-Item -LiteralPath $cleanup -Recurse -Force -ErrorAction SilentlyContinue
    }
}
exit 0
