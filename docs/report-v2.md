# Report v2

This page is the HTML briefing. It is one file. Open it in a browser. It does not need the network, a font download, or a web server.

The section tabs are the first thing on the page. The summary strip is on the Findings tab only. Under the title, the first fact is the run origin: who or what launched the scan, when it started, and why. An older folder with no `run-origin.txt` says `unknown` there. The summary also tells you which agents were detected, how many findings there are at each severity, and the change counts since the last scan, with a control that opens the Changes tab. If a cloud-agents inventory was collected, the summary also shows how many agents and how many tokens. If a telemetry export included approval decisions, the summary says how many were approved, how many were denied, and how many of the approvals came from a config rule. Token totals are not dollars. A dollar figure appears only when the Cursor dashboard usage export included `cost_cents`, and the page says that number is from that export.

The tabs are:

| Tab | What it is |
|---|---|
| Findings | Findings by severity and category, plus the evidence index |
| Access map | What each agent can do (shell, files, network, secrets, git, remote, approval), read only from the evidence |
| Changes | What is different from the previous scan |
| Agents / collectors | Per-tool detail, including which account each tool is signed in as, plus Grok Bot and cloud agents when those envelopes are present |
| Approvals | Tool-decision counts from a telemetry export |
| Usage | Token totals, and cost only when the export carried cents |
| Coverage gaps | Questions the evidence cannot answer |

If a tab has no evidence, it is dimmed with a "not collected" tag and the panel says `Not collected in this scan.` The page still opens. A missing file is not an error in the report. On the access map, a Yes or Unknown cell is a button that opens that cell's evidence. On Findings, a row opens its evidence underneath.

The page does not copy full transcripts or prompts. It does show finding samples. Those samples are unredacted unless the scan used `-Redact`, so they can include paths and secret-shaped text. Cowork still contributes counts, not file contents. The agents tab includes an account table when `evidence/accounts.json` is present: email, username, organization, and plan from local config. Those identifiers are shown on a normal scan. They are masked when the briefing is built with `-Redact`. Token and API key values are not in the table.

## What changed since the last scan

Each scan is a folder. The folder name can be a date (`C:\scans\2026-10-07`) or any other name. Inside it, `evidence\` holds one JSON file per collector.

```
C:\scans\
  2026-10-01\
    evidence\
      claude.json
      cursor.json
  2026-10-07\
    evidence\
      claude.json
      cursor.json
      changes.json
```

When you run a briefing, aiscan compares the folder you just scanned with the previous one and writes `changes.json` into the new folder before it builds the HTML. If you pass `-Previous`, that folder is the baseline, even if it is smaller. If you do not, the tool looks at the other folders next to this one and prefers the newest earlier scan with the same collectors. An older scan with that same collector set is preferred over a newer one missing a collector. A scan with fewer than half as many collectors is skipped. A one-collector run does not write a diff unless `-Previous` is set.

`changes.json` is the list of what was added, what went away, and which collector went quiet. The Changes tab reads that file. The other tabs do not treat it as another agent.

The first time there is no earlier folder, `changes.json` is still written and marked as a first scan. That is a baseline. It is not a clean bill of health.

A collector that used to report data and now reports nothing is called out. An empty result is not shown as "all clear." That is the case where a product moves tokens or transcripts off the machine and a local scan would otherwise look quiet.

## Where trends go

`changes.json` is one comparison: this scan versus the last one. It is not a chart of the last year. Counts you want to follow over time (tokens, messages, new high findings) should be indexed in Splunk. The summary fields in `changes.json` are already counts, and the per-collector before/after numbers are the rows to index. Do not ship the `raw\` folder. Without `-Redact`, the evidence can also contain paths, so do not forward the scan folder either.

More on the folder layout and the diff command is in [scan-history.md](scan-history.md).

## Build the same draft from a real scan

From the repo root, in Windows PowerShell 5.1:

```powershell
.\scripts\build-draft-report.ps1 -EvidenceRoot C:\scans\2026-10-07
```

The scan folder must contain `evidence\` with one JSON file per collector (`version` major 1). `changes.json`, `raw\`, `manifest.json`, and `run-origin.txt` are optional. The command writes `<EvidenceRoot>\briefing\report-v2.html`. If that folder does not exist, the script prints `Scan folder not found: C:\scans\2026-10-07` and exits 1. If the path exists but has no `evidence\` directory, it prints `Not a scan folder: C:\scans\2026-10-07 (expected an evidence directory)` and exits 1.

`-Previous`, `-Out`, `-OtelFile`, and `-SplunkExport` are optional. Leave the telemetry switches off when you do not have an export. Cloud agents show up only when that scan already contains `evidence\cloud-agents.json` (from `.\aiscan.ps1 cloud-agents`, which is not part of `all`).

```powershell
.\scripts\build-draft-report.ps1 -EvidenceRoot C:\scans\2026-10-07 -Previous C:\scans\2026-10-01 -Out C:\scans\2026-10-07\briefing\report-v2.html -OtelFile C:\exports\otel.json -SplunkExport C:\exports\cursor-usage.csv
```

A normal scan does this for you when you add `-Briefing`:

```powershell
.\aiscan.ps1 all -OutDir C:\scans\2026-10-07 -Previous C:\scans\2026-10-01 -Briefing
```
