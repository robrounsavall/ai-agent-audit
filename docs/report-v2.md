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

If a tab has no evidence, it is dimmed with a "not collected" tag and the panel says `Not collected in this scan.` The page still opens. A missing file is not an error in the report. On the access map, a Yes or Unknown cell is a button that opens that cell's evidence. On Findings, a row opens its detail underneath: what to do, then where it is.

## Opening a finding

Select a finding row and the panel under it answers three questions in order.

1. Why it matters and what to do. A short statement of the risk and numbered steps: which credential to rotate and where, which config key to change, which file to delete. The text is fixed per finding type and is in `report/remediation.py`.
2. What triggered it. The collector's sample and any extra fields it recorded.
3. Where it is. For secrets and PII this is one entry per distinct value, with every place that value appears. Named credential types (AWS, GitHub, vendor keys) are listed first. The two length-only matchers come last, and a value that is the length of a git commit id or a SHA-256 digest is marked as unlikely to be a credential. Each location names the tool, the file, and the line and column. A chat-transcript hit also names the tool's own session file, the workspace, the message role, and the time, because that session file is the one to delete. A `.env` finding lists the repository, the path, and the commit that added it. A permission finding lists the rules it is about.

The filter box above the list narrows the locations by tool, path, or type.

How much of that is shown depends on how the page was built.

| Build | File | Paths | Matched values and surrounding text |
|---|---|---|---|
| `-Briefing` | `briefing.html` | Shortened or hashed | Masked. Not on the page. |
| `-Briefing -LocalLinks` | `briefing-local.html` | Full, with Copy path, folder, and open-in-editor links | Masked. Not on the page. |
| `-Briefing -ShowSecrets` | `briefing-unmasked.html` | Full, same links | Shown in full, with up to 80 characters on each side |

`-ShowSecrets` is for the person doing the cleanup on the machine that was scanned. The file holds live credentials and transcript excerpts. Keep it on that machine and delete it when you are done. The banner at the top has a Hide values button that blurs the values for a screen share. `-Redact` and `-AgentMode` both turn `-ShowSecrets` off.

The open-in-editor links use the `vscode://file/<path>:<line>:<column>` and `cursor://file/...` schemes. They work when that editor is installed. A session log is often one very long line per message, so the column matters more than the line.

Positions come from the scan that wrote the folder. A folder scanned before this feature has no line numbers for secrets, and the panel says so. Scan again to get them.

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
