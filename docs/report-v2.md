# Report v2

This page is the HTML briefing. It is one file. Open it in a browser. It does not need the network, a font download, or a web server.

The top of the page is the summary. It tells you which agents were detected, how many findings there are at each severity, and one sentence about what changed since the last scan. If a cloud-agents inventory was collected, the summary also shows how many agents and how many tokens. If a telemetry export included approval decisions, the summary says how many were approved, how many were denied, and how many of the approvals came from a config rule. Token totals are not dollars. A dollar figure appears only when the Cursor dashboard usage export included `cost_cents`, and the page says that number is from that export.

Under the summary are tabs:

| Tab | What it is |
|---|---|
| Findings | Findings by severity and category, plus the evidence index |
| Access map | What each agent can do (shell, files, network, secrets, git, remote, approval), read only from the evidence |
| Changes | What is different from the previous scan |
| Agents / collectors | Per-tool detail, including Grok Bot and cloud agents when those envelopes are present |
| Approvals | Tool-decision counts from a telemetry export |
| Usage | Token totals, and cost only when the export carried cents |
| Coverage gaps | Questions the evidence cannot answer |

If a tab has no evidence, it says so in one line, for example `Not collected — run aiscan telemetry -OtelFile <file> -SplunkExport <file> to enable.` The page still opens. A missing file is not an error in the report.

The page shows presence and counts. It does not show prompts, transcript text, or secret values. That is the same rule the Cowork collector already follows: count the files, do not read the contents into the report.

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

When you run a briefing, aiscan compares the folder you just scanned with the previous one and writes `changes.json` into the new folder before it builds the HTML. If you pass `-Previous`, that folder is the baseline. If you do not, the tool looks at the other folders next to this one and picks the one whose evidence time is the latest time still earlier than this scan.

`changes.json` is the list of what was added, what went away, and which collector went quiet. The Changes tab reads that file. The other tabs do not treat it as another agent.

The first time there is no earlier folder, `changes.json` is still written and marked as a first scan. That is a baseline. It is not a clean bill of health.

A collector that used to report data and now reports nothing is called out. An empty result is not shown as "all clear." That is the case where a product moves tokens or transcripts off the machine and a local scan would otherwise look quiet.

## Where trends go

`changes.json` is one comparison: this scan versus the last one. It is not a chart of the last year. Counts you want to follow over time (tokens, messages, new high findings) should be indexed in Splunk. The summary fields in `changes.json` are already counts, and the per-collector before/after numbers are the rows to index. Do not ship the `raw\` folder. Paths and transcripts stay on the machine.

More on the folder layout and the diff command is in [scan-history.md](scan-history.md).

## Build the same draft from a real scan

From the repo, on Windows:

```powershell
.\scripts\build-draft-report.ps1 -EvidenceRoot C:\scans\2026-10-07 -Previous C:\scans\2026-10-01 -Out C:\scans\2026-10-07\briefing\report-v2.html -OtelFile C:\exports\otel.json -SplunkExport C:\exports\cursor-usage.csv
```

`-Previous`, `-OtelFile`, and `-SplunkExport` are optional. Leave the telemetry switches off when you do not have an export. Cloud agents show up only when that scan already contains `evidence\cloud-agents.json` (from `.\aiscan.ps1 cloud-agents`, which is not part of `all`).

A normal scan does this for you when you add `-Briefing`:

```powershell
.\aiscan.ps1 all -OutDir C:\scans\2026-10-07 -Previous C:\scans\2026-10-01 -Briefing
```
