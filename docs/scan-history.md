# Scan history

Each aiscan run already writes one JSON file per collector under `<scan>\evidence\`. Scan history is nothing more than a folder that holds those runs side by side. A dated folder per run is enough:

```
C:\scans\
  2026-10-01\
    evidence\
      claude.json
      cursor.json
      ...
  2026-10-07\
    evidence\
      claude.json
      cursor.json
      ...
```

The date is only a folder name. The diff uses the `ran_at` time inside the evidence, not the name, so a folder called `before-upgrade` works too.

## See what changed

From the repo (or anywhere `core` is on `PYTHONPATH`):

```
python core/scan_diff.py --current C:\scans\2026-10-07
```

With `--previous` omitted, the tool looks at sibling folders under the parent of `--current` (override that with `--history-root`) and considers the ones whose evidence `ran_at` is strictly earlier than this scan. It ignores folders that are not scans, and it ignores `changes.json` so a later diff cannot make an old folder look newer.

It then picks a baseline in this order:

1. The newest earlier scan that has the same collectors as this scan. An older scan with that same collector set is preferred over a newer one missing a collector.
2. If none match, the newest earlier scan that has at least half as many collectors. Fewer than half is too small: a one-collector retry is not the baseline for a full scan. Exactly half still counts (2 collectors can baseline a 4-collector scan; 6 can baseline an 11-collector scan).
3. If every earlier folder is too small, the result is a first scan.

A scan that itself has only one collector does not write `changes.json` unless you pass `--previous`. That keeps a retry from replacing a diff already in the folder.

To point at a specific baseline:

```
python core/scan_diff.py --current C:\scans\2026-10-07 --previous C:\scans\2026-10-01
```

`--previous` is used as given, even when that folder has fewer collectors.

`--dry-run` prints the result and does not write a file. Otherwise the tool writes `C:\scans\2026-10-07\evidence\changes.json`.

Try it on the synthetic pair without touching the demo files:

```
python core/scan_diff.py --current samples/synthetic-demo --previous samples/synthetic-previous --dry-run
```

`samples/synthetic-previous` is an earlier fake scan. The current demo is `samples/synthetic-demo`. Cursor goes from local token and composer counts to an empty report, which is the drift case below.

The first time there is no earlier folder, the tool still writes `changes.json`, marked `summary.comparison = "first_scan"`. That is a baseline, not a clean bill of health.

## What the diff flags

For each collector it records:

- platform newly detected, or no longer detected
- findings added, resolved, or with a changed severity (matched by finding id)
- rules added or removed, and allow rules on their own
- MCP servers added or removed, when the evidence names them (rules, a server list, or runtime transports)
- summary counters that moved, with the before and after values (message counts, tokens, agent counts, and the other numeric summary fields)

It also writes its own findings when something needs a person:

- a new high or critical finding, or one that rose into high or critical
- a new MCP server
- a new allow rule
- possible data-location drift

Drift is the important one. If a collector had findings, rules, or a real count (messages, tokens, sessions, and similar) and this scan either does not detect the platform or reports none of that data, the diff says so. A collector that suddenly finds nothing is not shown as clean. That is the failure mode where a provider moves data off the machine — Cursor token state leaving local SQLite for an API, or Claude transcripts moving — and a local scan would otherwise look quiet. A collector version change is called out separately, because a parser bump can also make old data disappear.

Bookkeeping such as "keys scanned" can stay non-zero and the drift flag still applies. Those numbers mean the collector ran, not that the data is still there.

## Briefing

The report v2 briefing loads `evidence/changes.json` on its own. The loader skips collector `changes` while it walks the other `evidence/*.json` files, then passes `load_changes_envelope(...)` to `render_changes_section` and `render_changes_nav`. Both return an empty string if there is no changes evidence; the page then says changes were not collected. A first scan gets a short note instead of a diff. The summary at the top of the page uses one sentence from the same envelope. See [report-v2.md](report-v2.md).

## Splunk, later

`changes.json` is one JSON event per scan. `ran_at` is the time. The `summary` object is already counts: `new_high_or_critical`, `drift_warnings`, `mcp_servers_added`, `findings_added`, and the rest. Findings carry tags you can alert on, especially `data_location_drift`, `new_mcp_server`, and `new_allow_rule`.

The per-collector `changes.collectors.<name>.counters` list is the trend source: each row is a counter name plus `before` and `after`. Index those if you want message or token lines over time.

Do not forward `raw/` or an unredacted scan folder. `changes.json` does not copy transcript bodies. Titles and rule text in it can still contain paths unless the scan used `-Redact`. Counts from a redacted scan are the part that can leave the machine. Raw transcripts cannot.
