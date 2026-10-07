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

With `--previous` omitted, the tool looks at sibling folders under the parent of `--current` (override that with `--history-root`) and picks the one whose evidence `ran_at` is the latest time still earlier than this scan. It ignores folders that are not scans, and it ignores `changes.json` so a later diff cannot make an old folder look newer.

To point at a specific baseline:

```
python core/scan_diff.py --current C:\scans\2026-10-07 --previous C:\scans\2026-10-01
```

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

The HTML piece is not wired into the briefing yet. When it is, the report should load `evidence/changes.json` on its own and skip collector `changes` in the generic collector loop. The briefing loader currently accepts every `evidence/*.json` file whose major version is 1, so leaving `changes` in that loop would show it as just another tool. Call:

- `render_changes_section(env)` in `report/sections/changes.py`
- `render_changes_nav(env)` in the same file

Both return an empty string if there is no changes evidence. A first scan gets a short note instead of a diff.

## Splunk, later

`changes.json` is one JSON event per scan. `ran_at` is the time. The `summary` object is already counts: `new_high_or_critical`, `drift_warnings`, `mcp_servers_added`, `findings_added`, and the rest. Findings carry tags you can alert on, especially `data_location_drift`, `new_mcp_server`, and `new_allow_rule`.

The per-collector `changes.collectors.<name>.counters` list is the trend source: each row is a counter name plus `before` and `after`. Index those if you want message or token lines over time.

Do not forward `raw/` or any path fields. This envelope does not put filesystem paths in the JSON; it keeps the scan folder's name only. That is the same boundary as the other evidence files: counts and redacted findings can leave the machine, raw transcripts cannot.
