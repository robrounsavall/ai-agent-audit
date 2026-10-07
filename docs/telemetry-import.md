# Telemetry import

This collector turns two kinds of saved export into the audit report:

- Approval decisions from Claude Code OpenTelemetry `tool_decision` events.
- Usage and cost from Cursor usage rows, plus generic token rows for other tools.

Claude Code does not write each Approve click to disk. A transcript shows
denials, not the click that allowed a tool. The approval audit trail is the
OpenTelemetry log event `claude_code.tool_decision`. Codex, Cursor, and Grok do
not emit that same event. If a Splunk search (or another export) has the same
fields — tool name, decision, source, time — this collector counts those rows too.

The collector reads files. Your Splunk search, and the Export button, happen
before you run it. The scan stays offline.

Synthetic examples live in `samples/telemetry-import/`. They are fake data for
the tests and for a dry run.

## Export approval decisions from Splunk

Use the index your pipeline writes for Claude Code. The examples below say
`index=claude`. Replace that with the index your OpenTelemetry Collector and
Cribl actually use. Cursor usage is already known to land in `index=cursor`.

In Splunk Web, set the time range you want to audit, run:

```spl
index=claude event.name=tool_decision
| table _time, tool_name, decision, source, tool_source
| sort _time
```

Then use **Export** and choose JSON or CSV. Save the file on disk.

The same search from a machine that already has the Splunk CLI pointed at your
local Splunk:

```text
splunk search "index=claude event.name=tool_decision | table _time, tool_name, decision, source, tool_source | sort _time" -maxout 0 -output csv > claude-tool-decisions.csv
```

If the events are still in an OTLP JSON file from a collector `file` exporter
(`resourceLogs` / `logRecords`), pass that file with `--otel-file` instead of
`--splunk-export`. JSON-lines works too: one OTLP log record or one flat object
per line.

Fields this collector reads, from the Claude Code monitoring reference
(https://code.claude.com/docs/en/monitoring-usage, Tool decision event):

| Field | Values |
|---|---|
| Event name | `claude_code.tool_decision` |
| `event.name` | `tool_decision` |
| `decision` | `accept` or `reject` |
| `source` | `config`, `hook`, `user_permanent`, `user_temporary`, `user_abort`, `user_reject` |
| `tool_name` | Tool name, such as `Bash`, `Write`, `WebFetch`, `mcp_tool` |
| `tool_source` | `builtin`, `mcp`, or `sdk_host_builtin_mcp` |
| `event.timestamp` | ISO 8601 time. Splunk `_time` is used when that attribute is absent |

`source=config` means Claude Code decided without showing a prompt (an allow or
deny rule, managed policy, a CLI flag, the permission mode, a session grant, or
a tool that is always safe). The event does not say which of those matched.
`hook` means a PreToolUse or PermissionRequest hook decided. The `user_*`
values are prompt answers: permanent and temporary are accepts, abort and
reject are denials.

Splunk rows may say `approve` / `allow` or `deny` instead of `accept` /
`reject`. Those are counted the same way.

`tool_parameters` (present only when Claude Code was started with
`OTEL_LOG_TOOL_DETAILS=1`) can contain the shell command, a URL, or an MCP
argument list. This collector does not store that payload. It keeps
`mcp_tool_name` when that name is present, and drops the rest. Prompt text
(`prompt`, `prompt_text`) is dropped the same way. Leave
`OTEL_LOG_TOOL_DETAILS` and `OTEL_LOG_USER_PROMPTS` off unless you have a
separate reason to keep commands in Splunk.

## Export Cursor usage from Splunk

The Cursor usage collector writes `index=cursor`,
`sourcetype=cursor:usage_events`, `event=cursor_usage_event`.

```spl
index=cursor sourcetype=cursor:usage_events event=cursor_usage_event
| table _time, model, kind, input_tokens, output_tokens, cache_read_tokens, cache_write_tokens, total_tokens, cost_cents
```

Export JSON or CSV the same way as the approval search.

`cost_cents` on these rows is shown in the report as **from the Cursor
dashboard usage export**. The dollar amount is that cent total, not a price
computed from tokens.

## Generic token rows

A CSV or JSON export with `harness`, `model`, and a token column
(`tokens`, `total_tokens`, or `input_tokens` / `output_tokens`) is counted as
usage for that harness. Example header:

```text
harness,model,tokens,input_tokens,output_tokens
codex,gpt-example,80,50,30
```

Those rows are **tokens only**. A `cost` or `cost_usd` column on them is
ignored. This collector never turns a token count into dollars.

## Run the collector

From the repository root. The script finds `core/` itself, so you do not need
`PYTHONPATH` unless you import it from another program.

```text
python components/telemetry-import/telemetry-import.py --evidence-root ./audit-run --otel-file ./exports/claude-tool-decisions.json --splunk-export ./exports/cursor-usage.csv
```

Both file flags are optional and repeatable. Pass every export you want in the
same envelope. With neither flag, the collector still writes
`evidence/telemetry.json` and exits `2`. The envelope says the platform was
not detected, and the note is: approvals are not on disk without an
OpenTelemetry `tool_decision` export.

| Exit | Meaning |
|---|---|
| 0 | At least one export file was read |
| 2 | No export was provided, or none of the paths could be read |
| 1 | `--evidence-root` does not exist |

`--dry-run` prints the envelope and writes nothing. `--raw-root` defaults to
`<evidence-root>/raw`. The raw files are a redacted JSONL copy: tool name,
decision, source, tokens, and cost. Command arguments and prompt text are not
copied there either.

`AISCAN_REDACT=1` (or `-Redact` on `aiscan.ps1`, once this collector is wired)
runs the shared path and secret masking. The default, matching the other
collectors, leaves ordinary tool and model names readable.

## What the evidence contains

`summary` holds the rollups the report section renders:

- Approvals and denials by tool, by source (`config`, `hook`, `user_permanent`, `user_temporary`, `user_abort`, `user_reject`), by group (`config rule`, `user`, `hook`), and by day.
- `top_auto_approved`: tools whose accepts have `source=config`.
- Usage totals by tool (`kind` on Cursor rows, harness or tool on generic rows) and by model.
- `cost_cents` and `cost_label` only when Cursor rows included `cost_cents`. Otherwise `cost_basis` is `tokens_only`.

Findings call out a high share of accepts from config rules, Bash / PowerShell,
Write, WebFetch, and MCP tools approved with no prompt (`config` or `hook`),
and the coverage limit: approve clicks are not in the Claude Code transcript.

`rules` stays empty. These are observed events, not a configured allow list.

## Wiring the report later

Do not edit `report/build-briefing.py` in the same change that adds this
collector. When that file is ready to grow a section, load
`evidence/telemetry.json` and call:

```python
from sections.telemetry import (
    approvals_nav_link,
    render_approvals_section,
    render_usage_section,
    telemetry_nav_links,
    usage_nav_link,
)
```

`report/` is not a Python package. Put `report/` on `sys.path` first, or load
`report/sections/telemetry.py` by path. Each function takes the telemetry
envelope. Each returns `""` when that half of the evidence is absent, so the
nav and the body can be concatenated as they are.

| Function | Role |
|---|---|
| `render_approvals_section(env)` | Section `#telemetry-approvals` |
| `render_usage_section(env)` | Section `#telemetry-usage` |
| `approvals_nav_link(env)` | `<a href="#telemetry-approvals">Approvals</a>` |
| `usage_nav_link(env)` | `<a href="#telemetry-usage">Usage</a>` |
| `telemetry_nav_links(env)` | Both links, or `""` |

Kicker numbers in the section HTML are `/09` and `/10`. Renumber them to match
the rest of the briefing. The markup uses the classes already defined in
`report/templates/briefing.css` (`section`, `perm-summary`, `table-wrap`,
`mode-chip`, `surface-note`).

Collector entry points, if the shell wrapper grows a component:

| Symbol | Role |
|---|---|
| `components/telemetry-import/telemetry-import.py` | Script |
| `COLLECTOR` | `"telemetry"` (the evidence filename) |
| `collect(otel_files, splunk_files, raw_root=None)` | Envelope, no process exit |
| `build_parser()` | The CLI, including the shared `--evidence-root` / `--raw-root` / `--dry-run` flags |
| `run(argv=None)` | `0` or `2` |
| `main()` | `sys.exit(run())` |

`component.json` sets `"in_all": false` until that wrapper exists.
