# Local MCP Visibility

Standalone tool for inventorying MCP server registrations across Claude,
Cursor, Codex, Grok Build, shared `.mcp.json`, and repo-scoped config files.

It is intentionally not wired into `aiscan.ps1` or the SCHEMA.md evidence
contract yet. It prints real local paths by default for operator use, while
still masking obvious bearer/header/token values.

## Run

```powershell
python tools\mcp-visibility\mcp_visibility.py
python tools\mcp-visibility\mcp_visibility.py --format summary
python tools\mcp-visibility\mcp_visibility.py --format table
python tools\mcp-visibility\mcp_visibility.py --repo-roots C:\Users\you\projects
python tools\mcp-visibility\mcp_visibility.py --redact
```

Use `--format summary` for the human report. It groups repeated server names and
calls out definition drift, auth/secret posture, non-local endpoints, and
reference-only Claude overlays.

## Duplicate Fields

The raw JSON includes `duplicate_group` and `duplicate_of` so future tooling can
correlate the same MCP server name across multiple sources. A duplicate is not
automatically a problem: the same server may legitimately appear in shared
`.mcp.json`, Codex config, Claude state, and Cursor project config.

The more useful warning is `definition_conflict` / `definition-drift` in the
summary report. That means same-name entries have different command, args, URL,
env-key, or header-key fingerprints.

## Promotion Path

Once the model is stable, promote it into a formal collector: write a SCHEMA.md
evidence envelope and render the inventory in the HTML briefing.
