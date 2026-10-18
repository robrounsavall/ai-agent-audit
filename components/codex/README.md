# Codex collector

Inventories Codex Desktop approval events, trusted projects, sandbox/telemetry posture from `~/.codex`.

Compressed session logs (`*.jsonl.zst`) are counted in a low finding and not opened. Reading them would need a compression library, and aiscan stays on the Python standard library.

| | |
|---|---|
| Evidence | `evidence/codex.json` |
| In `aiscan all` | yes |
| Deps | stdlib only (`tomllib`) |

## Test

```powershell
.\scripts\test-component.ps1 -Name codex
.\aiscan.ps1 codex
```
## Permission files

Also inventories permission profiles in `config.toml` and `*.config.toml`, saved
`rules/*.rules`, and lifecycle commands in `hooks.json`. Project `.codex` layers
are evaluated only for projects trusted by the user config. `--repo-roots` accepts
repository roots or parent folders to inspect. Managed `requirements.toml` and
legacy `managed_config.toml` are checked in the platform's Codex admin directory.
Desktop `.codex-global-state.json` contributes only permission modes and counts;
thread identifiers, account data, and workspace paths are excluded.
