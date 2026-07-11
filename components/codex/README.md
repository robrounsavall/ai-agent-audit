# Codex collector

Inventories Codex Desktop approval events, trusted projects, sandbox/telemetry posture from `~/.codex`.

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