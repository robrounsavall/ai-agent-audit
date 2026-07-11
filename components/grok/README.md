# Grok Build collector

Inventories Grok Build permission mode, MCP servers, and session metadata from `~/.grok`.

| | |
|---|---|
| Evidence | `evidence/grok.json` |
| In `aiscan all` | yes |
| Deps | stdlib only (`tomllib`) |

## Test

```powershell
.\scripts\test-component.ps1 -Name grok
.\aiscan.ps1 grok
```