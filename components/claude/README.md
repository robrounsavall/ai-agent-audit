# Claude Code collector

Inventories Claude Code permission settings, MCP servers, and bypass modes from `~/.claude`.

| | |
|---|---|
| Evidence | `evidence/claude.json` |
| In `aiscan all` | yes |
| Deps | stdlib only |

## Test

```powershell
.\scripts\test-component.ps1 -Name claude
.\aiscan.ps1 claude
```