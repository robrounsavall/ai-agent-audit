# GitHub Copilot collector

Inventories VS Code / JetBrains Copilot enablement, exclusions, and public-code settings.

| | |
|---|---|
| Evidence | `evidence/copilot.json` |
| In `aiscan all` | yes |
| Deps | stdlib only |

## Test

```powershell
.\scripts\test-component.ps1 -Name copilot
.\aiscan.ps1 copilot
```