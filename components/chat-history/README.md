# Chat-history collector

Aggregates transcript volume, retention, and secret-hit indicators across tools. Raw text stays under local `raw/`.

| | |
|---|---|
| Evidence | `evidence/chat-history.json` |
| In `aiscan all` | yes |
| Deps | stdlib only |

## Test

```powershell
.\scripts\test-component.ps1 -Name chat-history
.\aiscan.ps1 chat-history
```