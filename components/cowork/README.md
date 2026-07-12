# Cowork collector

Inventories Claude desktop app (Cowork) session workspaces under `%APPDATA%\Claude`:
transcripts, audit logs, outputs/uploads, cached Office-document PDF previews,
and local-to-cloud session bridging. Structure and counts only; session content
is never read.

| | |
|---|---|
| Evidence | `evidence/cowork.json` |
| In `aiscan all` | yes |
| Deps | stdlib only |

## Test

```powershell
.\scripts\test-component.ps1 -Name cowork
.\aiscan.ps1 cowork
```
