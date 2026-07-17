# Cowork collector

Inventories Claude desktop app (Cowork) session workspaces under `%APPDATA%\Claude`:
transcripts, audit logs, outputs/uploads, cached Office-document PDF previews
(if present; newer builds unpack Office files into per-session `outputs/` instead),
and local-to-cloud session bridging. Also reports the claude.ai desktop webview
state (`design` window file, IndexedDB, Local Storage) — existence and newest
mtime date only, since those stores persist draft composer state and attachment
metadata locally. The `design` window file doubles as a Claude Design usage
signal (`cowork.design.in_use`): it exists only once the Design window has been
opened, and its mtime is the last open. Structure and counts only; session and
webview content is never read.

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
