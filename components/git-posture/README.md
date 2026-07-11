# Git-posture collector

Checks repos under configured roots for `.env` history, hooks, ignore posture, and large blobs.

| | |
|---|---|
| Evidence | `evidence/git-posture.json` |
| In `aiscan all` | yes |
| Deps | stdlib, `git` on PATH; optional `gh` |

## Test

```powershell
.\scripts\test-component.ps1 -Name git-posture
.\aiscan.ps1 git-posture
```