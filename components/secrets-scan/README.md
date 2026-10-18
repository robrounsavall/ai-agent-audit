# Secrets-scan collector

Runs Betterleaks, gitleaks, or trufflehog over chat corpus and repo roots; redacted findings only in evidence. Betterleaks is preferred. trufflehog is passed `--no-verification` and `--no-update`, so it does not check secrets against live services or phone home for updates. A scanner that fails to finish is reported; it is not shown as zero hits.

| | |
|---|---|
| Evidence | `evidence/secrets-scan.json` |
| In `aiscan all` | yes |
| Deps | Betterleaks, gitleaks, or trufflehog on PATH |

## Test

```powershell
.\scripts\test-component.ps1 -Name secrets-scan
.\aiscan.ps1 secrets-scan
```