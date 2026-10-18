# Secrets-scan collector

Runs gitleaks (preferred) or trufflehog over chat corpus and repo roots; redacted findings only in evidence. trufflehog is passed `--no-verification` so it does not check secrets against live services.

| | |
|---|---|
| Evidence | `evidence/secrets-scan.json` |
| In `aiscan all` | yes |
| Deps | `gitleaks` preferred on PATH |

## Test

```powershell
.\scripts\test-component.ps1 -Name secrets-scan
.\aiscan.ps1 secrets-scan
```