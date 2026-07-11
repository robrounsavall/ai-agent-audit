# Secrets-scan collector

Runs gitleaks (preferred) or trufflehog over chat corpus and repo roots; redacted findings only in evidence.

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