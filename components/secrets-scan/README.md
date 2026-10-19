# Secrets-scan collector

Runs Betterleaks, then gitleaks, then trufflehog, over the chat corpus and repo roots. Evidence holds findings with shortened secret samples. Full file paths stay in `raw/`. `-Redact` masks paths and secrets in the evidence JSON and does not clean `raw/`.

| | |
|---|---|
| Evidence | `evidence/secrets-scan.json` |
| In `aiscan all` | yes |
| Deps | Betterleaks, gitleaks, or trufflehog (first one aiscan can use) |

## Test

```powershell
.\scripts\test-component.ps1 -Name secrets-scan
.\aiscan.ps1 secrets-scan
```