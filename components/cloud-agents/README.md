# Cursor cloud agents

Opt-in, read-only inventory of the user's Cursor cloud agents. It is not part of `aiscan all`. The rest of aiscan stays offline.

| | |
|---|---|
| Evidence | `evidence/cloud-agents.json` |
| In `aiscan all` | no |
| Deps | stdlib, network, `CURSOR_API_KEY` |

Auth is a user API key from Cursor Dashboard → API Keys (`crsr_...`), sent only as `Authorization: Bearer` to `https://api.cursor.com`. The key is never printed or written. Personal keys cannot be scoped to read-only; the same key can create or delete agents. This command still issues GET requests only and refuses every other method, every other host, and `GET /v1/repositories`.

It does not read the Cursor IDE session token and it does not call `cursor.com/api/dashboard`. Dollar cost is enterprise Admin API data and is not requested. Run `result` text is omitted unless you pass the flag, because it can contain source code or secrets.

Requests are spaced to about 20 per minute. HTTP 429 waits for `Retry-After` (capped at 120 seconds) and retries a few times.

```powershell
$env:CURSOR_API_KEY = "crsr_..."
.\aiscan.ps1 cloud-agents -OutDir C:\scans\today
.\aiscan.ps1 cloud-agents -IncludeRunResult -Redact
```

`-IncludeRunResult` stores the latest run's result text and follows `-Redact` / `AISCAN_REDACT`. The API key is stripped either way. Without `CURSOR_API_KEY` the command exits 0 and explains how to set it.

## Test

```powershell
.\scripts\test-component.ps1 -Name cloud-agents
```
