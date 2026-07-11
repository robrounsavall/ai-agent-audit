# PII-scan collector (optional)

Presidio-based PII scan of a chat corpus. Skipped by `aiscan all` (needs venv).
Run it directly with `.\aiscan.ps1 pii-scan` inside the venv.

With no `--target`, it scans the chat-history export under the raw root (if a
chat-history run produced one) plus every native chat location that exists
(Claude projects, Codex sessions, Cursor projects, Grok sessions). Pass
`--target DIR` (repeatable) to scan something else.

| | |
|---|---|
| Evidence | `evidence/pii-scan.json` |
| In `aiscan all` | no |
| Deps | `requirements.txt` (Presidio + spaCy model) |

## Test

```powershell
.\scripts\test-component.ps1 -Name pii-scan
# full scan requires venv:
# python -m venv .venv; .\.venv\Scripts\Activate.ps1; pip install -r requirements.txt
```