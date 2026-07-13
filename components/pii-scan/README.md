# PII-scan collector

Stdlib scan of a chat corpus for regulated-data indicators: credit cards
(IIN prefix + Luhn), SSNs (issuance rules), IBANs (mod-97), emails, phone
numbers (separators required), and public IP addresses (private/loopback are
counted in the summary but are not findings). No models, no pip install.

v2 dropped Microsoft Presidio: its NER entities tagged code identifiers as
people and places, and everything that survived triage was validatable with
patterns and checksums.

With no `--target`, it scans the chat-history export under the raw root (if a
chat-history run produced one) plus every native chat location that exists
(Claude projects, Codex sessions, Cursor projects, Grok sessions). Pass
`--target DIR` (repeatable) to scan something else.

| | |
|---|---|
| Evidence | `evidence/pii-scan.json` |
| In `aiscan all` | yes |
| Deps | stdlib only |

## Test

```powershell
.\scripts\test-component.ps1 -Name pii-scan
.\aiscan.ps1 pii-scan
```
