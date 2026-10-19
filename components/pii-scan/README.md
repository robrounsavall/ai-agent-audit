# PII-scan collector

Stdlib scan of a chat corpus for regulated-data indicators: credit cards
(IIN prefix + Luhn), SSNs (issuance rules), IBANs (mod-97), emails, phone
numbers (separators required), and public IP addresses (private/loopback are
counted in the summary but are not findings). No models, no pip install.

A built-in list of common test card numbers (for example 4111… and 4242…)
is counted separately as a low finding. The briefing calls them "Test card
numbers". Other valid card numbers stay critical. With `-Redact`, target
paths are stored as hashes, not full paths.

v2 dropped Microsoft Presidio: its NER entities tagged code identifiers as
people and places, and everything that survived triage was validatable with
patterns and checksums.

With no `--target`, it scans the chat-history export under the raw root (if a
chat-history run produced one) plus every native chat location that exists
(Claude projects, Codex sessions, Cursor projects, Grok sessions). Pass
`--target DIR` (repeatable) to scan something else.

A file over the shared 64 MiB cap (plain size, or unpacked size for
`.jsonl.zst`) is not scanned. The evidence lists those files once, as a low
finding, "N file(s) not scanned (too large)". Compressed files that are
corrupt or too slow to unpack stay a separate "could not be read" note.
The decompress time limit is the shared 30 seconds.

| | |
|---|---|
| Evidence | `evidence/pii-scan.json` |
| In `aiscan all` | yes |
| Deps | stdlib only (`compression.zstd` on Python 3.14+ reads `.jsonl.zst` transcripts; older Python counts them and does not open them) |

## Test

```powershell
.\scripts\test-component.ps1 -Name pii-scan
.\aiscan.ps1 pii-scan
```
