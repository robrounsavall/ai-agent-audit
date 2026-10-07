# Telemetry import

Opt-in collector. It reads OpenTelemetry and Splunk **export files** you already
saved and writes `evidence/telemetry.json`. It does not contact Splunk or any
other network service.

Not part of `aiscan all` until a later change wires it in. `in_all` is false.

| | |
|---|---|
| Evidence | `evidence/telemetry.json` |
| In `aiscan all` | no |
| Deps | stdlib only |

Full export steps, example SPL, and the report functions to call are in
[docs/telemetry-import.md](../../docs/telemetry-import.md).

```powershell
$env:PYTHONPATH = "core"
python components/telemetry-import/telemetry-import.py --evidence-root .\audit-run
python components/telemetry-import/telemetry-import.py `
  --evidence-root .\audit-run `
  --otel-file .\samples\telemetry-import\otel-tool-decisions.json `
  --splunk-export .\samples\telemetry-import\splunk-cursor-usage.csv
python -m unittest discover -s components/telemetry-import/tests -p "test_*.py" -v
```

Exit `0` when an export was read. Exit `2` when no export was provided or none
of the paths could be read (same "not detected" code as the other collectors).
