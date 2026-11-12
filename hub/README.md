# aiscan hub

The hub is a database and a dashboard for aiscan scans. A scan folder shows
one machine at one moment. The hub keeps every scan, so it can show what is
open right now, when each finding first appeared, what changed between
scans, and how several machines compare.

It is one SQLite file and one Python process. Standard library only,
Python 3.11+, no install step, the same as the collectors.

Why it is built this way, and what comes next, is in
[docs/hub-architecture.md](../docs/hub-architecture.md).

## Try it with invented data

```powershell
python hub\aiscan_hub.py demo
```

That builds a separate demo database (three made-up machines, twelve weeks
of scans), starts the dashboard, and opens it in your browser. It does not
read anything from your machine and does not touch your real hub database.

## Use it on your own scans

```powershell
# Scan and store the result in the hub in one step
.\aiscan.ps1 all -Hub

# Add scan folders you already have (one folder, or a folder of them)
.\aiscan.ps1 hub-import -OutDir C:\scans

# Open the dashboard
.\aiscan.ps1 hub
```

`-Hub` works with a default throwaway scan. The temp folder is still
deleted at the end, and the hub keeps the evidence layer.

`aiscan hub` prints a sign-in link and opens it. The dashboard listens on
`127.0.0.1:8765` and stops when you press Ctrl+C.

## What the dashboard shows

| Page | What it answers |
|---|---|
| Overview | How many critical and high findings still need a decision, open findings over time, what changed in recent scans, and one row per machine. |
| Findings | One row per finding per machine, tracked across scans: first seen, last seen, open or resolved. Filter by severity, source, machine, and review state. |
| Finding detail | Every run where it was or was not reported, the latest sample, and your review decision and note. |
| Permissions | Allow, ask, and deny rules in force now, across agents and machines, sorted by risk. |
| MCP servers | Every MCP server named in current evidence, which agent has it, and when the hub first saw it. |
| Accounts | Which identity each tool is signed in as. |
| Scans | Every stored scan. A scan page shows who launched it, its collectors, its findings, and what changed since the scan before it. |

A finding is **open** while the newest run of its collector still reports
it. "Current" always means the newest run of each collector, not the newest
scan. So re-running one collector updates that collector only, and a
collector that failed to write evidence does not make its old findings look
resolved.

Changes between scans are computed by `core/scan_diff.py`, the same code
that writes `evidence/changes.json`, so the hub and the briefing agree.

Your review decision (needs review, acknowledged, accepted risk, false
positive) stays with the finding across later scans. It does not change
what the scanner reports.

## What is stored, and what is not

Only the `evidence/` layer is read: the collector envelopes and
`run-origin.txt`.

- `raw/` is never opened. Transcripts and per-hit CSV rows do not enter the
  database.
- `raw_pointers` and `raw_evidence_ref` are dropped from every envelope.
- Fields the hub does not know are dropped. The list of kept fields is in
  [`hub_bundle.py`](hub_bundle.py).
- An envelope whose schema major version is not 1 is skipped with a note.

A scan added on the machine it ran on is stored **as scanned**. If the scan
did not use `-Redact`, the database holds the same paths, names, and
samples the scan folder holds. Treat the database file like a scan folder.

The database is `%LOCALAPPDATA%\aiscan\hub\hub.db`. Set `AISCAN_HUB_DB` or
pass `--db` to put it somewhere else. Delete the `hub` folder to remove it.

## Access

- The dashboard binds to `127.0.0.1`. Nothing is readable without the
  access token. The token is created on first run and kept in the
  `ui-token` file next to the database. `serve --rotate-token` replaces it.
- With `-AgentMode` (`AISCAN_AGENT_MODE=1`) the sign-in link is not printed.
- The server refuses requests whose `Host` header is not a name it was
  started with, sends no CORS headers, and requires a CSRF token on every
  form post. Pages carry no inline script.

## More than one machine

One hub can collect scans from several machines. This is the only part of
the hub that sends data over the network, and it runs only when you run it.

On the machine that hosts the hub:

```powershell
python hub\aiscan_hub.py token create --name laptop
python hub\aiscan_hub.py serve --bind 0.0.0.0 --allowed-host hub.example --tls-cert cert.pem --tls-key key.pem
```

On each machine that scans:

```powershell
.\aiscan.ps1 all -OutDir C:\scans\today
$env:AISCAN_HUB_TOKEN = "aish_..."
python hub\aiscan_hub.py push C:\scans\today --server https://hub.example:8765
```

What `push` sends is a **share-safe** bundle. It is built field by field
from the SCHEMA.md contract, whether or not the scan used `-Redact`:

- secrets and absolute paths in every text field are masked
- workspace and project names are hashed
- account emails become `<email>` (`--keep-emails` keeps them)
- `raw/` is not read

The short hostname is sent. The hub needs it to tell machines apart.

See exactly what would leave before anything does:

```powershell
python hub\aiscan_hub.py push C:\scans\today --dry-run
```

`push` refuses plain HTTP to another machine, never follows a redirect, and
reads the token from an environment variable so it does not land in shell
history. An ingest token can add scans. It cannot read anything. The hub
masks secrets a second time on arrival.

`serve` refuses to listen on a non-loopback address without TLS. If a
reverse proxy terminates TLS in front of it, pass `--insecure-http`.

## Commands

```
python hub\aiscan_hub.py [--db FILE] <command>

  ingest PATH...     add scan folders (or folders of scan folders)
  serve              run the dashboard
  demo               build a demo database from invented data and serve it
  status [--json]    counts from the database
  push SCAN          send one share-safe scan to another hub
  token create|list|revoke [--name NAME]
  prune --keep-days N [--keep-last N] [--dry-run]
```

`prune` always keeps each machine's newest scan. After pruning, "first
seen" for a finding is the oldest scan still stored.

## JSON API

Every page has the same data as JSON. Reads need the access token as a
cookie or `Authorization: Bearer`.

| Route | Returns |
|---|---|
| `GET /api/v1/health` | `{"status": "ok"}`. No token needed. |
| `GET /api/v1/overview` | Fleet counts. |
| `GET /api/v1/hosts` | Machines with open counts and detected agents. |
| `GET /api/v1/trend[?host=ID]` | Open findings by severity, one point per scan. |
| `GET /api/v1/scans[?host=ID]`, `GET /api/v1/scans/ID` | Scans, and one scan with findings and changes. |
| `GET /api/v1/findings?status=&severity=&collector=&host=&triage=&q=` | Finding lifecycle rows. |
| `GET /api/v1/rules?decision=&risk=&host=&q=` | Current permission rules. |
| `GET /api/v1/mcp-servers` | Current MCP servers. |
| `POST /api/v1/scans` | Ingest one bundle. Needs an ingest token. |

## Tests

```powershell
.\scripts\test-component.ps1 -Name hub
```
