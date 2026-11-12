# Hub architecture

This page records what the hub is, why it is shaped this way, and what
should come next. It answers the proposal in the 2026-11-06 architecture
hand-off (diagram 04, items P1 to P9).

User guide: [hub/README.md](../hub/README.md).

## The decision

aiscan gets a data backend and a dashboard by adding one component, the
**hub**: a SQLite file, an ingest path, and a small HTTP server that
renders the dashboard. It runs on the machine that scans, with no install
step. The same server can also run on one machine you control and accept
scans from others.

The hand-off sketched a central service with enrollment, mTLS, a queue,
multi-tenancy, and RBAC. That is the right shape for a hosted product with
customers. It is the wrong first step here, for three reasons.

1. **The project's promise is that you can audit it and run it with
   nothing installed.** A Postgres server, a job queue, and a JavaScript
   build would end that. The hub keeps it: stdlib Python, one file of data.
2. **The value was missing at one machine, not at a thousand.** Scan
   folders could not answer "when did this first appear", "is it fixed",
   or "what did I already decide about it". A database answers those for a
   single user on day one. A fleet service with no lifecycle model would
   not.
3. **Every piece of the larger design can be added later without redoing
   this one.** The ingest endpoint, the bundle format, and the schema are
   the same ones a hosted service would use. What is deferred is
   deployment machinery, not design.

## How data moves

```
aiscan.ps1 all -Hub                     another machine
      |                                       |
   scan folder                             scan folder
   evidence/  raw/                         evidence/  raw/
      |         (never read)                  |         (never read)
   build_bundle                           build_bundle(share_safe)
      |                                       |  secrets, paths, emails masked
      |                                  push: HTTPS POST /api/v1/scans
      |                                       |  ingest token
      +---------> normalize_bundle <----------+  (allowlist, caps, masks again)
                        |
                   ingest_bundle  ->  SQLite (hub.db)
                        |
                   rebuild_host   ->  current posture, finding lifecycle
                        |
              HTTP server: dashboard pages + JSON API  (127.0.0.1, token)
```

| File | Job |
|---|---|
| `hub/hub_bundle.py` | The bundle format and `normalize_bundle`, the one gate every scan passes before storage. An allowlist: unknown fields are dropped. |
| `hub/hub_db.py` | Schema, migrations, ingest, and the derived state rebuilt per machine. |
| `hub/hub_queries.py` | Read models. Pages and API call the same functions. |
| `hub/hub_web.py` | HTTP server, access control, ingest endpoint. |
| `hub/hub_pages.py`, `hub/static/` | Server-rendered HTML, one stylesheet, one small script. |
| `hub/aiscan_hub.py` | Command line: ingest, serve, push, token, prune, demo. |

The hub reuses core code instead of copying it: `scan_diff.load_scan` to
read a folder, `scan_diff.diff_envelopes` for changes,
`scan_diff.mcp_server_names` and `numeric_counters` for inventory and
metrics, `agent_summary` for collector status, and `common.mask_secrets`
and `redact_paths` for masking.

## Data model

Three kinds of tables.

**What a scan said.** Written once, never edited: `hosts`, `scans`,
`collector_runs` (with the cleaned envelope as JSON), `findings`, `rules`,
`accounts`, `mcp_servers`, `metrics`.

**What follows from that.** Rebuilt for a machine each time it gets a
scan: `current_runs` (the newest run of each collector), `finding_state`
(one row per finding per machine: open or resolved, first seen, last seen),
the `posture_*` columns on `scans` (what was open as of that scan), and
`scan_diffs` (cached changes).

**What a person decided.** Never rebuilt: `triage`, `tokens`.

Two rules in that model matter more than the rest.

- **Current posture is per collector, not per scan.** A one-collector
  re-run replaces that collector's state and leaves the others. A collector
  that crashed wrote no run, so its earlier findings stay open. This is the
  same concern `scan_diff` handles with its "baseline too small" rule.
- **Derived state is rebuilt, not patched.** A scan imported out of order
  lands in the right place, and pruning cannot leave stale rows. At this
  scale a rebuild is a few milliseconds.

A finding's identity is `(machine, collector, finding id)`. A finding with
no id is keyed by a hash of its title.

Schema changes go through `PRAGMA user_version` in `hub_db._migrate`. A
database from a newer aiscan is refused, not guessed at.

## Trust boundaries

The repo's existing contract decides most of this.

| Rule | Where it is enforced |
|---|---|
| `raw/` never leaves the machine, and never enters the database | `build_bundle` reads `evidence/` only. `normalize_bundle` drops `raw_pointers` and `raw_evidence_ref` at any depth. |
| A default scan is offline | `aiscan.ps1` gained `hub`, `hub-import`, and `-Hub`. All three are local. `push` exists only in `hub/aiscan_hub.py` and only runs when called. |
| Anything shared is built field by field and masked | `push` always builds a share-safe bundle, with or without `-Redact`. The server masks secrets again on arrival. |
| A scan is unredacted unless you ask | A local ingest stores what the scan wrote. The database is as sensitive as the scan folder beside it. |

The server's own defenses are listed at the top of `hub/hub_web.py`: token
on every read, `Host` allowlist against DNS rebinding, CSRF token plus
`Origin` check on posts, no CORS, strict Content-Security-Policy with no
inline script, size caps, and a brake on repeated bad tokens.

## The hand-off's proposal, item by item

| Item | Status | Notes |
|---|---|---|
| P1 Endpoint uploader | **Partly built** | `push` sends one scan. A failed push leaves the folder as it was, and re-running is safe because the hub stores a scan once. No scheduler and no outbox yet. |
| P2 Enrollment and device identity | **Built, simple form** | One named ingest token per machine, stored hashed, revocable. The machine is identified by its short hostname. |
| P3 Transport and auth | **Built** | HTTPS required off loopback, bearer token, no redirects. mTLS is not built. |
| P4 Ingest API | **Built** | Schema-major check, size caps, dedupe by content hash, field allowlist. |
| P5 Queue | **Not built, on purpose** | Ingest is one SQLite transaction that takes milliseconds. A queue would add a moving part with nothing to buffer. |
| P6 Persistence | **Built** | SQLite, with versioned migrations. |
| P7 Multi-tenancy and RBAC | **Not built** | One hub, one owner. There are two roles in effect: the access token reads everything, an ingest token only writes. |
| P8 Retention | **Built, manual** | `prune --keep-days / --keep-last`. Not automatic. |
| P9 Server UI | **Built** | Fleet view, finding lifecycle, drift and changes over time. |

## What to build next

In the order I would do it.

1. **Scheduled scans.** A script that registers a Windows scheduled task
   running `aiscan.ps1 all -Hub` (and optionally `push`). This is what
   turns the trend chart from "when I remembered" into a real series. It
   changes system state, so it should be its own opt-in script with an
   uninstall path.
2. **Alerts on change.** The diff already tags `new_high_finding`,
   `new_mcp_server`, `new_allow_rule`, and `data_location_drift`. A
   `notify` command after ingest could print them, raise a Windows toast,
   or post to a webhook you configure.
3. **Metric trends.** `metrics` already stores every numeric summary
   counter per run (messages, tokens, sessions). The dashboard does not
   chart them yet. Token and transcript-volume lines per agent are the
   obvious first charts.
4. **Stable machine identity.** The short hostname is the key today. Two
   machines with the same name merge, and a renamed machine splits. A
   random machine id written once under `%LOCALAPPDATA%\aiscan` and sent
   in the bundle fixes both.
5. **Evidence cards without raw paths.** The briefing's per-hit cards read
   `raw/*.csv`. The hub deliberately does not. A middle path is for
   `secrets-scan` and `pii-scan` to put a small share-safe per-rule
   breakdown in the envelope.
6. **A container image and Postgres**, only if the hub is ever hosted for
   more than one owner. That is also the point where P5 and P7 start to
   earn their cost. The SQL here is plain enough to port.

## Known limits

- Windows-first, like the scanner. The hub itself runs anywhere Python
  does, and its tests do not depend on Windows.
- `http.server` is fine for one person and a handful of machines. It is
  not a hardened internet-facing server. Put a real reverse proxy in front
  of it before exposing it beyond a network you trust.
- The dashboard has no user accounts. Whoever holds the access token sees
  everything in the hub.
- Scans from before the `copilot` to `vscode` rename are stored under
  `vscode`. Their finding ids were not rewritten, so the first scan after
  the rename shows the old ids resolving and the new ones opening, the
  same as `scan_diff` reports.
