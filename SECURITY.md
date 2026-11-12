# Security Policy

## Reporting a vulnerability

Use GitHub private vulnerability reporting on this repository (Security tab >
"Report a vulnerability"). Do not open a public issue for anything that could
leak user data, including parser bugs that cause under-redaction.

Reports that matter most here: any case where a collector writes raw
transcript content into `evidence/`, or where `-Redact` was on and a path,
username, or secret still appears in the evidence or the briefing. A normal
run without `-Redact` is unredacted on purpose. Paths and secret samples in
that output are not a bug.

For the hub, the reports that matter most: any way to read the dashboard or
the JSON API without the access token, any way a web page in the browser
can make the hub act (cross-site request, DNS rebinding), scan text that
reaches a page as markup, anything from `raw/` reaching the database, and
a secret, path, or email that survives in a `push` bundle.

## What this tool does and does not do

- Read-only against AI tool data. Collectors never modify tool configuration,
  sessions, or credential stores.
- Offline by default. The collectors in `aiscan all` make no network calls
  and nothing is uploaded. `cloud-agents` is opt-in and is not part of
  `all`. It sends HTTPS GET requests only to `https://api.cursor.com`
  using a user-supplied `CURSOR_API_KEY`, which is never printed or written.
  It does not read the Cursor IDE session token or call dashboard APIs.
- The hub (`-Hub`, `hub-import`, `hub`) stores the `evidence/` layer in a
  local SQLite file and serves a dashboard on `127.0.0.1` behind an access
  token. It never reads `raw/`. A scan stored on the machine it ran on
  keeps the text the scan wrote, so the database is as sensitive as an
  unredacted scan folder. `python hub\aiscan_hub.py push` is the only
  command that uploads, and only when you run it: it sends one masked,
  share-safe bundle over HTTPS to the server you name. `http.server` is not
  a hardened internet-facing server. Do not expose the hub beyond a network
  you trust without a reverse proxy in front of it.
- The `accounts` collector reads plain identifiers (email, username,
  organization, plan) and auth method from local config. Token, API key,
  password, and cookie values are never written. Credential stores are not
  decrypted. Claude `.credentials.json` is presence-only. Cursor `state.vscdb`
  is copied, then only the cached email and membership keys are queried.
  Codex `id_token` is decoded locally for email and plan; the token string
  is discarded.
- Raw transcript content only ever lands in the local `raw/` directory on your
  machine. The `evidence/` layer carries counts, hashes, and samples. Samples
  and rule text are masked only when `-Redact` is set. `-Redact` does not
  clean `raw/`. See [SCHEMA.md](SCHEMA.md).
- The default briefing (`-Briefing`, written to `briefing.html`) shows
  matched values, the text around them, and local file paths. That file
  holds live credentials. Keep it on this machine and delete it when you
  are done. The banner has a Hide values button for a screen share.
  `-ShowSecrets` writes the same unmasked content to `briefing-unmasked.html`.
  `-LocalLinks` writes `briefing-local.html` with full paths but values
  still masked. `-Redact` builds a shareable copy with values masked and
  paths hashed. `-AgentMode` also keeps values out of the briefing.
  Per-hit rows (file, line, column, value, surrounding text) are written
  under `raw/` as well.
- Redaction (`-Redact`) masks secret-shaped text, the running user's profile
  path and username, and other absolute paths in evidence samples and rules.
  It also hashes workspace labels. It does not rewrite `raw/`. Known limits
  are documented in SCHEMA.md. Review output before sharing it.
