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

## What this tool does and does not do

- Read-only against AI tool data. Collectors never modify tool configuration,
  sessions, or credential stores.
- Offline by default. The collectors in `aiscan all` make no network calls
  and nothing is uploaded. `cloud-agents` is opt-in and is not part of
  `all`. It sends HTTPS GET requests only to `https://api.cursor.com`
  using a user-supplied `CURSOR_API_KEY`, which is never printed or written.
  It does not read the Cursor IDE session token or call dashboard APIs.
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
- Redaction (`-Redact`) masks secret-shaped text, the running user's profile
  path and username, and other absolute paths in evidence samples and rules.
  It also hashes workspace labels. It does not rewrite `raw/`. Known limits
  are documented in SCHEMA.md. Review output before sharing it.
