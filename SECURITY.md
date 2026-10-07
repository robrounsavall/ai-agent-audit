# Security Policy

## Reporting a vulnerability

Use GitHub private vulnerability reporting on this repository (Security tab >
"Report a vulnerability"). Do not open a public issue for anything that could
leak user data, including parser bugs that cause under-redaction.

Reports that matter most here: any case where a collector writes raw
transcript content, credentials, or identifying filesystem paths into
`evidence/` output, or where `-Redact` fails to mask something it claims to
mask.

## What this tool does and does not do

- Read-only against AI tool data. Collectors never modify tool configuration,
  sessions, or credential stores.
- Offline by default. The collectors in `aiscan all` make no network calls
  and nothing is uploaded. `cloud-agents` is opt-in and is not part of
  `all`. It sends HTTPS GET requests only to `https://api.cursor.com`
  using a user-supplied `CURSOR_API_KEY`, which is never printed or written.
  It does not read the Cursor IDE session token or call dashboard APIs.
- Credential stores (`auth.json` and equivalents) are checked for presence and
  key names only. Token values are never read into output.
- Raw transcript content only ever lands in the local `raw/` directory on your
  machine. The `evidence/` layer carries counts, hashes, and redacted samples
  per [SCHEMA.md](SCHEMA.md).
- Redaction (`-Redact`) masks the running user's profile path and username and
  hashes other absolute paths. Known limits are documented in SCHEMA.md;
  review output before sharing it.
