# Changelog

All notable changes to aiscan are listed here, newest first. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
releases use [Semantic Versioning](https://semver.org/).

Collector versions (for example `pii-scan 1.3.0`) are tracked separately in
each collector's `__version__` and appear in the evidence envelopes.

## [Unreleased]

### Added

- `accounts` collector, included in `aiscan all`. It reports which identity
  each local AI tool is signed in as: tool, signed-in yes/no/unknown, email
  or username, organization, plan, auth method, home-relative source path,
  and last sign-in time when a timestamp is stored. Claude Code reads
  `oauthAccount` in `~/.claude.json`. Codex decodes the `id_token` payload
  in `~/.codex/auth.json` for email and plan, and takes the organization
  from `organization_name`, `org_name`, or the default (or first)
  `organizations` entry's title or name. Cursor copies `state.vscdb` and
  reads only `cursorAuth/cachedEmail` and `cursorAuth/stripeMembershipType`
  (plus two related auth keys). Grok CLI, Copilot, Grok Bot plain config,
  `gh` `hosts.yml` user, and global git `user.email` are included. MCP
  configs contribute auth method only (env var or header name).
  `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `XAI_API_KEY`, and `CURSOR_API_KEY`
  are presence-only. Findings: more than one distinct account, and API-key
  auth alongside subscription auth. `-Redact` stays off unless it is passed.
  With `-Redact`, emails are masked as `<email>`. Token, API key, password,
  and cookie values are not written. No network calls and no
  credential-store decryption. [RUN-AISCAN.md](RUN-AISCAN.md) tells an agent
  to summarize those identifiers instead of quoting them.
- [RUN-AISCAN.md](RUN-AISCAN.md), instructions an AI agent can follow to run
  one scan without reading transcripts or uploading results. The scan
  command in that file does not pass `-Redact`.
- `aiscan summary` prints a safe summary of a finished scan: collector,
  detection status, and each finding's severity, title, category, and
  evidence count. Paths, samples, rules, and raw pointers are left out.
  Titles and categories are masked even when the scan was unredacted.
  Coverage gaps are listed only as caveats, not as ranked findings. A bad
  evidence file is one collector error and does not stop the summary.
  Every run also writes `evidence\agent-summary.json`. The summary includes
  `aiscan_version`. `OUTDIR_ID=<folder name>` is printed only when that
  folder exists and will be kept. Running `summary` again keeps stored
  collector exit codes. With no `-OutDir`, `summary` reads the newest folder
  under `%LOCALAPPDATA%\aiscan-results`.
- `-AgentMode` prints scan paths relative to the output folder and omits the
  closing "Evidence kept at" line. The summary table and errors stay.
- Evidence envelopes include `aiscan_version`, the tool version that wrote
  them.

### Changed

- Docs no longer say the default output has no identifying paths or is
  redacted. `-Redact` stays off unless you pass it. It masks paths and
  secrets in evidence and the briefing, and it does not clean `raw/`.
- `aiscan all` prints the tool version from `git describe --tags` in a
  checkout, and from the `VERSION` file in a release zip. A checkout that is
  not exactly the release tag no longer prints `dev`.
- The release build refuses to publish when `VERSION` does not match the tag.
  Bump `VERSION` in the commit you tag.
- `secrets-scan` 1.1.0 reports one finding per scanner rule and severity.
  `evidence_count` is the number of hits, and the title includes how many
  files were involved. Per-hit rows stay in `raw/secrets-scan/findings.csv`.
  Severity comes from an explicit rule list (high-impact tokens are
  critical; every other rule is high) instead of a substring of the rule
  name. A rule whose hits are all placeholders is counted, and the briefing
  labels that rule as a likely test value.
- `git-posture` 1.1.0 reports one finding per check, with the repo or blob
  count in the title. The large-blob title includes the largest size.
  `.env.example`, `.env.sample`, `.env.template`, and `.env.dist` are not
  treated as a committed `.env`. A `.gitignore` comment or a `!.env` line
  no longer counts as ignoring that file.
- The briefing keeps the severity stored on these grouped secret findings,
  so the HTML matches the summary. Older per-hit secret titles still use
  the previous substring severity. Evidence cards for a grouped rule list
  every file for that rule, including when the scanner spelled the rule
  two ways.
- `secrets-scan` does not scan its own output folder when that folder sits
  inside a repository being scanned.
- The next scan diff can show each secret once as changed, because the
  title and the hit count moved from one row per hit to one row per rule.
  Finding ids keep the previous `secrets_scan.<rule>` shape (lowercase,
  spaces as underscores, 40 characters). A rule name longer than that gains
  a short hash so two long names do not share an id. Those ids are not
  reported as resolved and added back.

### Fixed

- A single collector without `-Json` printed the detailed console view,
  including the machine hostname, finding titles, and samples, even with
  `-AgentMode` or `-Redact`. With `-AgentMode` it now prints only the
  summary line (collector, detected, finding count). With `-Redact` and
  without `-AgentMode`, that view masks the hostname as `<host>`.
  `-Redact` stays off unless you pass it.
- The process exits 2 when a collector errors, writes no evidence file, or
  writes a file that is not a readable envelope. It exits 3 when the only
  failure is the briefing. A normal run, including "platform not detected",
  still exits 0.
- A previous envelope in the output folder is removed before that collector
  runs, so a new failure cannot be read as "not detected".
- `Opened briefing in default browser` is printed only when the browser
  launch succeeds.
- Throwaway output folders include a unique id, so two runs started in the
  same second do not share a directory.
- A byte-order mark in `VERSION` is ignored, and the release zip writes that
  file once.
- With `-Redact`, the closing note says this run's new evidence and briefing
  are redacted, that `raw\` is not, and that older files already in the folder
  are left as they were. Without `-Redact`, the previous warning is unchanged.
- The README asked for Python 3.10+, but collectors import `tomllib` (3.11).
  It now says 3.11+, and `aiscan.ps1` stops immediately if `python` is older.
- Windows PowerShell 5.1 was reading evidence with the ANSI code page and
  discovery JSON with the OEM code page, which mangled non-ASCII text. Evidence
  is read as UTF-8, and discovery JSON escapes non-ASCII paths.
- On Python 3.14 and newer, compressed Codex session logs (`.jsonl.zst`)
  are decompressed with the standard-library `compression.zstd` module and
  scanned (Codex, chat history, PII, and secrets). On older Python they are
  counted, not opened, and reported as a low finding, "N compressed Codex
  session logs not scanned". A compressed log that is corrupt, too large,
  or too slow to unpack is a coverage note, not a failed run. The Codex
  briefing row uses session activity for last used, and shows the Desktop
  app's last opened date on its own row.
- trufflehog is started with `--no-verification` and `--no-update`, so a
  secrets scan does not check secrets online or phone home for updates.
- A gitleaks or trufflehog run that fails is a finding. It is no longer
  reported as zero hits.
- PII scan counts a built-in list of common test card numbers as a low
  finding. The briefing calls them "Test card numbers". Other valid card
  numbers stay critical.
- With `-Redact`, pii-scan does not write scan-target paths into the
  evidence file.
- `--dry-run` does not write the pii-scan or secrets-scan raw files.
- git-posture does not lazy-fetch missing objects from a partial clone, and
  reports those repos as a coverage gap.
- Claude project settings are read from `<repo>/.claude/settings.json` and
  `settings.local.json`. A Claude Desktop install with no Claude Code home
  is still collected.
- "Is this MCP server local?" compares the URL host. `localhost.evil.example`
  and a query string of `127.0.0.1` are not treated as localhost.
- A config file with a BOM or comments is read. A file that cannot be decoded
  is reported as a parse problem instead of aborting the collector or looking
  like the file was missing.
- Copilot's enable setting is read when it is a per-language object, and an
  organization login is not copied into the summary.
- A chat transcript line that is not a JSON object, or a message stored as a
  plain string, is skipped or kept. It does not stop the chat-history export.
- An OpenTelemetry URL with a port above 65535 is recorded as
  `invalid-endpoint` instead of stopping the Claude or Codex collector.
- Cursor's state database still opens when the path contains `#`, `?`, or `%`.
- A telemetry timestamp has to be a real date. Trailing junk is not stored as
  the first or last time seen. One oversized or deeply nested export is
  counted as failed and the other files are still read.
- An MCP config whose `args` is not a list, or whose URL is a broken IPv6
  address, is recorded as unknown instead of stopping the MCP inventory.
- A Grok session with a missing, unreadable, or non-object `summary.json` is
  counted as sandbox unknown. It is not reported as sandbox off. A readable
  `sandbox_profile` of `off` is unchanged.
- The briefing skips one unreadable evidence file and keeps going. A count
  that is not a number is shown as zero instead of stopping the report.
- With `-Redact`, finding titles and first/last-seen dates are masked, and a
  redacted scan no longer copies raw rules, titles, or MCP names out of an
  older unredacted scan. Secrets shorter than 24 characters are fully masked.
  Lines are masked before they are shortened, so a cut token cannot leak as a
  fragment. Secret masking covers dashed vendor keys (`sk-ant-`, `sk-proj-`,
  `xai-`, `AIza`), `Authorization` and `Bearer` headers, `password=` values,
  and credentials in URLs. Path masking covers UNC paths (`\\server\share`,
  `\\wsl$`) and quoted paths, and a short username no longer rewrites a longer
  word. Telemetry endpoint, protocol, and service name are masked with the
  rest of the evidence. The briefing only uses a severity of critical, high,
  medium, or low in a pill's class.
- The scrub gate treats a Windows hostname as uppercase `DESKTOP-` plus the
  7-character suffix, so a file named `desktop-status.json` is not flagged.
  The documented AWS example keys are allowed only as those exact values. A
  realistic `DESKTOP-` hostname is still rejected.
- `secrets-scan` does not walk a repository for compressed transcripts when
  Windows spells that folder as both a short 8.3 name and a long name.

## [0.2.0] - 2026-10-15

### Added

- Release automation. Pushing a `v*` tag builds `aiscan-<version>.zip`
  (runtime files only), its `.sha256` file, and `get-aiscan.ps1`, and
  attaches them to the GitHub release (#10).
- `get-aiscan.ps1`, a one-line way to run aiscan without cloning. It
  downloads the release zip to `%LOCALAPPDATA%\aiscan\<version>`, checks the
  SHA256, extracts it, and runs `aiscan.ps1` with your arguments. No admin
  rights, and no machine-wide execution policy change. `-Version` pins a
  release and `-InstallOnly` stops after install (#10).
- `aiscan all` prints the aiscan version at the start (`dev` in a checkout)
  (#10).
- Report v2: a summary-first, tabbed HTML briefing with tabs for Findings,
  Access map, Changes, Agents / collectors, Approvals, Usage and Coverage
  gaps (#7, combining #1, #3, #4, #5, #6 and #8).
- Access map: what each agent can do (shell, files, network, secrets, git,
  remote, approval), read only from the evidence (#7).
- Scan-to-scan changes: `core/scan_diff.py` writes `evidence\changes.json`
  against the previous scan before a briefing is built. New `-Previous` and
  `-HistoryRoot` options (#7).
- `grok-bot` collector: Grok Bot desktop app presence, sizes and newest
  activity. Contents are not read (#7).
- `cloud-agents` command (opt-in, not part of `all`): read-only inventory of
  Cursor cloud agents through `GET https://api.cursor.com` with a
  `CURSOR_API_KEY` you supply. `-IncludeRunResult` is off by default (#7).
- `telemetry` command (opt-in, not part of `all`): approval and usage counts
  from local OTLP and Splunk export files, via `-OtelFile` and
  `-SplunkExport` (#7).
- `scripts/build-draft-report.ps1`, to rebuild the HTML from evidence you
  already have, and a synthetic draft at `samples/report-v2-draft.html` (#7).
- `cowork` collector: Claude desktop app Cowork sessions (transcripts,
  outputs, Office preview cache, cloud bridging), structure and counts only.
  Later versions add a webview local-state check (1.1.0) and a Claude
  Design usage finding (1.2.0). Runs in `all`.
- `claude` collector: MCP servers from the Claude desktop app config, and
  findings for `history.jsonl`, `file-history/` and `bash-audit.log`
  retention (presence and size only).

### Changed

- `pii-scan` 1.3.0 is a pure stdlib rewrite. Presidio and spaCy are gone,
  `requirements.txt` is removed, and detectors use real validation (Luhn for
  cards, SSN issuance rules, IBAN mod-97, public IPs). `pii-scan` now runs in
  `all`.
- Redaction is opt-in everywhere. `AISCAN_REDACT=1` (or `-Redact`) masks
  output for sharing and replaces `AISCAN_NO_REDACT`.
- `pii-scan` drops noisy default entities (DATE_TIME, URL, PERSON,
  LOCATION) and caps stored samples per file.
- The briefing cover shows last-used dates per tool. Collector versions
  moved to the Collection scope table.
- The briefing opens offline with no font download.

### Fixed

- Cowork evidence loaded but never rendered in the briefing.
- `pii-scan` `findings.csv` masked samples even in unredacted local mode.

## [0.1.0] - 2026-07-11

### Added

- First public release. `aiscan.ps1` runs one collector or `all` and
  writes evidence envelopes defined in `SCHEMA.md`.
- Collectors: `claude`, `cursor`, `codex`, `copilot`, `grok` (Grok Build),
  `chat-history`, `git-posture`, `secrets-scan` (gitleaks or trufflehog) and
  `pii-scan` (Presidio-based at this version).
- HTML briefing (`-Briefing`) and a sample report built from synthetic data.
- `tools/mcp-visibility`, a standalone MCP server inventory.
- Per-component tests and a CI matrix on `windows-latest`.

[Unreleased]: https://github.com/robrounsavall/ai-agent-audit/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/robrounsavall/ai-agent-audit/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/robrounsavall/ai-agent-audit/releases/tag/v0.1.0
