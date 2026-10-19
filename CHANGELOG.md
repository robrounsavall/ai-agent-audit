# Changelog

All notable changes to aiscan are listed here, newest first. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
releases use [Semantic Versioning](https://semver.org/).

Collector versions (for example `pii-scan 1.3.0`) are tracked separately in
each collector's `__version__` and appear in the evidence envelopes.

## [Unreleased]

### Fixed

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
