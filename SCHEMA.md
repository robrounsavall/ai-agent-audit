# Collector Output Schema (Contract)

Every collector under `components/<name>/` MUST emit a single JSON file:

```
<evidence_root>/evidence/<collector_name>.json
```

Downstream tooling (report rendering, any sharing pipeline) keys off this
schema. A normal local run does not redact. `-Redact` and `AISCAN_REDACT=1`
are off unless the operator turns them on. With redaction off, samples,
rules, and workspace labels can contain real paths, names, and secret-shaped
text. Raw chat transcripts still stay in `raw/`. The take-home marks below
are what a sharing pipeline may copy, and only after redaction is on.
Anything unknown should be dropped before a file leaves the machine.

## Top-level shape

```json
{
  "collector": "claude",
  "version": "1.0.0",
  "aiscan_version": "0.2.0",
  "ran_at": "2026-05-23T19:30:00-04:00",
  "host": "DESKTOP-XYZ",
  "platform_detected": true,
  "scope_hash": "sha256-of-paths-scanned",
  "summary": {
    "<metric>": "<value>"
  },
  "findings": [ Finding, ... ],
  "rules": [ Rule, ... ],
  "raw_pointers": [ RawPointer, ... ]
}
```

| Field | Take-home? | Notes |
|---|---|---|
| `collector`, `version`, `ran_at`, `host`, `platform_detected` | YES | Metadata. `host` is short hostname only. `version` is the collector schema, not the aiscan release. |
| `aiscan_version` | YES | Optional. Present when aiscan itself wrote the envelope. A release looks like `0.2.0`. A checkout that is not that tag looks like `0.2.0-3-gabcdef` or `0.2.0-dirty`. A release zip with no git metadata uses the `VERSION` file. `tools/mcp-visibility` and the hand-written samples omit it; an envelope without the field is still valid. |
| `scope_hash` | YES | SHA-256 of sorted, normalized list of paths scanned. Proves coverage without revealing paths. |
| `summary` | YES | Numeric counts and labels only. NEVER strings derived from user content. |
| `findings` | YES (sanitized per field tags) | See Finding shape. |
| `rules` | YES (sanitized) | Permission/allow-list inventory. |
| `raw_pointers` | NO | File paths to raw evidence in `raw/` dir. Never leaves the machine. |

## Finding

```json
{
  "id": "claude.permission.bash_curl_wide",
  "severity": "high",
  "category": "Shell Execution",
  "title": "Claude has unrestricted curl approval",
  "evidence_count": 3,
  "first_seen": "2026-04-12T10:14:00Z",
  "last_seen": "2026-05-23T18:01:00Z",
  "sample_redacted": "Bash(curl ${URL})",
  "secret_redacted": false,
  "tags": ["network_egress"]
}
```

| Field | Type | Take-home | Sanitization |
|---|---|---|---|
| `id` | string | YES | stable dotted ID, no PII |
| `severity` | enum: low/medium/high/critical | YES | |
| `category` | string | YES | from controlled vocabulary below |
| `title` | string | YES | author-written, no customer data |
| `evidence_count` | int | YES | |
| `first_seen`, `last_seen` | ISO8601 | YES | |
| `sample_redacted` | string | Only after `-Redact` | The field name does not mean the value was masked. With redaction off, this is the collector's original sample and can include paths and secret-shaped text. With `AISCAN_REDACT` set, `sanitize_text` masks secrets and hashes absolute paths before this field is saved. |
| `secret_redacted` | bool | YES | true if a secret value was present and masked |
| `tags` | string[] | YES | controlled vocabulary |
| `raw_evidence_ref` | string | NO | path into raw/, never leaves the machine |

## Rule (permission inventory)

```json
{
  "platform": "claude",
  "scope": "user|workspace|project",
  "scope_label_redacted": "workspace#a1b2",
  "rule_type": "bash|powershell|mcp_tool|web_fetch|edit|other",
  "rule": "Bash(curl:*)",
  "decision": "allow|deny|ask",
  "command_or_tool_redacted": "curl",
  "risk": "low|medium|high|critical",
  "exposure_category": "Network Egress",
  "source_kind": "user_config|project_config|session_prefix|session_event",
  "confidence": "high|medium|observed_event"
}
```

`source_kind` and `confidence` are OPTIONAL (omit for collectors that do not
track provenance).

`scope_label_redacted`: Workspace and project names are PII. When redaction
is on, collectors replace the name with `<scope>#<short hash>`. When it is
off, they keep the last path segment as `<scope>:<name>`. That segment can
be a project name or a username. Full filesystem paths are not stored in
this field either way.

`Rule` records describe an effective permission decision. `decision` is limited
to `allow`, `deny`, or `ask`; collectors must not emit configuration posture as
an invented decision such as `config`. Settings such as sandbox mode, telemetry
enablement, or environment forwarding belong in sanitized findings and summary
metrics unless this contract is explicitly extended.

Rules carry two optional provenance fields so reports can group by source and
weight confidence:

- `source_kind`: `user_config` | `project_config` | `session_prefix` |
  `session_event`. Durable config grants use `*_config`; session-derived grants
  use `session_*`.
- `confidence`: `high` | `medium` | `observed_event`. `observed_event` marks a
  one-time approval seen in a session, not a persisted grant.

Both are emitted by `make_rule()` when supplied and are tagged share-safe
below. The Codex collector groups by these (`user_config` for config.toml
grants, `session_prefix`/`session_event` for session-derived rules).

## RawPointer

```json
{ "kind": "chat_transcript", "path": "raw/chat-history/claude/2026-05-22.md", "sha256": "..." }
```

Used for run bookkeeping. Never included in shared output.

## Controlled vocabularies

**Severity:** `low`, `medium`, `high`, `critical`

**Exposure category:** `Shell Execution`, `Network Egress`, `Data Access`,
`Telemetry Configuration`, `Cross-Agent Visibility`, `MCP Tooling`,
`Secrets Exposure`, `Source Code Egress`, `Git Posture`, `Identity & SSO`,
`General Tooling`

**Tags:** free-form short tokens, lowercase snake_case. Examples:
`network_egress`, `unbounded_glob`, `env_read`, `chat_plaintext`,
`history_retention`, `mcp_external`, `gh_token_present`, `pre_commit_missing`.

**Rule type:** `bash`, `powershell`, `mcp_tool`, `web_fetch`, `edit`,
`approval_event`, `other`

## Sanitization rules

These rules describe a redacted run, or a bundle someone is about to take
off the machine. They are not what a default local run writes.
`make_finding` and `make_rule` call `sanitize_text`, which returns the
original string unless `AISCAN_REDACT` is set (`-Redact` on `aiscan.ps1`).

Any shared bundle must be built field-by-field from this schema. Rules:

1. `raw_pointers` is dropped entirely.
2. Any field named `raw_evidence_ref` is dropped.
3. Any field ending in `_redacted` is passed through as-is. That value is
   masked only when the scan used `-Redact`. Any unsuffixed string that looks
   like a secret is masked again at sharing time, as a backstop.
4. `summary` values must be numeric or short controlled-vocab strings.
   Sanitizer drops any string > 64 chars or matching the secret regex.
5. Workspace and project names are stored in `scope_label_redacted`. With
   `-Redact`, that value is a hash. Without it, it is the last folder name,
   which can be a project name or a username. The full path is not copied
   into this field.
6. Chat transcript text NEVER appears in evidence/. It lives only in `raw/`.
   The chat-history collector emits counts, sizes, date ranges, and findings
   (e.g., "12 transcripts contain AKIA prefixes") but not text.
7. The `_redacted` suffix is not itself a transform. When redaction is on,
   collectors remove user names, workspace and repository paths, and
   WSL-mounted user paths before emitting these fields. When redaction is
   off, the same fields can still contain that text.

## Discovery summary block (safe metadata only)

`evidence/discovery.json` and the `summary.history_roots` block in collector evidence store a hash (`path_id`) instead of the raw path. That block does not contain filesystem paths. Other evidence files can, when redaction is off.

Each entry contains:

| Field | Type | Notes |
|---|---|---|
| `detected` | bool | Whether the path was found and readable |
| `file_count` | int | Count of matching files under the root |
| `newest` | ISO8601 date | Most recent file mtime |
| `source` | string | Source label: `default`, `cli`, `config`, `env:CODEX_HOME`, or `env:CLAUDE_CONFIG_DIR` |
| `path_id` | string | SHA-256 short hash of the normalized path. Proves identity without revealing it. |

For this block, coverage is provable and the resolved path is not stored. Console output and `--json` output from `discover.py` contain full paths. Those are not written into `discovery.json`. Other evidence can still contain paths when redaction is off.

## Redaction status

Redaction is off unless `-Redact` or `AISCAN_REDACT=1` is set. A default
local run keeps real paths, names, and secret-shaped samples in evidence.

Codex session parsing was hardened against two early defects (verified
2026-07-07 against the open-source `openai/codex` rollout format): prose is no
longer promoted into rule rows (`parse_approved_prefixes` accepts structured
JSON arrays only), and the operator's username/profile path is replaced with
`<user>`/`<userprofile>` tokens under `-Redact`. Known residue: workspace
folder names can survive inside command strings of session-derived rules, and
the envelope `host` field carries the short hostname. Review redacted output
before sharing it.

## Collector list (v1)

| Collector | Reads | Notes |
|---|---|---|
| `claude` | `~/.claude/settings*.json`, project `<repo>/.claude/settings.json` and `settings.local.json` (not the `~/.claude/projects` transcript folder), `~/.claude/projects/**/*.jsonl`, `%APPDATA%\Claude\claude_desktop_config.json` (mcpServers; collected even with no Claude Code home), `~/.claude` side artifacts (`history.jsonl`, `file-history/`, `bash-audit.log` — presence/size only) | Settings-file and project-JSONL permission inventory plus desktop MCP registry and retention findings |
| `cowork` | `%APPDATA%\Claude\local-agent-mode-sessions/**` (structure/counts only), `claude-code-sessions/**`, `cowork-file-preview/office-cache/*.pdf` (count; older installs — newer builds unpack Office files into per-session `outputs/`), `bridge-state.json`, webview state (`design`, `IndexedDB/https_claude.ai_0.indexeddb.leveldb/`, `Local Storage/leveldb/` — existence + newest mtime date only) | Cowork (Claude desktop app) session workspace inventory: transcripts, audit logs, outputs/uploads, preview cache, cloud bridging, plus claude.ai webview local-state presence (draft/composer state persists locally). Content never read. |
| `cursor` | `%APPDATA%\Cursor\User\globalStorage\state.vscdb`, `~/.cursor/projects/**` | Confirm or write off durable allow-list. |
| `codex` | `~/.codex/sessions/**/*.jsonl` (session prefixes + aggregated approval events) and `~/.codex/config.toml` (durable posture: trust, sandbox, approval, MCP, apps, telemetry, hooks) plus auth presence | Session parsing/redaction hardened; user-level config.toml parsed. Trusted-project `.codex/config.toml` layers remain additional coverage. |
| `grok` | `~/.grok/config.toml` (durable posture: `[ui].permission_mode`/`yolo`, `[mcp_servers.*]`, `[permission].allow`, `[subagents]`, `[memory]`) plus `<git-root>/.grok/config.toml` project layer; `~/.grok/sessions/**/summary.json` (metadata-only: session count, model distribution, message counts) and sibling `chat_history.jsonl`/`updates.jsonl`/`events.jsonl` (count/size only, never content in evidence) plus auth presence | `~/.grok/config.toml` uses the same `[mcp_servers.<name>]` TOML shape as Codex. `permission_mode = "always-approve"` or `yolo = true` is the headline critical finding. This collector is Grok Build, not Cursor's Grok Bot desktop app. |
| `grok-bot` | `%APPDATA%\Grok Bot` top-level names from a real install (presence, size, count, mtime only): `sand-secrets.json`, `box-secrets-push-state.v1.json`, `lockfile`, `desktop-status.json`, `Preferences`, `gateway-descriptor.json`, `Local State`, `window-state.json`, plus Chromium dirs (`Local Storage`, `Session Storage`, `Network`, `Cache`, …) and `sand-client-persistence`. Nothing under that directory is opened. | Cursor's Grok Bot desktop client. `local_execution` is `unknown` (`not_determinable_offline`): those names do not show whether local execution is on. No `rules` rows. Secrets-store and lockfile findings are presence only. |
| `accounts` | Plain identity fields only. See the accounts section below. | Signed-in identity per tool. No token, API key, password, or cookie values. No network. |
| `copilot` | `%APPDATA%\Code\User\settings.json`, JetBrains config | NEW. Enable state, exclude rules, telemetry, SKU. |
| `chat-history` | All 4 transcript sources | Writes raw markdown to `raw/chat-history/`. Evidence is counts + secret-hit findings only. |
| `git-posture` | Repos under user-specified roots | `.env` in history, hook presence, branch protection (opt-in `gh`), large blobs. |
| `secrets-scan` | `raw/chat-history/` + repo roots | Betterleaks, gitleaks, or trufflehog wrapper (first one found). `summary.scanner` names it; `summary.scanner_mode` is `betterleaks-v1` or `betterleaks-v2` for Betterleaks. Betterleaks validation is always forced off. Evidence samples shorten the secret (first and last four characters). File paths for those hits stay in `raw/secrets-scan/findings.csv` and are not removed by `-Redact`. Other evidence text is masked only when redaction is on. |
| `cloud-agents` | Official Cloud Agents API, `GET https://api.cursor.com` only, with a user-supplied `CURSOR_API_KEY` | Opt-in. Not part of `aiscan all`. Does not read the Cursor IDE session token or call `cursor.com/api/dashboard`. Does not call `GET /v1/repositories` or the enterprise Admin API. |
| `telemetry` | Local files only: OTLP JSON / JSON-lines (`--otel-file`) and Splunk JSON or CSV exports (`--splunk-export`) | Opt-in `aiscan telemetry`. Not part of `aiscan all`. Counts tool decisions and usage. Does not store prompts, commands, or secret values. `cost_cents` is copied from a Cursor dashboard usage export and is never estimated from tokens. |
| `changes` | Derived. Not a collector. `python core/scan_diff.py` compares two evidence roots and writes `evidence/changes.json` | The briefing loader skips this file when it walks collector envelopes and passes it only to the changes section. |
| `agent-summary` | Derived. Not a collector. `aiscan summary` (and every scan) writes `evidence/agent-summary.json` | Safe fields only: collector, detection, and finding severity, title, category, and evidence count. The briefing loader skips this file and `run-status.json`. |

## Cloud agent inventory (`cloud-agents`)

`evidence/cloud-agents.json` uses the envelope above plus two extra fields. It is produced only by the opt-in `cloud-agents` command.

| Field | Take-home? | Notes |
|---|---|---|
| `agents` | YES, review first | One object per cloud agent. Names, repository URLs, starting refs, branch names, and pull request URLs are operational inventory, not transcripts. |
| `limits` | YES | Fixed sentences describing what this API call does not include. |

`summary` for this collector:

| Field | Type | Notes |
|---|---|---|
| `key_configured` | bool | False when `CURSOR_API_KEY` was unset. The key itself is never stored. |
| `api` | string | Always `https://api.cursor.com` on a real run. |
| `total_agents` | int | Agents returned, including archived. |
| `agents_active` | int | Status `ACTIVE`, compared case-insensitively. Any other status, including undocumented ones, is not counted here. |
| `agents_running` | int | Latest run status `CREATING` or `RUNNING`. |
| `agents_with_prs` | int | Agents with at least one `prUrl`. Open, merged, and closed are not known; GitHub is not called. |
| `total_tokens` | int | Sum of per-agent `totalTokens`. Not dollars. |
| `by_status` | object | Map of the API's status string (any string) to a count. |
| `agent_errors` | int | Agents whose detail or run could not be read. |
| `usage_unavailable` | int | Agents whose usage endpoint returned 403 or 404. |
| `include_run_result` | bool | True only when `--include-run-result` / `-IncludeRunResult` was set. |

Each `agents[]` object:

| Field | Notes |
|---|---|
| `id`, `name`, `status`, `url` | Status is stored as returned. Unknown values are kept, not coerced. |
| `env_type`, `env_name` | From `env.type` / `env.name`. |
| `created_at`, `updated_at` | ISO-8601 timestamps from the API. |
| `repos[]` | `url`, `starting_ref`, `pr_url`. |
| `work_on_current_branch`, `auto_create_pr` | Booleans, or null when the API omitted them. |
| `branches[]` | `repo_url` (no scheme, as the API returns it), `branch`, `pr_url`. |
| `latest_run` | `id`, `status`, `duration_ms`. `result` is omitted unless the flag is set. |
| `tokens` | `input_tokens`, `output_tokens`, `cache_read_tokens`, `cache_write_tokens`, `total_tokens`. |
| `usage_unavailable` | True when the usage endpoint is not enabled for the key. |
| `error` | Short scrubbed note when a per-agent GET failed. |

Run `result` text can contain source code or secrets. It is not stored by default. With the flag, it is passed through `sanitize_text`, so `-Redact` / `AISCAN_REDACT` masks paths and secrets. The API key is removed either way. `/v1/me` is called only to authenticate; the response's email and name are not written.

The API key never appears in this file. Personal keys cannot be scoped to read-only; the collector still refuses every method except GET and every host except `api.cursor.com`.

## Telemetry import (`telemetry`)

`evidence/telemetry.json` is the opt-in telemetry envelope (`collector` = `telemetry`). It is not produced by `aiscan all`. Exit codes for the collector: 0 when at least one export was read, 2 when no file could be read (an envelope is still written, `platform_detected` false), 1 when `--evidence-root` does not exist.

`summary` when an export was read:

| Field | Notes |
|---|---|
| `approval_events`, `approvals`, `denials` | Counts of tool decisions. Approvals are `accept`; denials are `reject`. |
| `config_approvals`, `config_approval_percent` | Accepts whose source is `config` (no prompt). |
| `approvals_by_tool`, `approvals_by_source`, `approvals_by_group`, `approvals_by_day` | Rollups. Tool names only, not command text. |
| `usage_events`, `input_tokens`, `output_tokens`, `cache_read_tokens`, `cache_write_tokens`, `total_tokens` | Sums of exported token columns. |
| `cost_cents` | Present only when a row carried `cost_cents` from the Cursor dashboard usage export. |
| `cost_basis` | `cursor_dashboard` when `cost_cents` was in the export, otherwise `tokens_only` or `none`. |
| `cost_label` | `from the Cursor dashboard usage export` when dollars are shown. Dollars are not estimated from token counts. |
| `usage_by_tool`, `usage_by_model` | Same rule per row: a dollar figure only when that row had `cost_cents`. |

Prompt text, tool parameters, and secret-shaped attributes are dropped before anything is written.

## Scan-to-scan changes (`changes`)

`evidence/changes.json` is a normal major-version-1 envelope (`collector` = `changes`) plus a `changes` object. `aiscan` writes it when `-Briefing` is set, by running `core/scan_diff.py` against the previous evidence root. The briefing does not iterate this file with the other collectors.

`summary.comparison` is `first_scan` when no earlier scan was found, and `diff` otherwise. Count fields include `findings_added`, `findings_resolved`, `new_high_or_critical`, `drift_warnings`, `mcp_servers_added`, `allow_rules_added`, and `counters_moved`. Per-collector before/after counters live under `changes.collectors`. The file does not copy transcript bodies. Titles and rule text go through `sanitize_text`, so without `-Redact` they can still contain paths.

A collector that previously had data and now reports none is a drift warning, not a clean result. Long-term trends (token lines over months, and so on) belong in Splunk, not in a pile of HTML files. See [docs/scan-history.md](docs/scan-history.md) and [docs/report-v2.md](docs/report-v2.md).

## Agent summary (`agent-summary`)

`evidence/agent-summary.json` is not a collector envelope. `aiscan summary` prints the same JSON, and every scan writes the file. It is the only scan output an agent should read.

| List | Fields |
|---|---|
| `collectors` | `collector`, `platform_detected`, `detection_status` |
| `findings` | `collector`, `severity`, `title`, `category`, `evidence_count` |
| `collector_errors` | `collector`, `platform_detected`, `detection_status` |
| `coverage_caveats` | same fields as `findings` |

Findings are sorted by severity (`critical`, `high`, `medium`, `low`, then `unknown`), then real findings before any finding the collector tagged `test_data` (that tag is not copied), then by `evidence_count` descending. Remaining ties break on collector, category, then title. `evidence_count` is the count that collector recorded. Collectors do not share one unit. A severity outside that list is stored as `unknown` and still listed.

The object also has `aiscan_version`, the same string the scan printed (`git describe` in a checkout, the `VERSION` file in a release zip).

`detection_status` is one of `detected`, `not detected`, `parse error`, `not collected`, or `error (exit N)`. A known exit other than 0 is a collector error even when an envelope was written, listed as `error (exit N)`. Exit 0 with no evidence file is `error (exit 0)`, the same rule the scan uses when a collector writes nothing. Exit 2 with a parsed envelope is not an error: collectors use that for "not detected", and the status then follows `platform_detected`. Exit 2 with no file is `error (exit 2)`. An unreadable envelope is `parse error`. When no exit code was stored, status follows `platform_detected`.

Coverage caveats are findings that describe a gap (missing scanner, nothing to scan, a `coverage` tag or id). They appear only in `coverage_caveats`, not in `findings`. A secrets-scan envelope whose `summary.scanner` is `none`, and that has no coverage finding of its own, adds the caveat "No secrets scanner found".

Titles and categories are always masked for paths and secrets, even when the scan itself was unredacted. Paths, samples, rules, and raw pointers are not copied. `evidence/run-status.json` stores exit codes for a later summary. Running `summary` again keeps those exit codes. It is not a collector envelope. The briefing loader skips both files.

## Account identities (`accounts`)

`evidence/accounts.json` is produced by `aiscan all` and by `aiscan accounts`. It uses the envelope above plus an `accounts` array and a `limits` array. `summary` stays numeric. Identifiers live only in `accounts[]` and in finding samples.

| Field | Take-home? | Notes |
|---|---|---|
| `accounts` | YES, after review | One object per tool, API-key row, or MCP server that has auth configured. |
| `limits` | YES | Fixed sentences describing what this collector does not read. |

`summary`:

| Field | Type | Notes |
|---|---|---|
| `tools_reported` | int | Rows in `accounts`. |
| `signed_in` | int | Rows whose `signed_in` is `yes`. |
| `unknown` | int | Rows whose `signed_in` is `unknown`. |
| `not_signed_in` | int | Rows whose `signed_in` is `no`. |
| `distinct_accounts` | int | Distinct account identifiers, compared case-insensitively. MCP rows are not included. |
| `api_key_rows` | int | Rows whose auth method is an API key, env var, or header. |
| `subscription_rows` | int | Rows whose auth method is `oauth`. |
| `findings` | int | Finding count. |

Each `accounts[]` object:

| Field | Notes |
|---|---|
| `tool` | `claude-code`, `codex`, `cursor`, `copilot`, `grok`, `grok-bot`, `git`, `gh`, or `mcp:<server>`. |
| `signed_in` | `yes`, `no`, or `unknown`. |
| `account` | Email or username. Empty when only an API key is present. |
| `organization` | Organization, team, or GitHub host when stored in plain config. |
| `plan` | Plan or membership tier when stored in plain config (`pro`, `supergrok`, …). |
| `auth_method` | `oauth`, `api_key`, `git_config`, `config`, `not_present`, `unreadable`, `unknown`, or an MCP method list such as `env:NAME`, `header:Authorization`, `url_userinfo`, `args:authorization`. |
| `source` | Home-relative path (`~/.codex/auth.json`, `%APPDATA%/...`), a file name when the path is outside the profile, or `env:NAME`. Never an absolute path. |
| `last_sign_in` | ISO-8601 when a timestamp field exists. For Codex this is `last_refresh` in `auth.json`. Empty when the tool does not store one. |

Redaction stays off unless `-Redact` or `AISCAN_REDACT=1` is set, so a normal scan keeps these identifiers. With that flag, emails in `account`, `organization`, `plan`, `source`, `last_sign_in`, `auth_method`, and finding samples are replaced with `<email>` before the file is written. The briefing does the same when it renders an already-written file with redaction on.

What each tool reads, and what is deliberately not read:

| Tool | Read | Not read |
|---|---|---|
| Claude Code | `~/.claude.json` `oauthAccount` (`emailAddress`, `organizationName`, plan/billing fields). `primaryApiKey` and `settings.json` `env` contribute **presence and the variable name only**. `.credentials.json` is presence only. | `.credentials.json` contents. Project history. Any key value. |
| Codex | `~/.codex/auth.json`. Email and plan are decoded from the `id_token` JWT payload (`email`, `https://api.openai.com/auth` `chatgpt_plan_type`). Organization is `organization_name` or `org_name` when that claim is set, otherwise the default (or first) `organizations` entry's `title` or `name`. `last_refresh` is the last sign-in field. `OPENAI_API_KEY` is presence only. | `access_token`, `refresh_token`, the `id_token` string, API key values, organization ids, and every other claim (account id, user id, name). |
| Cursor | A **copy** of `state.vscdb`. Query keys: `cursorAuth/cachedEmail`, `cursorAuth/stripeMembershipType`, `cursorAuth/cachedSignUpType`, `cursorAuth/stripeSubscriptionStatus`. The original file is not opened. | Every other key, including access and refresh tokens. |
| Copilot | Top-level JSON in the Copilot globalStorage directory (email, `organizationLogin`, `sku`) and a short `copilot-user` file. | Files whose names contain `token`, `secret`, or `cookie`. |
| Grok CLI | `~/.grok/auth.json`, `user-settings.json`, `user_settings.json`, `user-settings.toml`. Allowlisted keys only (email, username, org, plan, last sign-in). | Token and API key values. Session transcripts. |
| Grok Bot | `desktop-status.json`, `Preferences`, `Local State`. Allowlisted keys only. | Cookies, Local Storage, Session Storage, Network, Cache, `sand-secrets.json`, `box-secrets-push-state.v1.json`. |
| GitHub CLI | `hosts.yml` lines whose key is `user`. | `oauth_token` and every other key. |
| git | Global config `[user]` `email` and `name`. | Credential helpers, `include` files, other sections. |
| MCP | Auth method: env var **names**, header **names**, whether a URL has userinfo, whether an arg mentions Authorization. | Header values, env values, URLs, commands. |
| Environment | Whether `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `XAI_API_KEY`, or `CURSOR_API_KEY` is set to a non-empty string. | The values. |

No network calls. No cookie decryption. No credential-store decryption.

Findings:

| id | When |
|---|---|
| `accounts.identity.multiple` | Two or more distinct account identifiers across tools (medium, Identity & SSO). |
| `accounts.auth.api_key_and_subscription` | At least one API-key-style row and one `oauth` row. Medium when the same tool has both, otherwise low. |

## Versioning

Bump `version` (semver) on any schema change. Downstream tooling (e.g. the
briefing builder) refuses to process evidence with a major version it does not
understand.

`aiscan_version` does not bump that number. It is an optional field, and
collectors that already write major version 1 stay on `1.x`. Readers must
accept an envelope that omits it.
