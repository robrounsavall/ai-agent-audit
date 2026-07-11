# Collector Output Schema (Contract)

Every collector under `components/<name>/` MUST emit a single JSON file:

```
<evidence_root>/evidence/<collector_name>.json
```

Downstream tooling (report rendering, any sharing/sanitization pipeline) keys
off this schema. Fields marked share-safe below are the only fields that should
ever leave the machine. Anything unknown is dropped by default.

## Top-level shape

```json
{
  "collector": "claude",
  "version": "1.0.0",
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
| `collector`, `version`, `ran_at`, `host`, `platform_detected` | YES | Metadata. `host` is short hostname only. |
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
| `sample_redacted` | string | YES | MUST already be redacted by collector. Use `${VAR}` for variable parts. |
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

`scope_label_redacted`: Workspace and project names are PII. Replace with
`<scope>#<short hash of original name>` before writing. Collectors do this.

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

Any shared bundle must be built field-by-field from this schema. Rules:

1. `raw_pointers` is dropped entirely.
2. Any field named `raw_evidence_ref` is dropped.
3. Any field ending in `_redacted` is passed through as-is (collector
   guarantees it is safe). Any unsuffixed string that LOOKS like a secret
   (matches secret regex) is masked at sanitization time as belt-and-suspenders.
4. `summary` values must be numeric or short controlled-vocab strings.
   Sanitizer drops any string > 64 chars or matching the secret regex.
5. Workspace/project names: collectors emit `scope_label_redacted` only.
   Original names live in `raw/`.
6. Chat transcript text NEVER appears in evidence/. It lives only in `raw/`.
   The chat-history collector emits counts, sizes, date ranges, and findings
   (e.g., "12 transcripts contain AKIA prefixes") but not text.
7. The `_redacted` suffix is a collector guarantee, not a sanitizer transform.
   Collectors MUST remove user names, workspace/repository paths, WSL-mounted
   user paths, and irrelevant surrounding session text before emitting these
   fields.

## Discovery summary block (safe metadata only)

`evidence/discovery.json` and the `summary.history_roots` block in collector evidence carry safe metadata only. No raw filesystem paths appear in any stored evidence.

Each entry contains:

| Field | Type | Notes |
|---|---|---|
| `detected` | bool | Whether the path was found and readable |
| `file_count` | int | Count of matching files under the root |
| `newest` | ISO8601 date | Most recent file mtime |
| `source` | string | Source label: `default`, `cli`, `config`, `env:CODEX_HOME`, or `env:CLAUDE_CONFIG_DIR` |
| `path_id` | string | SHA-256 short hash of the normalized path. Proves identity without revealing it. |

This is consistent with the `scope_hash` rule above: coverage is provable; resolved paths are not exposed. Console output and `--json` output from `discover.py` contain full paths — those stay on the operator's machine and are never persisted to evidence.

## Redaction status

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
| `claude` | `~/.claude/settings*.json`, project `.claude/settings.local.json`, `~/.claude/projects/**/*.jsonl` | Settings-file and project-JSONL permission inventory |
| `cursor` | `%APPDATA%\Cursor\User\globalStorage\state.vscdb`, `~/.cursor/projects/**` | Confirm or write off durable allow-list. |
| `codex` | `~/.codex/sessions/**/*.jsonl` (session prefixes + aggregated approval events) and `~/.codex/config.toml` (durable posture: trust, sandbox, approval, MCP, apps, telemetry, hooks) plus auth presence | Session parsing/redaction hardened; user-level config.toml parsed. Trusted-project `.codex/config.toml` layers remain additional coverage. |
| `grok` | `~/.grok/config.toml` (durable posture: `[ui].permission_mode`/`yolo`, `[mcp_servers.*]`, `[permission].allow`, `[subagents]`, `[memory]`) plus `<git-root>/.grok/config.toml` project layer; `~/.grok/sessions/**/summary.json` (metadata-only: session count, model distribution, message counts) and sibling `chat_history.jsonl`/`updates.jsonl`/`events.jsonl` (count/size only, never content in evidence) plus auth presence | `~/.grok/config.toml` uses the same `[mcp_servers.<name>]` TOML shape as Codex. `permission_mode = "always-approve"` or `yolo = true` is the headline critical finding. |
| `copilot` | `%APPDATA%\Code\User\settings.json`, JetBrains config | NEW. Enable state, exclude rules, telemetry, SKU. |
| `chat-history` | All 4 transcript sources | Writes raw markdown to `raw/chat-history/`. Evidence is counts + secret-hit findings only. |
| `git-posture` | Repos under user-specified roots | `.env` in history, hook presence, branch protection (opt-in `gh`), large blobs. |
| `secrets-scan` | `raw/chat-history/` + repo roots | gitleaks wrapper. Findings only, redacted samples. |

## Versioning

Bump `version` (semver) on any schema change. Downstream tooling (e.g. the
briefing builder) refuses to process evidence with a major version it does not
understand.
