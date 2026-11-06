"""Content for the aiscan Data Atlas (docs/aiscan-data-atlas.html).

Every claim about aiscan carries a source citation. A citation is
(path, first line, last line, anchor). `build_atlas.py --verify` checks that
each anchor string appears inside its line range in the working tree, so a
citation that drifts from the code fails loudly instead of rotting quietly.

Public vendor documentation is cited by key into DOCS. Those pages are not
under version control; each entry records the date it was read.

Only generic placeholder paths appear here: %USERPROFILE%, %APPDATA%,
%LOCALAPPDATA%, %ProgramData%, %TEMP%, <repo>, <scan-root>. No machine data.
"""

from __future__ import annotations

BASE_SHA = "07153c79d4adc057bf2c936aa359cc8b19f2abea"
REPO_URL = "https://github.com/robrounsavall/ai-agent-audit"
AISCAN_VERSION = "0.2.0"
RESEARCHED_ON = "2026-11-06"


def C(path: str, start: int, end: int, anchor: str) -> tuple:
    return ("src", path, start, end, anchor)


def D(key: str) -> tuple:
    return ("doc", key)


DOCS = {
    "claude-data-usage": {
        "short": "Claude Code · data usage",
        "title": "Claude Code docs: Data usage",
        "url": "https://docs.claude.com/en/docs/claude-code/data-usage",
        "accessed": RESEARCHED_ON,
        "used_for": (
            "Prompts and model outputs are sent to the model provider over TLS; "
            "Anthropic retention periods by account type; local transcripts under "
            "~/.claude/projects/ kept 30 days by default (cleanupPeriodDays), with "
            "Claude Desktop and Cowork sessions exempt by default; cloud sessions "
            "run in Anthropic-managed VMs with transcripts stored by Anthropic; "
            "Remote Control transcripts are also stored on Anthropic servers while connected."
        ),
    },
    "codex-config-advanced": {
        "short": "Codex · advanced config",
        "title": "OpenAI Codex docs: Advanced configuration (config and state locations, history persistence)",
        "url": "https://developers.openai.com/codex/config-advanced",
        "accessed": RESEARCHED_ON,
        "used_for": (
            "Codex keeps local state under CODEX_HOME (default ~/.codex): config.toml, "
            "auth.json when file-based credential storage is used (otherwise the OS "
            "keychain/keyring), and history.jsonl when history persistence is on."
        ),
    },
    "codex-cloud": {
        "short": "Codex · Cloud",
        "title": "OpenAI Codex docs: Codex Cloud",
        "url": "https://developers.openai.com/codex/cloud",
        "accessed": RESEARCHED_ON,
        "used_for": (
            "Codex Cloud tasks run in cloud environments with their own workspace and "
            "can continue while the local computer is asleep."
        ),
    },
    "cursor-cloud-agent": {
        "short": "Cursor · Cloud Agents",
        "title": "Cursor docs: Cloud Agents",
        "url": "https://cursor.com/docs/cloud-agent",
        "accessed": RESEARCHED_ON,
        "used_for": (
            "Cloud agents run in isolated cloud VMs, clone the repository, and push "
            "branches; user-level ~/.cursor/hooks.json is not available in the VM."
        ),
    },
    "cursor-cloud-security": {
        "short": "Cursor · cloud agent security",
        "title": "Cursor docs: Cloud Agent security overview (what data is stored, where, and for how long)",
        "url": "https://cursor.com/docs/cloud-agent/security",
        "accessed": RESEARCHED_ON,
        "used_for": (
            "Runtime workspace lives in the VM; VM snapshots are kept on a rolling 30 days "
            "of inactivity; conversation state is kept in Cursor's backend indefinitely by "
            "default and is deletable; secrets live in encrypted backend stores."
        ),
    },
    "cursor-privacy-governance": {
        "short": "Cursor · privacy & governance",
        "title": "Cursor docs: Privacy and Data Governance",
        "url": "https://cursor.com/docs/enterprise/privacy-and-data-governance",
        "accessed": RESEARCHED_ON,
        "used_for": (
            "Two data flows leave the machine: LLM requests (prompts and code context "
            "to model providers) and Cloud Agents (temporarily stored encrypted repository copies)."
        ),
    },
    "vscode-chat-sessions": {
        "short": "VS Code · chat sessions",
        "title": "VS Code docs source: chat-sessions.md (microsoft/vscode-docs at 36ba054f)",
        "url": "https://github.com/microsoft/vscode-docs/blob/36ba054f/docs/copilot/chat/chat-sessions.md",
        "accessed": RESEARCHED_ON,
        "used_for": "The Chat view lists local and active chat sessions per workspace; sessions can be exported as JSON.",
    },
    "vscode-session-history": {
        "short": "VS Code · session history",
        "title": "VS Code docs: Save, sync, and query session history",
        "url": "https://code.visualstudio.com/docs/agents/run/sessions/session-history",
        "accessed": RESEARCHED_ON,
        "used_for": (
            "Session sync (Experimental, chat.sessionSync.enabled, default false) can upload "
            "local session history to the user's GitHub account; a local SQLite session store "
            "records metadata, conversation turns and touched file paths."
        ),
    },
}


CATEGORIES = (
    ("auth", "Accounts & auth"),
    ("config", "Permissions & config"),
    ("sessions", "Sessions & chat"),
    ("cache", "Caches, databases & app state"),
    ("remote", "Remote / cloud"),
)

MODES = {
    "parsed": ("Parsed", "Content is parsed and specific settings become rules, findings or summary values."),
    "allowlist": ("Allowlisted keys", "File is opened, but only named identity or policy keys are kept. Everything else is ignored."),
    "metadata": ("Metadata only", "File is parsed for counts, modes or model names. Prompt and response text are not kept in evidence."),
    "stat": ("Presence / size / date", "Existence, size, count or modified date only. Contents are never opened."),
    "export": ("Exported to raw/", "Text is copied into the local raw/ folder of the scan. Evidence gets counts and secret-hit findings only."),
    "notread": ("Not read", "No collector in this commit opens this location."),
    "network": ("Opt-in network GET", "Read from a vendor API only when the operator runs an opt-in command and supplies a key."),
}

COLLECTOR_STATUS = {
    "all": "Runs in aiscan all",
    "optin": "Opt-in, not in all",
    "tool": "Standalone tool, not run by aiscan.ps1",
    "derived": "Derived from evidence",
}


HARNESSES = [
    {
        "id": "claude-code",
        "name": "Claude Code",
        "short": "Claude Code",
        "vendor": "Anthropic",
        "collectors": ["claude", "chat-history", "accounts", "pii-scan"],
        "summary": (
            "The `claude` collector turns user and project settings into a permission inventory and "
            "flags risky modes. `chat-history` copies transcript text into `raw/`. `accounts` keeps the "
            "signed-in email, organization and plan, never a token."
        ),
        "rows": [
            {
                "cat": "config",
                "loc": r"%USERPROFILE%\.claude\settings.json, settings.local.json",
                "keeps": "User-level permission rules (allow / deny / ask), default permission mode, env block.",
                "reads": [
                    ("claude", "parsed",
                     "allow / deny / ask strings become `rules` rows typed bash, powershell, mcp_tool, web_fetch or edit. "
                     "Bypass, auto and acceptEdits modes become findings. Home can move with `CLAUDE_CONFIG_DIR`.",
                     [C("components/claude/claude.py", 218, 252, "def discover_settings("),
                      C("components/claude/claude.py", 322, 360, "def extract_rules_from_settings("),
                      C("core/paths.py", 205, 207, "CLAUDE_CONFIG_DIR")]),
                ],
            },
            {
                "cat": "config",
                "loc": r"<repo>\.claude\settings.json, settings.local.json",
                "keeps": "Project-scoped permission rules committed to, or kept beside, a repository.",
                "reads": [
                    ("claude", "parsed",
                     "Found under the default repo roots (`%USERPROFILE%\\repos`, `code`, `src`, `projects`, `source`, `dev`, "
                     "`git`, `work`, `workspace`, `cursor-projects`, `Documents\\GitHub`, `Documents\\repos`) or `-RepoRoots`. "
                     "Rules are tagged `project_config`.",
                     [C("components/claude/claude.py", 190, 215, "def _repo_candidates("),
                      C("core/common.py", 30, 48, "DEFAULT_REPO_ROOT_NAMES")]),
                ],
            },
            {
                "cat": "config",
                "loc": r"%APPDATA%\Claude\claude_desktop_config.json",
                "keeps": "Claude desktop app MCP server registry.",
                "reads": [
                    ("claude", "parsed",
                     "Only `mcpServers` is used. Each server becomes an `mcp_tool` rule; a non-localhost URL is a high finding.",
                     [C("components/claude/claude.py", 516, 547, "mcpServers")]),
                ],
            },
            {
                "cat": "config",
                "loc": "Process environment, HKCU / HKLM Environment registry keys",
                "keeps": "OpenTelemetry export settings for Claude Code.",
                "reads": [
                    ("claude", "parsed",
                     "OTEL variable names and endpoint are summarised; header values are not. Registry is read only on Windows.",
                     [C("components/claude/claude.py", 103, 139, "def read_registry_env(")]),
                ],
            },
            {
                "cat": "sessions",
                "loc": r"%USERPROFILE%\.claude\projects\<project>\*.jsonl",
                "keeps": "Plaintext session transcripts used for resume (30 days by default per vendor docs).",
                "keeps_cites": [D("claude-data-usage")],
                "reads": [
                    ("claude", "metadata",
                     "Newest 5 files, first 50 lines each, for the Claude Code version string only.",
                     [C("components/claude/claude.py", 289, 316, "[:5]")]),
                    ("chat-history", "export",
                     "user / assistant lines rendered to `raw\\chat-history\\claude\\YYYY-MM-DD.md`; tool bodies included because "
                     "aiscan.ps1 passes `--include-tool-details`.",
                     [C("components/chat-history/chat-history.py", 273, 290, "def collect_claude("),
                      C("aiscan.ps1", 391, 394, "--include-tool-details")]),
                    ("pii-scan", "metadata",
                     "Scanned in place for card, SSN, IBAN, email, phone and public-IP patterns. Samples go to `raw\\pii-scan`.",
                     [C("components/pii-scan/pii-scan.py", 599, 612, "claude_projects")]),
                ],
            },
            {
                "cat": "sessions",
                "loc": r"%USERPROFILE%\.claude\history.jsonl",
                "keeps": "Global prompt history across projects.",
                "reads": [
                    ("claude", "stat", "Size only; reported as a retention finding.",
                     [C("components/claude/claude.py", 550, 568, "history.jsonl")]),
                ],
            },
            {
                "cat": "cache",
                "loc": r"%USERPROFILE%\.claude\file-history\, bash-audit.log",
                "keeps": "Pre-edit file snapshots; optional shell audit log.",
                "reads": [
                    ("claude", "stat", "File count and total size for snapshots; size only for the audit log. Never opened.",
                     [C("components/claude/claude.py", 571, 609, "file-history")]),
                ],
            },
            {
                "cat": "auth",
                "loc": r"%USERPROFILE%\.claude.json",
                "keeps": "Account profile (oauthAccount) and, for API-key users, a stored key.",
                "reads": [
                    ("accounts", "allowlist",
                     "`oauthAccount` email, organization and plan fields. `primaryApiKey` and settings `env` keys count as presence "
                     "and variable name only.",
                     [C("components/accounts/accounts.py", 610, 701, "oauthAccount")]),
                ],
            },
            {
                "cat": "auth",
                "loc": r"%USERPROFILE%\.claude\.credentials.json",
                "keeps": "Claude Code sign-in credentials.",
                "reads": [
                    ("accounts", "stat", "Presence only. Contents are never opened.",
                     [C("components/accounts/accounts.py", 612, 618, ".credentials.json")]),
                ],
            },
            {
                "cat": "remote",
                "loc": "Anthropic services",
                "keeps": "Prompts and outputs sent for inference; retention depends on account type. Cloud sessions run in "
                         "Anthropic-managed VMs and their transcripts are stored by Anthropic.",
                "keeps_cites": [D("claude-data-usage")],
                "reads": [
                    ("none", "notread", "No collector calls Anthropic. Server-side history and retention are invisible to the scan.",
                     [C("report/access_map.py", 44, 47, '("claude", "remote")')]),
                ],
            },
        ],
        "cannot": [
            ("Whether Claude Code ran anywhere other than this machine. The access map leaves the remote column unknown on purpose.",
             [C("report/access_map.py", 44, 47, '("claude", "remote")')]),
            ("Cloud sessions, Remote Control transcripts and anything retained on Anthropic servers.", [D("claude-data-usage")]),
            ("The `cleanupPeriodDays` retention setting: no collector source references it.", []),
            ("Full conversation content in evidence: it exists only in the local `raw\\chat-history\\claude` export.",
             [C("SCHEMA.md", 166, 169, "Chat transcript text NEVER appears in evidence/")]),
        ],
    },
    {
        "id": "claude-desktop",
        "name": "Claude desktop / Cowork",
        "short": "Claude desktop",
        "vendor": "Anthropic",
        "collectors": ["cowork", "claude", "chat-history"],
        "summary": (
            "`cowork` inventories Cowork session workspaces under `%APPDATA%\\Claude` by counting files and reading dates. "
            "It opens only `bridge-state.json`. Note the overlap: `chat-history` walks every `*.jsonl` under the same "
            "`%APPDATA%\\Claude` tree, so session JSONL with user/assistant lines there is exported to `raw/`."
        ),
        "rows": [
            {
                "cat": "sessions",
                "loc": "%APPDATA%\\Claude\\local-agent-mode-sessions\\<account>\\<org>\\local_*\\",
                "keeps": "One folder per Cowork session: transcripts, audit log, outputs and uploads.",
                "reads": [
                    ("cowork", "stat",
                     "Session count and dates; `*.jsonl` count; `audit.jsonl` presence; `outputs` / `uploads` file counts.",
                     [C("components/cowork/cowork.py", 72, 117, "def iter_session_dirs(")]),
                    ("chat-history", "export",
                     "`%APPDATA%\\Claude` is a second Claude root, walked with `rglob(\"*.jsonl\")`.",
                     [C("components/chat-history/chat-history.py", 312, 319, 'APPDATA / "Claude"'),
                      C("components/chat-history/chat-history.py", 273, 277, 'rglob("*.jsonl")')]),
                ],
            },
            {
                "cat": "sessions",
                "loc": r"%APPDATA%\Claude\claude-code-sessions\**\local_*.json",
                "keeps": "Session metadata files.",
                "reads": [("cowork", "stat", "Counted, not parsed.",
                           [C("components/cowork/cowork.py", 205, 209, "def scan_metadata(")])],
            },
            {
                "cat": "cache",
                "loc": r"%APPDATA%\Claude\cowork-file-preview\office-cache\*.pdf",
                "keeps": "Office document previews (older installs).",
                "reads": [("cowork", "stat", "Count and newest date. PDF bytes are not opened.",
                           [C("components/cowork/cowork.py", 130, 134, "office-cache")])],
            },
            {
                "cat": "remote",
                "loc": r"%APPDATA%\Claude\bridge-state.json",
                "keeps": "Local record of sessions bridged to the cloud.",
                "reads": [("cowork", "parsed", "Counts entries with `enabled`. The only Cowork file whose content is read.",
                           [C("components/cowork/cowork.py", 137, 144, "bridge-state.json")])],
            },
            {
                "cat": "cache",
                "loc": r"%APPDATA%\Claude\IndexedDB\https_claude.ai_0.indexeddb.leveldb, Local Storage\leveldb, design",
                "keeps": "claude.ai webview local state: draft composer state and attachment metadata, per the collector notes.",
                "keeps_cites": [C("components/cowork/cowork.py", 18, 23, "draft composer state")],
                "reads": [("cowork", "stat", "Existence and newest modified date of direct children only.",
                           [C("components/cowork/cowork.py", 168, 201, "WEBVIEW_MARKERS")])],
            },
            {
                "cat": "config",
                "loc": r"%APPDATA%\Claude\claude_desktop_config.json",
                "keeps": "Desktop MCP servers.",
                "reads": [("claude", "parsed", "Read by the Claude Code collector, even when no `.claude` home exists.",
                           [C("components/claude/claude.py", 516, 547, "mcpServers")])],
            },
        ],
        "cannot": [
            ("Cowork shell commands, secret stores, git pushes and approval mode: the envelope records none of them.",
             [C("report/access_map.py", 48, 59, '("cowork", "shell")')]),
            ("What a cloud-bridged session did remotely. The scan counts bridge entries locally and stops there.",
             [C("components/cowork/cowork.py", 295, 305, "cowork.bridge.remote_sync")]),
            ("Webview LevelDB contents, audit log contents, uploaded or generated files.",
             [C("components/cowork/cowork.py", 20, 26, "never their contents")]),
        ],
    },
    {
        "id": "cursor",
        "name": "Cursor IDE & CLI",
        "short": "Cursor",
        "vendor": "Anysphere (Cursor)",
        "collectors": ["cursor", "chat-history", "accounts", "pii-scan"],
        "summary": (
            "Three collectors touch Cursor's SQLite state database in three different ways. `cursor` opens it read-only "
            "for permission and MCP keys, `chat-history` opens it read-only to export Composer chats, and `accounts` "
            "copies it to a temp folder first and reads four identity keys from the copy."
        ),
        "rows": [
            {
                "cat": "cache",
                "loc": r"%APPDATA%\Cursor\User\globalStorage\state.vscdb",
                "keeps": "SQLite key/value state (ItemTable, cursorDiskKV): settings, MCP approvals, auth keys, Composer chats.",
                "reads": [
                    ("cursor", "parsed",
                     "Opened `mode=ro&immutable=1`. Targeted MCP / autorun keys plus an ItemTable allow-list scan that skips "
                     "auth, OAuth, secret and chat key prefixes.",
                     [C("components/cursor/cursor.py", 82, 85, "immutable=1"),
                      C("components/cursor/cursor_permissions.py", 30, 34, "SKIP_KEY_PREFIXES")]),
                    ("chat-history", "export",
                     "Composer headers, then each bubble's text, to `raw\\chat-history\\cursor-composer`.",
                     [C("components/chat-history/chat-history.py", 598, 610, "composer.composerHeaders")]),
                    ("accounts", "allowlist",
                     "Copied to a temp dir, then only `cursorAuth/cachedEmail`, membership, sign-up type and subscription status.",
                     [C("components/accounts/accounts.py", 548, 581, "copyfile")]),
                ],
            },
            {
                "cat": "config",
                "loc": r"%USERPROFILE%\.cursor\mcp.json, %APPDATA%\Cursor\mcp.json, %USERPROFILE%\.mcp.json, <repo>\.cursor\mcp.json",
                "keeps": "MCP server registrations, user and project scope.",
                "reads": [("cursor", "parsed",
                           "Servers become `mcp_tool` rules. Secret-looking env or args raise critical findings without copying the value.",
                           [C("components/cursor/cursor.py", 215, 275, "def collect_mcp_registrations("),
                            C("core/paths.py", 225, 227, "cursor_user_mcp")])],
            },
            {
                "cat": "config",
                "loc": r"%USERPROFILE%\.cursor\cli-config.json, <repo>\.cursor\cli.json",
                "keeps": "Cursor CLI approval mode, allow / deny tokens, sandbox settings.",
                "reads": [("cursor", "parsed", "Shell / Write / WebFetch / Mcp / Read tokens become rules; `CURSOR_CONFIG_DIR` is honoured.",
                           [C("components/cursor/cursor_permissions.py", 585, 618, "cli-config.json")])],
            },
            {
                "cat": "config",
                "loc": r"%USERPROFILE%\.cursor\permissions.json, sandbox.json, hooks.json (and <repo>\.cursor\ copies)",
                "keeps": "Auto-review instructions, sandbox policy, hook commands.",
                "reads": [("cursor", "parsed", "permissions.json contributes instruction counts only, never the instruction text.",
                           [C("components/cursor/cursor_permissions.py", 393, 398, "def _parse_permissions_json("),
                            C("components/cursor/cursor_permissions.py", 623, 641, "hooks.json")])],
            },
            {
                "cat": "sessions",
                "loc": r"%USERPROFILE%\.cursor\projects\<project>\agent-transcripts\<id>\<id>.jsonl",
                "keeps": "Agent conversation transcripts.",
                "reads": [
                    ("cursor", "metadata", "Each line parsed and keyword-matched to count permission events.",
                     [C("components/cursor/cursor.py", 471, 500, "def search_transcripts(")]),
                    ("chat-history", "export", "user / assistant messages to `raw\\chat-history\\cursor`.",
                     [C("components/chat-history/chat-history.py", 535, 575, "def collect_cursor_transcripts(")]),
                ],
            },
            {
                "cat": "config",
                "loc": r"%ProgramFiles%\Cursor\..\product.json, %LOCALAPPDATA%\Programs\cursor\..\product.json",
                "keeps": "Installed Cursor build metadata.",
                "reads": [("cursor", "parsed", "Version string and install scope only.",
                           [C("components/cursor/cursor_permissions.py", 535, 558, "def default_install_dirs(")])],
            },
            {
                "cat": "remote",
                "loc": "Cursor backend and model providers",
                "keeps": "Prompts and code context for LLM requests; Cloud Agent repository copies while running.",
                "keeps_cites": [D("cursor-privacy-governance")],
                "reads": [("none", "notread", "The offline `cursor` collector makes no network call. Cloud agents are a separate opt-in inventory.",
                           [C("report/access_map.py", 60, 62, '("cursor", "remote")')])],
            },
        ],
        "cannot": [
            ("Remote agents from the IDE envelope: the access map keeps Cursor's remote column unknown.",
             [C("report/access_map.py", 60, 62, '("cursor", "remote")')]),
            ("Auth tokens and chat rows in state.vscdb during the permission scan (skipped by prefix).",
             [C("components/cursor/cursor_permissions.py", 30, 34, "SKIP_KEY_PREFIXES")]),
            ("Team admin policy beyond the locally cached `adminSettings.cached` counts and booleans.",
             [C("components/cursor/cursor_permissions.py", 156, 178, "def read_admin_state(")]),
        ],
    },
    {
        "id": "cursor-cloud",
        "name": "Cursor Cloud Agents",
        "short": "Cloud Agents",
        "vendor": "Anysphere (Cursor)",
        "collectors": ["cloud-agents"],
        "optin": True,
        "summary": (
            "Not part of `aiscan all`. With a user-supplied `CURSOR_API_KEY`, `aiscan cloud-agents` sends HTTPS GET requests "
            "to `api.cursor.com` and records an inventory of agents. A request guard refuses any other method, host, port or path."
        ),
        "rows": [
            {
                "cat": "remote",
                "loc": "GET https://api.cursor.com /v1/me, /v1/agents, /v1/agents/{id}, …/runs/{runId}, …/usage",
                "keeps": "Cloud agent records: status, repositories, branches, PR URLs, runs, token usage.",
                "keeps_cites": [D("cursor-cloud-agent")],
                "reads": [("cloud-agents", "network",
                           "Names, repos, refs, branches, PR URLs, latest run status and token totals. `/v1/me` authenticates; "
                           "its email and name are not written.",
                           [C("components/cloud-agents/cloud-agents.py", 65, 71, "_PATH_RE"),
                            C("components/cloud-agents/cloud-agents.py", 131, 152, "def enforce_request(")])],
            },
            {
                "cat": "auth",
                "loc": "CURSOR_API_KEY environment variable",
                "keeps": "User API key created on the Cursor dashboard.",
                "reads": [("cloud-agents", "network", "Sent as a Bearer header to api.cursor.com; never printed or written to evidence.",
                           [C("components/cloud-agents/cloud-agents.py", 7, 9, "CURSOR_API_KEY")])],
            },
            {
                "cat": "sessions",
                "loc": "Cloud agent conversation state",
                "keeps": "Conversation state kept in Cursor's backend, indefinitely by default.",
                "keeps_cites": [D("cursor-cloud-security")],
                "reads": [("cloud-agents", "notread",
                           "Not collected. The inventory omits conversation transcripts by design.",
                           [C("components/cloud-agents/cloud-agents.py", 77, 84, "Full conversations are not collected")])],
            },
            {
                "cat": "sessions",
                "loc": "Cloud agent latest run result text",
                "keeps": "Latest run result text in the API payload, when present.",
                "reads": [("cloud-agents", "network",
                           "Collected only when `-IncludeRunResult` enables `--include-run-result`; omitted by default and redacted when redaction is on.",
                           [C("components/cloud-agents/cloud-agents.py", 513, 514, "if include_run_result and isinstance(run.get(\"result\"), str):"),
                            C("components/cloud-agents/cloud-agents.py", 779, 782, "--include-run-result"),
                            C("components/cloud-agents/cloud-agents.py", 79, 79, "Run result text is omitted unless --include-run-result")])],
            },
        ],
        "cannot": [
            ("Dollar cost, PR open/merged state, `/v1/repositories`, and the IDE session token.",
             [C("components/cloud-agents/cloud-agents.py", 77, 84, "LIMITS")]),
            ("VM snapshots, secrets configured for cloud agents, shell or tool use inside the VM.",
             [C("report/access_map.py", 94, 102, '("cloud-agents", "shell")'), D("cursor-cloud-security")]),
        ],
    },
    {
        "id": "codex",
        "name": "OpenAI Codex (CLI & desktop)",
        "short": "Codex",
        "vendor": "OpenAI",
        "collectors": ["codex", "chat-history", "accounts", "pii-scan"],
        "summary": (
            "`codex` reads durable posture from `config.toml`, profile files, rules, hooks, trusted-project layers, managed "
            "policy and desktop state, then mines session rollouts for approval events. Compressed `.jsonl.zst` rollouts "
            "need Python 3.14 or newer."
        ),
        "rows": [
            {
                "cat": "config",
                "loc": r"%USERPROFILE%\.codex\config.toml, *.config.toml",
                "keeps": "Sandbox mode, approval policy, trusted projects, MCP servers, apps, OTEL, hooks.",
                "keeps_cites": [D("codex-config-advanced")],
                "reads": [("codex", "parsed", "Durable posture findings and `user_config` rules. Home can move with `CODEX_HOME`.",
                           [C("components/codex/codex.py", 267, 291, "def parse_config_toml("),
                            C("components/codex/codex_permissions.py", 195, 200, "config.toml")])],
            },
            {
                "cat": "config",
                "loc": r"%USERPROFILE%\.codex\rules\*.rules, hooks.json, <repo>\.codex\ (trusted only)",
                "keeps": "Saved prefix and network rules; lifecycle hooks; project layers.",
                "reads": [("codex", "parsed",
                           "prefix_rule / network_rule calls become rules. Project layers are read only for projects marked trusted.",
                           [C("components/codex/codex_permissions.py", 205, 257, "*.rules"),
                            C("components/codex/codex_permissions.py", 290, 311, "trust_level")])],
            },
            {
                "cat": "config",
                "loc": r"%ProgramData%\OpenAI\Codex\requirements.toml, managed_config.toml",
                "keeps": "Administrator-managed requirements.",
                "reads": [("codex", "parsed", "Parsed when present.",
                           [C("components/codex/codex_permissions.py", 315, 341, "requirements.toml")])],
            },
            {
                "cat": "cache",
                "loc": r"%USERPROFILE%\.codex\.codex-global-state.json",
                "keeps": "Desktop app persisted state.",
                "reads": [("codex", "allowlist", "Permission, mode and thread policy fields only; thread ids and paths are excluded.",
                           [C("components/codex/codex_permissions.py", 343, 405, ".codex-global-state.json")])],
            },
            {
                "cat": "sessions",
                "loc": r"%USERPROFILE%\.codex\sessions\**\*.jsonl (and *.jsonl.zst)",
                "keeps": "Session rollouts: messages, tool calls, approvals.",
                "reads": [
                    ("codex", "metadata",
                     "function_call arguments (sandbox_permissions, prefix_rule, command) and structured approved-prefix arrays.",
                     [C("components/codex/codex.py", 114, 162, "def parse_approved_prefixes("),
                      C("core/compressed.py", 57, 69, "compression")]),
                    ("chat-history", "export", "user_message / agent_message events to `raw\\chat-history\\codex`.",
                     [C("components/chat-history/chat-history.py", 415, 458, "user_message")]),
                ],
            },
            {
                "cat": "sessions",
                "loc": r"%USERPROFILE%\.codex\history.jsonl",
                "keeps": "Local history file when history persistence is enabled.",
                "keeps_cites": [D("codex-config-advanced")],
                "reads": [("none", "notread", "No collector references this file; only `sessions\\` is read.", [])],
            },
            {
                "cat": "cache",
                "loc": r"%USERPROFILE%\.codex\session_index.jsonl, state_*.sqlite",
                "keeps": "Session index and state database.",
                "reads": [("codex", "stat", "Modified date only, for a last-used date.",
                           [C("components/codex/codex.py", 646, 653, "session_index.jsonl")])],
            },
            {
                "cat": "auth",
                "loc": r"%USERPROFILE%\.codex\auth.json",
                "keeps": "File-based credential storage (when not using the OS keyring).",
                "keeps_cites": [D("codex-config-advanced")],
                "reads": [
                    ("codex", "metadata", "Top-level key names only, to label the auth method.",
                     [C("components/codex/codex.py", 569, 582, "def detect_auth_method(")]),
                    ("accounts", "allowlist",
                     "The `id_token` JWT payload is decoded locally for email, plan and organization; token strings are not stored.",
                     [C("components/accounts/accounts.py", 704, 758, "id_token")]),
                ],
            },
            {
                "cat": "cache",
                "loc": r"%LOCALAPPDATA%\Packages\OpenAI.Codex_*\..\codex-desktop-*.log",
                "keeps": "Codex desktop app logs.",
                "reads": [("codex", "stat", "Presence and newest date; log contents never read. Windows only.",
                           [C("components/codex/codex.py", 524, 550, "def desktop_activity(")])],
            },
            {
                "cat": "remote",
                "loc": "Codex Cloud environments",
                "keeps": "Cloud tasks with their own workspace.",
                "keeps_cites": [D("codex-cloud")],
                "reads": [("none", "notread", "Not collected.", [C("report/access_map.py", 63, 65, '("codex", "remote")')])],
            },
        ],
        "cannot": [
            ("Codex Cloud tasks or any remote execution.", [C("report/access_map.py", 63, 65, '("codex", "remote")'), D("codex-cloud")]),
            ("Credentials held in the OS keyring: aiscan reads files and never decrypts credential stores.",
             [C("components/accounts/accounts.py", 12, 27, "decrypt")]),
            ("Compressed rollouts on Python older than 3.14: counted, not opened, and reported as a coverage gap.",
             [C("components/codex/codex.py", 776, 798, "compressed_not_scanned")]),
        ],
    },
    {
        "id": "vscode",
        "name": "VS Code + GitHub Copilot",
        "short": "VS Code",
        "vendor": "Microsoft / GitHub",
        "collectors": ["vscode", "chat-history", "accounts"],
        "summary": (
            "`vscode` replaced the older `copilot` collector. It reads Copilot and agent settings, extension names, workspace "
            "MCP files and chat-session metadata (no prompt text), and a minor JetBrains Copilot unit."
        ),
        "rows": [
            {
                "cat": "config",
                "loc": r"%APPDATA%\Code\User\settings.json, <repo>\.vscode\settings.json",
                "keeps": "Copilot enablement, excludes, agent mode, tool auto-approve, MCP and workspace trust.",
                "reads": [("vscode", "parsed", "Settings become rules and findings; `chat.tools*autoApprove*` true is high.",
                           [C("components/vscode/vscode.py", 193, 200, "def parse_vscode_settings("),
                            C("components/vscode/vscode.py", 368, 376, "vscode.copilot.tools.auto_approve")])],
            },
            {
                "cat": "config",
                "loc": r"<repo>\.vscode\mcp.json",
                "keeps": "Workspace MCP servers.",
                "reads": [("vscode", "parsed", "Server names hashed; non-localhost servers flagged.",
                           [C("components/vscode/vscode.py", 560, 598, "def parse_workspace_mcp(")])],
            },
            {
                "cat": "sessions",
                "loc": r"%APPDATA%\Code\User\workspaceStorage\<id>\chatSessions\*.jsonl",
                "keeps": "Per-workspace chat sessions (prompts, responses, settings).",
                "keeps_cites": [D("vscode-chat-sessions")],
                "reads": [
                    ("vscode", "metadata", "Request counts, modes, model families and permission levels. Workspace id hashed.",
                     [C("components/vscode/vscode.py", 452, 458, "Never returns prompt")]),
                    ("chat-history", "export", "User and response text to `raw\\chat-history\\copilot`.",
                     [C("components/chat-history/chat-history.py", 374, 412, "chatSessions")]),
                ],
            },
            {
                "cat": "auth",
                "loc": "%APPDATA%\\Code\\User\\globalStorage\\github.copilot\\, github.copilot-chat\\",
                "keeps": "Copilot extension state and token files.",
                "reads": [
                    ("vscode", "metadata", "Token file presence; small JSON files for a SKU label.",
                     [C("components/vscode/vscode.py", 126, 153, "def detect_sku(")]),
                    ("accounts", "allowlist", "Top-level JSON identity fields; files named token, secret or cookie are not opened.",
                     [C("components/accounts/accounts.py", 891, 955, "cookie")]),
                ],
            },
            {
                "cat": "cache",
                "loc": r"%APPDATA%\Code\logs\**\GitHub Copilot Chat.log",
                "keeps": "Copilot Chat extension logs.",
                "reads": [("vscode", "metadata", "Last 3 log windows scanned for a SKU line and a signed-in marker; no username kept.",
                           [C("components/vscode/vscode.py", 156, 187, "def sku_from_logs(")])],
            },
            {
                "cat": "config",
                "loc": r"%USERPROFILE%\.vscode\extensions\*",
                "keeps": "Installed extensions.",
                "reads": [("vscode", "stat", "Folder names matched against an AI-extension vocabulary.",
                           [C("components/vscode/vscode.py", 404, 446, "def inventory_extensions(")])],
            },
            {
                "cat": "config",
                "loc": r"%APPDATA%\JetBrains\*\options\github-copilot.xml",
                "keeps": "JetBrains Copilot plugin settings.",
                "reads": [("vscode", "parsed", "Enable flags only (minor unit).",
                           [C("components/vscode/vscode.py", 694, 718, "def parse_jetbrains_xml(")])],
            },
            {
                "cat": "remote",
                "loc": "GitHub account (session sync)",
                "keeps": "Optional, experimental upload of local session history to GitHub; off by default.",
                "keeps_cites": [D("vscode-session-history")],
                "reads": [("none", "notread", "Not collected. No collector source references `chat.sessionSync`.", [])],
            },
        ],
        "cannot": [
            ("File writes, secret stores and git pushes: not recorded by the VS Code envelope.",
             [C("report/access_map.py", 66, 74, '("vscode", "files")')]),
            ("Chats outside `workspaceStorage\\*\\chatSessions`, such as empty-window sessions or a separate local session database "
             "described in VS Code docs. No collector source references them.", [D("vscode-session-history")]),
            ("Anything synced to or stored by GitHub.", [D("vscode-session-history")]),
        ],
    },
    {
        "id": "grok-build",
        "name": "Grok Build (CLI)",
        "short": "Grok Build",
        "vendor": "xAI",
        "collectors": ["grok", "chat-history", "accounts", "pii-scan"],
        "summary": (
            "`grok` covers the Grok Build CLI home `%USERPROFILE%\\.grok` (not the Grok Bot desktop app). "
            "`permission_mode = \"always-approve\"` or `yolo = true` is the headline critical finding."
        ),
        "rows": [
            {
                "cat": "config",
                "loc": r"%USERPROFILE%\.grok\config.toml, <repo>\.grok\config.toml",
                "keeps": "Permission mode, MCP servers, permission allow lists, subagents, memory.",
                "reads": [("grok", "parsed", "Same `[mcp_servers.<name>]` shape as Codex. Home can move with `GROK_HOME`.",
                           [C("components/grok/grok.py", 116, 147, "always-approve"),
                            C("components/grok/grok.py", 516, 540, "def discover_project_configs(")])],
            },
            {
                "cat": "sessions",
                "loc": r"%USERPROFILE%\.grok\sessions\**\summary.json, signals.json, events.jsonl",
                "keeps": "Per-session summary, counters and event log.",
                "reads": [("grok", "metadata",
                           "Model id, message count, sandbox profile, tool-call counts and MCP event server names.",
                           [C("components/grok/grok.py", 335, 422, "def collect_session_inventory(")])],
            },
            {
                "cat": "sessions",
                "loc": r"%USERPROFILE%\.grok\sessions\**\chat_history.jsonl, updates.jsonl",
                "keeps": "Conversation transcript and streaming updates.",
                "reads": [
                    ("grok", "stat", "Size only; content is never read by this collector.",
                     [C("components/grok/grok.py", 388, 395, "chat_history.jsonl")]),
                    ("chat-history", "export", "chat_history.jsonl user / assistant lines to `raw\\chat-history\\grok`; updates and events are not opened.",
                     [C("components/chat-history/chat-history.py", 467, 479, "chat_history.jsonl")]),
                ],
            },
            {
                "cat": "cache",
                "loc": r"%USERPROFILE%\.grok\logs\unified.jsonl, logs\mcp\*",
                "keeps": "CLI and MCP logs.",
                "reads": [("grok", "stat", "Count and bytes only.",
                           [C("components/grok/grok.py", 491, 513, "def collect_log_metadata(")])],
            },
            {
                "cat": "auth",
                "loc": r"%USERPROFILE%\.grok\auth.json, user-settings.json",
                "keeps": "Sign-in state and user settings.",
                "reads": [
                    ("grok", "stat", "auth.json existence only.",
                     [C("components/grok/grok.py", 656, 667, "grok.auth.present_excluded")]),
                    ("accounts", "allowlist", "Allowlisted identity keys (email, username, org, plan, last sign-in).",
                     [C("components/accounts/accounts.py", 761, 847, "user-settings")]),
                ],
            },
            {
                "cat": "remote",
                "loc": "xAI services",
                "keeps": "Not verified from public docs for this atlas.",
                "reads": [("none", "notread", "Not collected.", [C("report/access_map.py", 75, 77, '("grok", "remote")')])],
            },
        ],
        "cannot": [
            ("Remote execution or server-side history.", [C("report/access_map.py", 75, 77, '("grok", "remote")')]),
            ("Prompt-history content (`prompt_history.jsonl` is an existence check only).",
             [C("components/grok/grok.py", 420, 422, "prompt_history.jsonl")]),
        ],
    },
    {
        "id": "grok-bot",
        "name": "Grok Bot (desktop)",
        "short": "Grok Bot",
        "vendor": "Cursor",
        "collectors": ["grok-bot", "accounts"],
        "summary": (
            "The weakest coverage by design. `grok-bot` only stats `%APPDATA%\\Grok Bot`: names, counts, bytes, newest date. "
            "It reports local execution as `unknown` (`not_determinable_offline`), not absent. The repository describes the "
            "app as Cursor's desktop assistant whose Bot work runs on a per-user cloud computer."
        ),
        "rows": [
            {
                "cat": "cache",
                "loc": r"%APPDATA%\Grok Bot\ (Local Storage, Session Storage, Network, Cache, sand-client-persistence, …)",
                "keeps": "Chromium-style app state and client persistence.",
                "reads": [("grok-bot", "stat", "Tree walk for file and folder counts, total bytes, newest date. Nothing is opened.",
                           [C("components/grok-bot/grok-bot.py", 119, 145, "def _walk_stats("),
                            C("components/grok-bot/grok-bot.py", 11, 14, "never opens")])],
            },
            {
                "cat": "auth",
                "loc": r"%APPDATA%\Grok Bot\sand-secrets.json, box-secrets-push-state.v1.json, lockfile",
                "keeps": "Secret store and lock files.",
                "reads": [("grok-bot", "stat", "Presence and size only.",
                           [C("components/grok-bot/grok-bot.py", 83, 87, "sand-secrets.json")])],
            },
            {
                "cat": "auth",
                "loc": r"%APPDATA%\Grok Bot\desktop-status.json, Preferences, Local State",
                "keeps": "Desktop status and browser-style preference files.",
                "reads": [("accounts", "allowlist", "Allowlisted identity keys only. Cookies and storage folders are not read.",
                           [C("components/accounts/accounts.py", 850, 888, "desktop-status.json")])],
            },
            {
                "cat": "remote",
                "loc": "Cursor cloud (per repository source comments)",
                "keeps": "Connector grants, Cloud Agent delegation, messaging, network policy, Auto-review.",
                "keeps_cites": [C("components/grok-bot/grok-bot.py", 16, 18, "Cloud controls stay out")],
                "reads": [("none", "notread", "Cloud controls stay out of this evidence on purpose.",
                           [C("components/grok-bot/grok-bot.py", 16, 18, "Cloud controls stay out")])],
            },
        ],
        "cannot": [
            ("Whether commands run on this machine: `local_execution` is always `unknown`.",
             [C("components/grok-bot/grok-bot.py", 97, 98, "not_determinable_offline")]),
            ("File writes, network or MCP grants, git, remote execution and approval mode.",
             [C("report/access_map.py", 78, 93, '("grok-bot", "files")')]),
            ("Remote storage of Grok Bot data: not verified from public docs for this atlas.", []),
        ],
    },
]


CROSS_CUTTING = [
    {
        "name": "accounts",
        "status": "all",
        "what": "Signed-in identity per tool: Claude Code, Codex, Cursor, Copilot, Grok CLI, Grok Bot, git, gh, plus MCP auth "
                "method and whether `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `XAI_API_KEY` or `CURSOR_API_KEY` is set.",
        "out": "evidence/accounts.json with an `accounts[]` array and fixed `limits` sentences. No raw/ output.",
        "safety": "No token, key, password or cookie values; no credential-store decryption; no network.",
        "cites": [C("components/accounts/accounts.py", 12, 27, "decrypt"),
                  C("components/accounts/accounts.py", 102, 107, "XAI_API_KEY"),
                  C("components/accounts/accounts.py", 1006, 1052, "hosts.yml")],
    },
    {
        "name": "chat-history",
        "status": "all",
        "what": "Exports Claude, Codex, Cursor, Cursor Composer, Grok and VS Code Copilot chats to dated Markdown.",
        "out": "raw/chat-history/<tool>/YYYY-MM-DD.md (local only) plus counts, sizes, retention and secret-hit findings in evidence.",
        "safety": "Evidence never carries transcript text. raw/ is never redacted, even with -Redact.",
        "cites": [C("components/chat-history/chat-history.py", 1, 8, "raw markdown"),
                  C("components/chat-history/chat-history.py", 764, 797, "chat_history.secret")],
    },
    {
        "name": "secrets-scan",
        "status": "all",
        "what": "Runs the first scanner found (Betterleaks, then gitleaks, then trufflehog) over raw/chat-history and repo roots.",
        "out": "raw/secrets-scan/findings.csv with file paths; grouped findings per rule in evidence with shortened samples.",
        "safety": "Validation forced off (`--validate=false --analyze=false`, trufflehog `--no-verification`) so found secrets are not sent anywhere.",
        "cites": [C("components/secrets-scan/secrets-scan.py", 96, 113, "BETTERLEAKS_PATH"),
                  C("components/secrets-scan/secrets-scan.py", 334, 351, "--validate=false"),
                  C("core/common.py", 718, 734, "def redact_sample(")],
    },
    {
        "name": "pii-scan",
        "status": "all",
        "what": "Stdlib detectors for Luhn-checked cards, SSNs, IBANs (mod-97), emails, phones and public IPs.",
        "out": "Grouped findings in evidence; raw/pii-scan/findings.csv capped at 25 samples per file and entity.",
        "safety": "Runs after chat-history in `all` so it scans this run's export. Files over 64 MiB are skipped and reported.",
        "cites": [C("components/pii-scan/pii-scan.py", 81, 93, "MAX_FILE_BYTES"),
                  C("aiscan.ps1", 332, 335, "pii-scan runs last")],
    },
    {
        "name": "git-posture",
        "status": "all",
        "what": "`.env` files added in history, missing pre-commit hooks, `.gitignore` secret patterns, blobs over 10 MiB, partial clones.",
        "out": "evidence/git-posture.json with findings and per-repo rules. No raw/ output.",
        "safety": "git runs with lazy fetch and credential prompts disabled. Branch protection via `gh api` needs `--allow-gh`, "
                  "which aiscan.ps1 never passes.",
        "cites": [C("components/git-posture/git-posture.py", 92, 124, "GIT_NO_LAZY_FETCH"),
                  C("components/git-posture/git-posture.py", 255, 280, "def check_branch_protection("),
                  C("aiscan.ps1", 395, 397, '"git-posture"')],
    },
    {
        "name": "telemetry",
        "status": "optin",
        "what": "Imports OTLP JSON / JSON-lines and Splunk JSON or CSV export files the operator already saved.",
        "out": "evidence/telemetry.json with approval and usage rollups; raw/telemetry-import/*.jsonl with redacted fields.",
        "safety": "Local files only, no Splunk call. Prompt text, tool parameters and secret-shaped attributes are dropped.",
        "cites": [C("components/telemetry-import/telemetry-import.py", 1, 17, "Splunk"),
                  C("components/telemetry-import/telemetry-import.py", 138, 168, "SENSITIVE_KEYS")],
    },
    {
        "name": "cloud-agents",
        "status": "optin",
        "what": "Cursor Cloud Agents inventory over the official API.",
        "out": "evidence/cloud-agents.json with `agents[]` and `limits`.",
        "safety": "GET only, host `api.cursor.com` only, fixed path allowlist, `/v1/repositories` refused, key never written.",
        "cites": [C("components/cloud-agents/cloud-agents.py", 131, 152, "def enforce_request("),
                  C("components/cloud-agents/component.json", 1, 9, "opt-in GET")],
    },
    {
        "name": "tools/mcp-visibility",
        "status": "tool",
        "what": "Cross-tool MCP server inventory with definition-drift and auth-posture notes.",
        "out": "JSON, table or summary to stdout. Outside the evidence contract.",
        "safety": "Prints real local paths by default; masks obvious credential values. Described in source as for local lab/testing use.",
        "cites": [C("tools/mcp-visibility/mcp_visibility.py", 3, 7, "outside the Phase 1 evidence pipeline"),
                  C("tools/mcp-visibility/README.md", 8, 10, "not wired into")],
    },
    {
        "name": "tools/github-access",
        "status": "tool",
        "what": "GitHub Apps installed on organizations you own, and SAML-authorized credentials.",
        "out": "Summary or JSON to stdout.",
        "safety": "Network: HTTPS GET to api.github.com with a token you already have. Cannot list personal installs or OAuth grants.",
        "cites": [C("README.md", 115, 115, "tools/github-access"),
                  C("aiscan.ps1", 328, 330, "GitHub access inventory")],
    },
]


INVENTORY = [
    # name, version cite, in_all, paths/repo roots, network, raw output
    ("claude", "1.4.0", C("components/claude/claude.py", 54, 54, "1.4.0"), "all", "paths, repo roots", "none", "—"),
    ("cowork", "1.2.0", C("components/cowork/cowork.py", 48, 48, "1.2.0"), "all", "own root", "none", "—"),
    ("cursor", "1.4.0", C("components/cursor/cursor.py", 38, 38, "1.4.0"), "all", "paths, repo roots", "none", "—"),
    ("codex", "1.4.0", C("components/codex/codex.py", 47, 47, "1.4.0"), "all", "paths", "none", "—"),
    ("vscode", "1.1.0", C("components/vscode/vscode.py", 47, 47, "1.1.0"), "all", "paths, repo roots", "none", "—"),
    ("chat-history", "1.3.0", C("components/chat-history/chat-history.py", 39, 39, "1.3.0"), "all", "paths", "none", "raw/chat-history/"),
    ("git-posture", "1.1.0", C("components/git-posture/git-posture.py", 38, 38, "1.1.0"), "all", "repo roots", "none via aiscan.ps1 (gh only with --allow-gh)", "—"),
    ("secrets-scan", "1.1.0", C("components/secrets-scan/secrets-scan.py", 52, 52, "1.1.0"), "all", "repo roots, raw/", "none (validation forced off)", "raw/secrets-scan/"),
    ("grok", "1.3.0", C("components/grok/grok.py", 41, 41, "1.3.0"), "all", "paths, repo roots", "none", "—"),
    ("grok-bot", "1.1.0", C("components/grok-bot/grok-bot.py", 39, 39, "1.1.0"), "all", "own root", "none", "—"),
    ("pii-scan", "1.3.1", C("components/pii-scan/pii-scan.py", 72, 72, "1.3.1"), "all", "paths, raw/", "none", "raw/pii-scan/"),
    ("accounts", "1.0.0", C("components/accounts/accounts.py", 63, 63, "1.0.0"), "all", "paths, repo roots", "none", "—"),
    ("cloud-agents", "1.0.0", C("components/cloud-agents/cloud-agents.py", 46, 46, "1.0.0"), "optin", "none", "GET api.cursor.com", "—"),
    ("telemetry", "1.1.0", C("components/telemetry-import/telemetry-import.py", 114, 114, "1.1.0"), "optin", "export files", "none", "raw/telemetry-import/"),
]


PIPELINE = [
    {
        "id": "launch",
        "label": "Launch",
        "short": "aiscan.ps1",
        "what": "One PowerShell entry point. `all` (the default) runs twelve offline collectors in a fixed order. "
                "`cloud-agents` and `telemetry` are separate commands; `discover` and `summary` are modes.",
        "inputs": "Command name and flags: -OutDir / -Here, -Briefing, -Redact, -RepoRoots, -AgentMode, -LaunchedBy, -Reason.",
        "outputs": "A scan root with `evidence\\` and `raw\\`, plus `run-origin.txt`. Without -OutDir or -Here the root is "
                   "`%TEMP%\\aiscan-<stamp>-<nonce>`, deleted at the end unless -Keep or -Briefing is set.",
        "adapt": "The component.json `in_all` flags agree with the list, but aiscan.ps1 does not read them: the order is hard-coded.",
        "cites": [C("aiscan.ps1", 191, 194, "ValidateSet"),
                  C("aiscan.ps1", 332, 335, "$StdlibOrder"),
                  C("aiscan.ps1", 657, 671, "aiscan-$stamp-$nonce"),
                  C("aiscan.ps1", 694, 696, "Remove-Item -LiteralPath $Root")],
    },
    {
        "id": "resolve",
        "label": "Resolve paths",
        "short": "core/paths.py",
        "what": "Each tool home is resolved once with precedence CLI flag > paths.json > tool env var > default, and passed "
                "to collectors as flags.",
        "inputs": "`CLAUDE_CONFIG_DIR`, `CODEX_HOME`, `GROK_HOME`, optional `paths.json`; defaults under %USERPROFILE% and %APPDATA%.",
        "outputs": "Process arguments only. Evidence stores a hashed `path_id` and a source label, never the resolved path.",
        "adapt": "`discover` prints what would be scanned without reading content.",
        "cites": [C("core/paths.py", 9, 20, "Precedence per override unit"),
                  C("core/paths.py", 154, 167, "def _default_for("),
                  C("core/paths.py", 329, 343, "def safe_path_meta(")],
    },
    {
        "id": "collect",
        "label": "Collect",
        "short": "components/*",
        "what": "Each collector reads its tool's files read-only and decides findings and rules itself. Severity is assigned here, "
                "not in a later analysis stage.",
        "inputs": "Harness config, session stores, SQLite state (read-only, or a temp copy for accounts), repos.",
        "outputs": "One envelope per collector; chat-history, secrets-scan and pii-scan also write `raw\\`.",
        "adapt": "This is where 'analysis' mostly happens: collectors are both readers and rule engines.",
        "cites": [C("components/cursor/cursor.py", 82, 85, "immutable=1"),
                  C("components/accounts/accounts.py", 560, 563, "copyfile")],
    },
    {
        "id": "normalize",
        "label": "Normalize",
        "short": "core/common.py",
        "what": "Shared helpers build the envelope (`make_envelope`), findings (`make_finding`) and permission rules (`make_rule`), "
                "merge duplicate findings and write `evidence\\<collector>.json` atomically.",
        "inputs": "Collector results.",
        "outputs": "Envelope: collector, version, aiscan_version, ran_at, host, platform_detected, scope_hash, summary, findings, rules, raw_pointers.",
        "adapt": "Every string passes `sanitize_text`, which is a no-op unless `AISCAN_REDACT` is set.",
        "cites": [C("core/common.py", 314, 334, "def make_envelope("),
                  C("core/common.py", 459, 528, "def make_finding("),
                  C("core/common.py", 262, 266, "def sanitize_text("),
                  C("core/common.py", 337, 353, "def write_evidence(")],
    },
    {
        "id": "store",
        "label": "Store",
        "short": "evidence/ vs raw/",
        "what": "Two layers. `evidence\\` holds structured envelopes; `raw\\` holds transcript exports and scanner CSVs that "
                "never leave the machine.",
        "inputs": "Envelopes and raw exports.",
        "outputs": "See the output tree below.",
        "adapt": "`raw_pointers` and `raw_evidence_ref` link evidence to raw files and must be dropped before sharing.",
        "cites": [C("SCHEMA.md", 152, 169, "raw_pointers` is dropped entirely")],
    },
    {
        "id": "derive",
        "label": "Derive",
        "short": "agent-summary, scan_diff, access map",
        "what": "Derived steps read envelopes only, never the machine. `agent_summary.py` writes a safe summary every scan; "
                "`run_status.py` turns exit codes into the scan exit code; with -Briefing, `scan_diff.py` writes `changes.json` "
                "against a previous scan; the access map is computed while the briefing renders.",
        "inputs": "evidence\\*.json, run-origin.txt.",
        "outputs": "agent-summary.json, run-status.json, changes.json (with -Briefing).",
        "adapt": "The access map is pure: it never touches the filesystem and leaves uncaptured cells unknown.",
        "cites": [C("core/agent_summary.py", 235, 242, "coverage_caveats"),
                  C("aiscan.ps1", 1068, 1075, "Invoke-ScanDiff"),
                  C("report/access_map.py", 1, 11, "does not read the filesystem")],
    },
    {
        "id": "brief",
        "label": "Brief",
        "short": "report/build-briefing.py",
        "what": "Builds one self-contained HTML file: a summary, then tabs for findings, access map, changes, agents/collectors, "
                "approvals, usage and coverage gaps.",
        "inputs": "Collector envelopes (derived files skipped), changes.json, run-origin.txt.",
        "outputs": "`briefing\\briefing.html` (or `briefing-local.html` with local links).",
        "adapt": "Only with -Briefing. Refuses envelopes whose schema major version is not 1.",
        "cites": [C("report/build-briefing.py", 3782, 3790, "_PAGE_TABS"),
                  C("report/build-briefing.py", 723, 760, "def load_evidence("),
                  C("aiscan.ps1", 743, 744, "briefing.html")],
    },
]


OUTPUT_TREE = [
    ("<scan-root>\\", "dir", "-OutDir, -Here, or a %TEMP% folder deleted at the end unless kept", None),
    ("  run-origin.txt", "safe", "launched_by | started | reason, masked even without -Redact", C("core/run_origin.py", 8, 17, "-LaunchedBy")),
    ("  evidence\\", "dir", "structured layer", None),
    ("    <collector>.json", "review", "one envelope per collector; unredacted by default", C("core/common.py", 337, 353, "def write_evidence(")),
    ("    agent-summary.json", "safe", "severity, title, category, counts; titles always masked", C("core/agent_summary.py", 475, 483, "mask_secrets")),
    ("    run-status.json", "safe", "collector exit codes", C("core/run_status.py", 1, 16, "Exit code for one aiscan.ps1 run")),
    ("    changes.json", "review", "only with -Briefing; diff against the previous scan", C("core/scan_diff.py", 10, 19, "--previous")),
    ("  raw\\", "local", "LOCAL ONLY. Never redacted.", C("aiscan.ps1", 685, 688, "raw\\ is NOT redacted")),
    ("    chat-history\\<tool>\\YYYY-MM-DD.md", "local", "full transcript text", C("components/chat-history/chat-history.py", 7, 8, "YYYY-MM-DD.md")),
    ("    secrets-scan\\findings.csv, summary.md", "local", "file, line, rule, sample", C("components/secrets-scan/secrets-scan.py", 507, 541, "findings.csv")),
    ("    pii-scan\\findings.csv, summary.md", "local", "capped samples", C("components/pii-scan/pii-scan.py", 36, 38, "findings.csv")),
    ("  briefing\\briefing.html", "review", "only with -Briefing", C("aiscan.ps1", 743, 744, "briefing.html")),
]


ENVELOPE_FIELDS = [
    ("collector", "yes", "Collector name, e.g. `claude`."),
    ("version", "yes", "Collector schema version (semver). The briefing refuses a major other than 1."),
    ("aiscan_version", "yes", "Release or `git describe` string of the aiscan that wrote the file."),
    ("ran_at", "yes", "ISO 8601 time with offset."),
    ("host", "yes", "Short hostname. Kept even with -Redact; SCHEMA.md lists it as known residue."),
    ("platform_detected", "yes", "Whether the tool was found. 'Not detected' is a normal result."),
    ("scope_hash", "yes", "SHA-256 of the sorted list of scanned paths: proves coverage without listing paths."),
    ("summary", "yes", "Numbers and short controlled-vocabulary labels only."),
    ("findings", "after redaction", "id, severity, category, title, evidence_count, first/last seen, sample_redacted, secret_redacted, tags."),
    ("rules", "after redaction", "platform, scope, scope_label_redacted, rule_type, rule, decision allow|deny|ask, risk, source_kind, confidence."),
    ("raw_pointers", "never", "Local paths into raw/ with sha256. Dropped before anything is shared."),
]

ENVELOPE_CITES = [C("SCHEMA.md", 17, 46, "Top-level shape"), C("SCHEMA.md", 196, 203, "host"), C("core/common.py", 314, 334, "def make_envelope(")]


REDACTION = [
    # item, default, with -Redact, cites
    ("Finding samples and rule text", "Original text. Can include paths, usernames and secret-shaped strings.",
     "Profile paths become `<userprofile>` / `<user>`, other paths `<path#hash>`, secrets masked.",
     [C("core/common.py", 251, 266, "def redaction_disabled("), C("core/common.py", 181, 248, "<userprofile>")]),
    ("Workspace / project labels", "`<scope>:<last folder name>`; can be a project or user name.", "`<scope>#<short hash>`.",
     [C("SCHEMA.md", 97, 102, "scope_label_redacted")]),
    ("accounts[] identifiers", "Real email, username, organization, plan.", "Emails replaced with `<email>`.",
     [C("SCHEMA.md", 364, 364, "<email>")]),
    ("Briefing HTML", "Shows samples unredacted.", "Built from redacted evidence; local file links turned off.",
     [C("report/build-briefing.py", 2066, 2073, "-Redact turns off -LocalLinks")]),
    ("raw/ folder", "Full transcript text, scanner CSVs with file paths.", "Unchanged. -Redact never cleans raw/.",
     [C("aiscan.ps1", 685, 688, "raw\\ is NOT redacted")]),
    ("secrets-scan evidence samples", "Always shortened: short values fully masked, longer ones keep a small head and tail.",
     "Shortened, then masked.", [C("core/common.py", 718, 734, "def redact_sample(")]),
    ("agent-summary.json", "Titles and categories always masked for paths and secrets.", "Same.",
     [C("core/agent_summary.py", 475, 483, "mask_secrets")]),
    ("run-origin.txt", "Masked, control characters removed, 120-character cap.", "Same.",
     [C("core/run_origin.py", 12, 17, "capped")]),
    ("discovery / history_roots", "Hashed `path_id` plus a source label; no paths.", "Same.",
     [C("core/paths.py", 329, 343, "path_id")]),
    ("Envelope host field", "Short hostname.", "Still the short hostname.", [C("SCHEMA.md", 200, 203, "host")]),
]

GUARANTEES = [
    ("Read-only SQLite", "Cursor's state.vscdb is opened with `mode=ro&immutable=1`; `accounts` reads a temp copy instead.",
     [C("components/cursor/cursor.py", 82, 85, "immutable=1"), C("components/accounts/accounts.py", 560, 563, "copyfile")]),
    ("No secret validation", "Betterleaks validation and analysis are forced off and their environment overrides stripped.",
     [C("components/secrets-scan/secrets-scan.py", 57, 72, "BETTERLEAKS_VALIDATE")]),
    ("No lazy git fetch", "git runs with `GIT_NO_LAZY_FETCH=1`, `GIT_TERMINAL_PROMPT=0` and an empty askpass.",
     [C("components/git-posture/git-posture.py", 92, 124, "GIT_TERMINAL_PROMPT")]),
    ("Request guard", "cloud-agents refuses non-GET, non-HTTPS, other hosts, ports, userinfo and unknown paths, and re-checks redirects.",
     [C("components/cloud-agents/cloud-agents.py", 131, 152, "def enforce_request(")]),
    ("Atomic evidence writes", "Envelopes are written to a temp file and renamed into place.",
     [C("core/common.py", 337, 353, "mkstemp")]),
    ("Bounded parsing", "Config files capped at 8 MiB; decompression and PII scanning capped at 64 MiB and 30 seconds.",
     [C("core/configfmt.py", 25, 26, "MAX_CONFIG_BYTES"), C("core/compressed.py", 28, 33, "MAX_DECOMPRESSED_BYTES")]),
]


PLATFORM_NOTES = [
    ("Windows only", "Path resolution is Windows-first; macOS and Linux are not supported yet.", [C("README.md", 153, 154, "macOS/Linux are not supported yet")]),
    ("Python 3.11+", "aiscan.ps1 stops when `python` is missing or older than 3.11 (tomllib).", [C("aiscan.ps1", 271, 303, "3.11")]),
    ("Python 3.14+ for .jsonl.zst", "Compressed Codex rollouts need stdlib `compression.zstd`; older Pythons count them and report a gap.",
     [C("core/compressed.py", 57, 69, "compression")]),
    ("Registry", "Claude OTEL settings are also read from the Windows registry when `winreg` exists.", [C("components/claude/claude.py", 130, 139, "winreg")]),
    ("Codex desktop", "Desktop presence needs win32 and %LOCALAPPDATA%.", [C("components/codex/codex.py", 534, 537, "win32")]),
    ("Secret scanner binary", "secrets-scan needs Betterleaks, gitleaks or trufflehog; without one it reports a medium coverage finding.",
     [C("components/secrets-scan/secrets-scan.py", 675, 683, "secrets-scan.tool_unavailable")]),
    ("JetBrains", "Copilot for JetBrains is a minor unit inside vscode.", [C("components/vscode/vscode.py", 691, 694, "JetBrains")]),
]


LIMITATIONS = [
    "Source facts are pinned to one commit. A later commit can change any path, mode or default shown here; re-run "
    "`python docs/atlas/build_atlas.py --verify` after rebasing.",
    "'What the harness keeps' is drawn from aiscan's own code comments and from the public vendor pages listed in the manifest, "
    "read on the date shown. Vendors change storage layouts and retention without notice.",
    "Grok Build and Grok Bot remote storage were not verified from public documentation. Grok Bot statements come from repository source comments.",
    "'Not read' means no collector source in this commit references the location. It is a statement about aiscan, not proof that the location exists on every install.",
    "The overlap where chat-history exports JSONL from the whole %APPDATA%\\Claude tree is read from the code path, not observed on a machine.",
    "No real machine was scanned to make this page. Example paths are generic placeholders.",
    "This page explains coverage; it is not a security assessment of any vendor.",
]
