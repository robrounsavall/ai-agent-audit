# vscode

VS Code surface collector. Replaces the retired `copilot` component (v1.0.0);
evidence key is now `vscode` and finding ids moved from `copilot.*` to
`vscode.*` (with a `vscode.copilot.*` subspace).

VS Code is audited as a surface hosting AI harnesses, not as a single tool:

- Copilot settings (enable state, per-language overrides, exclusion patterns,
  public-code suggestions, telemetry) — v1 lineage.
- Copilot SKU/auth from both `globalStorage` dirs (`github.copilot` AND
  `github.copilot-chat`; v1 only probed the former and reported `unknown` on
  free/limited seats) plus the Copilot Chat log channel SKU line.
- Agent-mode posture: `chat.agent.*`, every `chat.tools*autoApprove*` variant
  (HIGH finding + approval rules), `chat.mcp.*`, workspace trust.
- Installed AI extension inventory (`~/.vscode/extensions` + built-in Copilot),
  so additional harnesses (Cline, Continue, ...) surface instead of staying
  blind spots.
- Chat-session inventory from `workspaceStorage/*/chatSessions/*.jsonl`:
  metadata only — counts, modes, model families, permission levels. Prompt
  text and account labels are never read into evidence; workspace identity is
  hashed.
- Empty-window chats from `globalStorage/emptyWindowChatSessions/*.jsonl`
  (same metadata-only parsing; counted as `chat_empty_window_sessions`).
- Agent host (VS Code's Agents view, which runs Copilot CLI and other agents):
  `globalStorage/agent-host-config.json` for standing `permissions`
  allow/ask/deny rules, global auto-approve, edit auto-approve patterns,
  terminal sandbox (on/off, network, unsandboxed escape, git/gh auth),
  computer use, hosted MCP (GitHub MCP server, MCP connectors), agent merge
  and workspace trust; `globalStorage/agent-host.db` (read-only) for session
  counts per provider, chat count, deleted sessions and the newest activity
  date. Trusted folder paths, shell paths, titles and free-text instructions
  are counted, never copied.
- `last_activity`: newest of chat-session file dates and agent-host session
  times. The briefing uses it for "Last used". A settings.json edit does not
  count as use.
- Workspace-scoped `.vscode/settings.json` and `.vscode/mcp.json` under
  `--repo-roots` (hashed repo identity; non-localhost MCP servers flagged).
- JetBrains Copilot config (minor unit).

```
python vscode.py --evidence-root ./audit-run [--vscode-root DIR] [--repo-roots a,b] [--dry-run]
```

SKU and plan values are a fixed vocabulary (`free`, `individual`,
`individual_or_business`, `business`, `enterprise`, `signed_in`, `unknown`).
An organization login is reported as `business` and the login string is not
copied. A settings file that cannot be parsed is `vscode.config.parse_error`
and is not treated as an empty config.

Findings: `vscode.copilot.tools.auto_approve` (high),
`vscode.copilot.permission_level_relaxed`, `vscode.mcp.non_local_server`,
`vscode.workspace_trust.disabled`, `vscode.ai_extension.present`,
`vscode.copilot.agent.max_requests_raised`, `vscode.config.parse_error`,
`vscode.agent_host.global_auto_approve` (high), `vscode.agent_host.sandbox_off`,
`vscode.agent_host.unsandboxed_commands`, `vscode.agent_host.computer_use`,
`vscode.agent_host.agent_merge` (medium), `vscode.agent_host.allow_rules`,
`vscode.agent_host.edit_auto_approve`, `vscode.agent_host.remote_mcp` (low),
plus the v1-lineage Copilot findings (`vscode.copilot.exclude.none_configured`,
`vscode.copilot.public_code.enabled`, `vscode.copilot.telemetry.enabled`).
