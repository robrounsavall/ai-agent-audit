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
- Workspace-scoped `.vscode/settings.json` and `.vscode/mcp.json` under
  `--repo-roots` (hashed repo identity; non-localhost MCP servers flagged).
- JetBrains Copilot config (minor unit).

```
python vscode.py --evidence-root ./audit-run [--vscode-root DIR] [--repo-roots a,b] [--dry-run]
```

Findings: `vscode.copilot.tools.auto_approve` (high),
`vscode.copilot.permission_level_relaxed`, `vscode.mcp.non_local_server`,
`vscode.workspace_trust.disabled`, `vscode.ai_extension.present`,
`vscode.copilot.agent.max_requests_raised`, plus the three v1-lineage Copilot
findings.
