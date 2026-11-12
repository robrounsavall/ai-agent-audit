# Claude Code collector

Inventories Claude Code permission settings, MCP servers, and bypass modes from `~/.claude`, from `<repo>/.claude/settings.json` and `settings.local.json`, and from the Claude Desktop MCP config (even when Claude Code itself is not installed).

| | |
|---|---|
| Evidence | `evidence/claude.json` |
| In `aiscan all` | yes |
| Deps | stdlib only |

## Test

```powershell
.\scripts\test-component.ps1 -Name claude
.\aiscan.ps1 claude
```

## WSL

Claude Code run inside WSL keeps its own `~/.claude` under the Linux home, so
the collector also reads every `/home/<user>/.claude` in WSL distros that are
already running (`wsl.exe --list --running`, read over `\\wsl.localhost`). A
stopped distro is not started. For each one it reads user `settings.json` and
`settings.local.json` (rules get scope label `wsl:<distro>`), the same
side-artifact checks as Windows, and the implicit auto-mode default. Findings
that also exist on Windows are merged into one finding with a
`wsl:<distro>:` note. The summary gains `wsl_homes` (per distro: sessions,
last activity, permission mode, Claude Code version, settings files, rules),
`wsl_sessions` and `wsl_last_activity`. The Linux username and home path are
not written to evidence. Set `AISCAN_WSL=0` to skip WSL.

## Permission mode findings

The start mode is read from `permissions.defaultMode` (legacy top-level `defaultMode` / `permissionMode` still accepted).

| Finding id | Severity | Meaning |
|---|---|---|
| `claude.permission.bypass_mode` | critical | `bypassPermissions` in user settings |
| `claude.permission.auto_mode` | medium | `auto` in user settings |
| `claude.permission.auto_mode_default` | medium | No mode set; Claude Code 2.1.283+ starts in `auto` (older versions: Pro/Max/Team plans) |
| `claude.permission.accept_edits_mode` | low | `acceptEdits` auto-accepts file edits |
| `claude.permission.mode_not_applied` | low | `auto`/`bypassPermissions` set in project or `settings.local.json` (ignored by Claude Code 2.1.257+), or disabled via `disableAutoMode` / `disableBypassPermissionsMode` |

The summary adds `permission_mode`, `permission_mode_source`, `claude_code_version` (from transcripts), `auto_mode_disabled` and `bypass_mode_disabled`.
