# Claude Code collector

Inventories Claude Code permission settings, MCP servers, and bypass modes from `~/.claude`.

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
