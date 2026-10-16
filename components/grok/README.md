# Grok Build collector

Inventories Grok Build permission mode, MCP servers, and session metadata from `~/.grok`.

This is not Cursor's Grok Bot desktop app. That client is
[components/grok-bot](../grok-bot/README.md). This collector still only
records that `auth.json` exists. The `accounts` collector reads allowlisted
identity fields from that file and from user-settings, and does not store
token values.

| | |
|---|---|
| Evidence | `evidence/grok.json` |
| In `aiscan all` | yes |
| Deps | stdlib only (`tomllib`) |

## Test

```powershell
.\scripts\test-component.ps1 -Name grok
.\aiscan.ps1 grok
```