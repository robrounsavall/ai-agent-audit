# Grok Bot collector

Inventories the **Grok Bot** desktop app on a Windows endpoint. Grok Bot is
Cursor's desktop and mobile assistant. It is not [Grok Build](../grok/README.md)
(`~/.grok`, evidence `grok.json`).

| | |
|---|---|
| What it is | Named Bots reached from the Grok Bot desktop app (and iOS). Bot work runs on a per-user cloud computer with a browser, filesystem, and terminal. |
| Where it runs | Desktop app on this machine for chat, review, and approvals. Execution is on Cursor-hosted cloud computers. Optional local execution can also run commands on this machine. |
| Evidence | `evidence/grok-bot.json` |
| Reads | `%APPDATA%\Grok Bot` presence only: `settings.json`, `local-exec-daemon.log` (size), `local-exec-daemon-credential.json`, `local-exec-daemon-connection.json`, `local-exec-daemon/` |
| In `aiscan all` | yes |
| Deps | stdlib only |

Settings, credential, connection, and log **contents are never opened**. A
credential file contributes presence only, same as other collectors'
`auth.json` handling.

## What a hit means

- `grok_bot.desktop.present` — the desktop client has local app data.
- `grok_bot.local_exec.capability_present` — the local-execution channel has
  artifacts, so a Bot can be granted commands and file moves on this machine.
  The member policy is ask every time, always allow, or never. This collector
  does not read which one is set.
- `grok_bot.local_exec.credential_present` — the local-exec credential file
  exists. Contents stay unread.

## Control points this scan does not collect

These are real Grok Bot controls, and they are cloud-side. An offline
endpoint scanner has no local schema for them, so they are left out on
purpose rather than guessed:

| Control | Where it actually lives |
|---|---|
| Execution on Local Computer policy (ask / always / never), including the team ceiling | Grok Bot settings on this desktop, and the Grok Bot page of the Cursor dashboard |
| Connector / plugin grants (team Cursor MCP policy; no separate Grok Bot connector list) | Cursor dashboard Plugins & MCPs. Tokens stay on Cursor's backend |
| Cloud Agent delegation (on by default; admins can disable spawning) | Grok Bot page of the Cursor dashboard |
| Outbound messaging, routines, Slack account links | Cursor audit logs / Action Recording (Enterprise), not this disk |
| Auto-review and network policy | Dashboard. Personal Auto-review rules are described as stored on the desktop, but the file format is not published, so `settings.json` is not parsed |
| Files, browser sessions, and logins on the shared cloud computer | The member's hosted computer, not `%APPDATA%` |

GitHub access, when a member has it, is a connector grant under that MCP
policy. It is not a local `mcp.json` this repo already knows how to parse, so
`tools/mcp-visibility` does not inventory it either.

## Test

```powershell
.\scripts\test-component.ps1 -Name grok-bot
.\aiscan.ps1 grok-bot
```
