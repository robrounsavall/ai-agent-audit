# Grok Bot collector

Inventories the **Grok Bot** desktop app on a Windows endpoint. Grok Bot is
Cursor's desktop and mobile assistant. It is not [Grok Build](../grok/README.md)
(`~/.grok`, evidence `grok.json`).

| | |
|---|---|
| What it is | Named Bots reached from the Grok Bot desktop app (and iOS). Bot work runs on a per-user cloud computer with a browser, filesystem, and terminal. |
| Where it runs | Desktop app on this machine for chat, review, and approvals. Execution is on Cursor-hosted cloud computers. Optional local execution can also run commands on this machine. |
| Evidence | `evidence/grok-bot.json` |
| Reads | `%APPDATA%\Grok Bot` presence, sizes, counts, and mtimes only. Top-level names match a real install (`sand-secrets.json`, `lockfile`, `Local Storage`, `Network`, `sand-client-persistence`, and the other Chromium/`sand-*` entries). |
| In `aiscan all` | yes |
| Deps | stdlib only |

No file under that directory is opened. `sand-secrets.json`,
`box-secrets-push-state.v1.json`, `gateway-descriptor.json`, `desktop-status.json`,
`Preferences`, `Local Storage`, `Session Storage`, `Network`, and
`sand-client-persistence` contribute presence, size, or mtime only.

## What a hit means

- `grok_bot.desktop.present` — the desktop client has local app data. The sample carries the file count and the newest mtime in the tree.
- `grok_bot.secrets.store_present` — `sand-secrets.json` and/or `box-secrets-push-state.v1.json` exist. Contents stay unread.
- `grok_bot.lockfile.present` — `lockfile` exists, so the app is running or ran recently.
- `grok_bot.state.local_stores_present` — `Local Storage`, `Session Storage`, `Network`, and/or `sand-client-persistence` exist. Contents stay unread.

`summary.local_execution` is `unknown` and `local_execution_reason` is
`not_determinable_offline`. A real install does not leave a file whose name
shows whether local execution is on. This collector does not treat a missing
path as "local execution is off."

## Control points this scan does not collect

| Control | Why it is not in the evidence |
|---|---|
| Execution on Local Computer (ask / always / never), including the team ceiling | Not visible from the AppData names on a real install. The policy lives in the app and on the Cursor dashboard. |
| `desktop-status.json` and `Preferences` contents | Present on disk. Not parsed. A follow-up could read them only after the on-disk schema is confirmed. |
| Connector / plugin grants | Cursor dashboard Plugins & MCPs. Tokens stay on Cursor's backend. |
| Cloud Agent delegation | Grok Bot page of the Cursor dashboard |
| Outbound messaging, routines, Slack account links | Cursor audit logs / Action Recording, not this disk |
| Files and browser sessions on the shared cloud computer | The member's hosted computer, not `%APPDATA%` |

## Test

```powershell
.\scripts\test-component.ps1 -Name grok-bot
.\aiscan.ps1 grok-bot
```
