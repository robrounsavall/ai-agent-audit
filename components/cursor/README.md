# Cursor collector

Inventories Cursor permission posture and local project/transcript signals from Cursor state and projects dirs.

| | |
|---|---|
| Evidence | `evidence/cursor.json` |
| In `aiscan all` | yes |
| Deps | stdlib only |

## Permission sources (Cursor 3.2x)

- `cli-config.json` (`$CURSOR_CONFIG_DIR` or `~/.cursor`) and project `.cursor/cli.json`: `approvalMode`, `permissions.allow/deny` tokens, `sandbox.*`.
- `state.vscdb` `applicationUser` row, `composerState` only: `useYoloMode`, `yoloEnableRunEverything`, `yoloCommandAllowlist`/`Denylist`, `webFetchDomainAllowlist`, `modes4` (`autoRun`/`fullAutoRun`). `adminSettings.cached`: team policy counts only.
- `permissions.json` (counts of auto-review instructions only), `sandbox.json`, `hooks.json` at user and project level.
- `product.json` under the Program Files / LocalAppData install dirs for the Cursor version.

Unparseable config files raise `cursor.config.parse_error` (low). Auth/OAuth/secret rows and chat rows in `state.vscdb` are excluded from this collector; only the listed composer fields and admin policy counts are retained. The `accounts` collector copies the database and reads `cursorAuth/cachedEmail` and `cursorAuth/stripeMembershipType` only. IDE/admin state is read separately through a read-only connection, keeping the legacy search summary free of internal payloads. Oversized state values are skipped; `cursorDiskKV` is only queried for one targeted key. Read/write/web rules alone do not suppress the missing command allow-list finding.

## Test

```powershell
.\scripts\test-component.ps1 -Name cursor
.\aiscan.ps1 cursor
```