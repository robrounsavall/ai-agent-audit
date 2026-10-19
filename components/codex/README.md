# Codex collector

Inventories Codex Desktop approval events, trusted projects, sandbox/telemetry posture from `~/.codex`.

Codex compresses session rollouts older than seven days (`rollout-*.jsonl` becomes `rollout-*.jsonl.zst`). On Python 3.14 and newer those files are decompressed with the standard-library `compression.zstd` module and scanned like plain rollouts. A plain file wins when both copies exist. On older Python the compressed logs are counted and not opened, and a low finding says "N compressed Codex session logs not scanned". A compressed log that is corrupt, too large, or too slow to unpack is a low coverage note. Nothing is installed.

`last_used` is the newest mtime among rollouts, `session_index.jsonl`, and `state_*.sqlite` (those files are not opened for this). `desktop_installed` and `desktop_last_opened` come from the Store app folder and its `codex-desktop-*.log` mtimes, also stat only. The briefing shows the app as its own "Codex Desktop app" row.

| | |
|---|---|
| Evidence | `evidence/codex.json` |
| In `aiscan all` | yes |
| Deps | stdlib only (`tomllib`; `compression.zstd` on Python 3.14+ for compressed sessions) |

## Test

```powershell
.\scripts\test-component.ps1 -Name codex
.\aiscan.ps1 codex
```
## Permission files

Also inventories permission profiles in `config.toml` and `*.config.toml`, saved
`rules/*.rules`, and lifecycle commands in `hooks.json`. Project `.codex` layers
are evaluated only for projects trusted by the user config. `--repo-roots` accepts
repository roots or parent folders to inspect. Managed `requirements.toml` and
legacy `managed_config.toml` are checked in the platform's Codex admin directory.
Desktop `.codex-global-state.json` contributes only permission modes and counts;
thread identifiers, account data, and workspace paths are excluded.
