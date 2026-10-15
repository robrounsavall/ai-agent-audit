# Codex collector

Inventories Codex Desktop approval events, trusted projects, sandbox/telemetry posture from `~/.codex`.

| | |
|---|---|
| Evidence | `evidence/codex.json` |
| In `aiscan all` | yes |
| Deps | stdlib only (`tomllib`; `compression.zstd` on Python 3.14+ for compressed sessions) |

## Compressed sessions

The Codex app compresses session rollouts older than seven days in place
(`rollout-*.jsonl` -> `rollout-*.jsonl.zst`, mtimes preserved). The collector
reads both, preferring the plain file when both exist. Reading `.zst` needs
Python 3.14+ (stdlib `compression.zstd`) or an already-installed `zstandard`
package; aiscan never installs one. On an older Python the files are still
counted, their mtimes still feed `last_used`, and the medium finding
`codex.compressed_sessions_unreadable` says how many sessions were not parsed.

Activity fields in the summary (all from file mtimes; nothing below is opened):

- `last_used`: newest of the session rollouts, `session_index.jsonl` and
  `state_*.sqlite` (`last_used_source` names the winner).
- `desktop_installed` / `desktop_last_opened`: the Microsoft Store app's
  `%LOCALAPPDATA%\Packages\OpenAI.Codex_*` folder and the newest
  `codex-desktop-*.log` under its `LocalCache\Local\Codex\Logs`. Opened is
  not used; the report shows it as a separate "Codex Desktop app" row.

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
