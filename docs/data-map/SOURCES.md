# aiscan Data Map: sources and method

`docs/aiscan-data-map.html` is generated from two files in this folder:

- `data_map_content.py` holds every claim, each tied to a citation.
- `build_data_map.py` renders the page, including the inline SVG diagrams, CSS and JS.

Edit the content, then rebuild:

```
python docs/data-map/build_data_map.py --verify   # rebuild and check every citation anchor
python docs/data-map/build_data_map.py --check    # fail if the committed HTML is stale
```

## Source baseline

- Repository commit: `07153c79d4adc057bf2c936aa359cc8b19f2abea` (`BASE_SHA` in `data_map_content.py`), aiscan 0.2.0.
- Every source citation links to `blob/<BASE_SHA>/<path>#L<start>-L<end>`.
- `--verify` checks that each citation's anchor string appears inside its cited line range in the `BASE_SHA` blob (`git show`), not in later working-tree edits. That keeps line numbers honest at the pinned commit.
- The coverage matrix is parsed from `AGENTS`, `COLUMNS` and `UNCAPTURED` in `report/access_map.py`.
- Research was done by reading source code only. No scan was run, and no machine, user data or credential file was opened. Example paths are generic placeholders such as `%USERPROFILE%`, `%APPDATA%` and `<repo>`. The sample envelope is synthetic and uses `EXAMPLE-HOST`.

## Public documentation (read 2026-11-06)

| Topic | URL |
| --- | --- |
| Claude Code data usage and retention | https://docs.claude.com/en/docs/claude-code/data-usage |
| Codex config and state locations | https://developers.openai.com/codex/config-advanced |
| Codex Cloud | https://developers.openai.com/codex/cloud |
| Cursor Cloud Agents | https://cursor.com/docs/cloud-agent |
| Cursor Cloud Agent security | https://cursor.com/docs/cloud-agent/security |
| Cursor privacy and data governance | https://cursor.com/docs/enterprise/privacy-and-data-governance |
| VS Code chat sessions (doc source, pinned) | https://github.com/microsoft/vscode-docs/blob/36ba054f/docs/copilot/chat/chat-sessions.md |
| VS Code session history and sync | https://code.visualstudio.com/docs/agents/run/sessions/session-history |

The two Cursor security and governance pages were confirmed through search-result extracts rather than a full page fetch.

Remote storage for Grok Build and Grok Bot could not be verified from public docs. The page labels them "not verified" and makes no claims about them.

## Judgment calls

- **Credential file names.** File names such as `auth.json` and `.credentials.json` appear because collectors stat or allowlist them, and leaving them out would make the page inaccurate. The page never shows contents, and the research never read any.
- **Shorthand mapping.** The requested shorthand was "collectors → normalized evidence → analysis → briefing". The page maps it onto the seven stages the code actually has and notes that most analysis happens inside each collector.
- **Unclear coverage.** Coverage that is unknown or platform-dependent is shown as such, never as "no access". Examples include Grok Bot local execution and the `UNCAPTURED` cells.
