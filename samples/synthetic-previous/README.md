# Synthetic previous scan

An earlier fake scan to diff against `samples/synthetic-demo`.
Host is `DEMO-ENDPOINT`. No real paths, identities, or credentials.

The story, relative to the current demo:

- Cursor still had local token and composer counts, plus an MCP server. The current demo's Cursor collector is empty, so the diff should flag possible data-location drift.
- Cowork was detected and had sessions. The current demo has no Cowork evidence, so the platform is no longer detected.
- Claude did not yet have the dangerous-mode finding, the `Bash(*)` allow rule, or the Playwright MCP server. It did have a curl allow finding and a Slack MCP server.
- Grok's collector version was `0.9.0` (the demo is `1.0.0`).
- Copilot was not detected.
- Chat message counts and a secrets-scan severity are lower than the current demo.

Preview the diff without writing into the demo folder:

    python core/scan_diff.py --current samples/synthetic-demo --previous samples/synthetic-previous --dry-run
