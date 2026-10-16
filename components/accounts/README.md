# Accounts collector

Reports which account each AI tool on the machine is signed in as. This is a
read-only inventory of identifiers (email, username, organization, plan) and
auth method. It does not report token or API key values.

| | |
|---|---|
| Evidence | `evidence/accounts.json` |
| In `aiscan all` | yes |
| Deps | stdlib only |

`accounts[]` has one row per tool (and extra rows for an API key beside a
subscription login, each MCP server that carries auth, and each set API-key
environment variable). `signed_in` is `yes`, `no`, or `unknown`. `source` is
home-relative (`~/.codex/auth.json`, `%APPDATA%/...`) or `env:NAME`. It is
never an absolute path.

`-Redact` / `AISCAN_REDACT=1` replaces emails with `<email>` in the rows and
in finding samples, same as other shareable output.

## What it reads

| Tool | Where the identifier lives |
|---|---|
| Claude Code | `~/.claude.json` `oauthAccount` (email, organization, plan). `.credentials.json` is presence only and is not opened. |
| Codex | `~/.codex/auth.json`. Email and plan are taken from the `id_token` JWT payload. Organization is `organization_name` or `org_name`, or the default (or first) `organizations` entry's title or name. `last_refresh` is reported as the last sign-in time. |
| Cursor | A copy of `state.vscdb`. Keys: `cursorAuth/cachedEmail`, `cursorAuth/stripeMembershipType`, `cursorAuth/cachedSignUpType`, `cursorAuth/stripeSubscriptionStatus`. |
| Copilot | Top-level JSON under the Copilot globalStorage directory, plus a `copilot-user` file when it is a short username. Files with `token` in the name are not opened. |
| Grok CLI | `~/.grok/auth.json` and `user-settings.json` / `user-settings.toml`. Allowlisted keys only. |
| Grok Bot | `desktop-status.json`, `Preferences`, and `Local State`, allowlisted keys only. |
| GitHub CLI | `hosts.yml` `user:` field. |
| git | Global `user.email` / `user.name`. |
| MCP | Auth *method* only (env var name, header name, URL userinfo present, Authorization arg). |
| Environment | Presence of `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `XAI_API_KEY`, `CURSOR_API_KEY`. |

Findings: more than one distinct account identifier across tools, and API-key
auth used alongside subscription (OAuth) auth.

## What it does not read

Token, API key, password, and cookie values. Claude credential files. Cursor
keys other than the four above. Codex `access_token` and `refresh_token`.
Grok Bot cookies, Local Storage, Session Storage, Network, Cache, and
secrets-store files. Git credential helpers. `oauth_token` lines in
`hosts.yml`. No network calls and no credential-store decryption.

## Test

```powershell
.\scripts\test-component.ps1 -Name accounts
.\aiscan.ps1 accounts
```
