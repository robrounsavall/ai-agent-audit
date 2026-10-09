# GitHub access inventory

Opt-in report of what you have allowed to access GitHub organizations you own.
It is not part of `aiscan all`. `aiscan` stays offline. This tool calls the
GitHub API with a token you already have, and it only reads.

```powershell
gh auth login
python tools\github-access\github_access.py
python tools\github-access\github_access.py --org your-org
python tools\github-access\github_access.py --format json
```

Token lookup is `--token`, then `GH_TOKEN`, then `GITHUB_TOKEN`, then
`gh auth token`. The token is not printed. Do not commit the output: it names
apps, permission grants, and the last eight characters of SAML-authorized tokens.

## What you get

For each organization you belong to:

| Call | When it works | What it shows |
|---|---|---|
| `GET /orgs/{org}/installations` | You are an organization owner. Classic tokens need the `admin:read` scope GitHub documents for this route. | Every GitHub App installed on the org, its permission map (`contents:write` and the rest), and whether it can see all repositories or a selected set |
| `GET /orgs/{org}/credential-authorizations` | You are an owner and the org uses SAML SSO | PATs, SSH keys, OAuth tokens, and GitHub App user tokens that members have authorized for the org. Defaults to your login. `--all-members` lists everyone |

A membership that is not an owner is reported as such and not queried.

## What a token cannot show

GitHub does not give a personal access token these lists. The report prints the settings pages instead of inventing them:

- GitHub Apps installed on your **personal** account: [settings/installations](https://github.com/settings/installations)
- OAuth apps you clicked Authorize on: [settings/applications](https://github.com/settings/applications). The old grants API required a password and does not accept a token.
- Personal access tokens you created: [settings/tokens](https://github.com/settings/tokens)
- The repository names behind an app whose access is "selected". That list is only available to the app's own installation token.

`GET /user/installations` is a different call. It lists installations of the app that issued the token, not every app you have installed, so this tool does not use it as an inventory.

## Test

```powershell
python -m unittest discover -s tools\github-access\tests -v
```
