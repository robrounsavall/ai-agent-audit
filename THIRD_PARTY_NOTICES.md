# Third-Party Notices

This project is stdlib-first Python. Optional features call external tools or
packages, none of which are bundled in this repository:

| Dependency | License | Used by | Bundled? |
|---|---|---|---|
| [gitleaks](https://github.com/gitleaks/gitleaks) | MIT | `secrets-scan` collector (external binary on PATH) | No |
| [trufflehog](https://github.com/trufflesecurity/trufflehog) | AGPL-3.0 | optional alternative scanner (external binary, never linked) | No |

This project is not affiliated with or endorsed by Anthropic, OpenAI, Cursor,
xAI, Microsoft, or GitHub. Tool names are used to identify the software whose
local data the collectors inventory.
