"""What to do about a finding.

Each guide is a short statement of the risk and an ordered list of steps.
The text is fixed and written here. It never contains evidence, so it is the
same in a masked briefing and in an unmasked one.

Lookup order for a finding id: an exact id, then the longest matching id
prefix, then a pattern matched anywhere in the id (the MCP and parse-error
families share one guide across tools), then the finding's category.
"""

from __future__ import annotations

import re
from typing import Any

Guide = dict[str, Any]

# Where each tool keeps its own transcripts. The scan folder's raw/ copy is
# separate and is covered by PURGE_SCAN_COPY.
TRANSCRIPT_HOMES: dict[str, str] = {
    "claude": (
        "Claude Code keeps each session as a .jsonl file under "
        "~/.claude/projects/<project>/. Delete the session file named on the hit. "
        "cleanupPeriodDays in ~/.claude/settings.json sets how long Claude Code keeps them."
    ),
    "cursor": (
        "Cursor keeps agent transcripts under ~/.cursor/projects/<project>/agent-transcripts/. "
        "Delete the transcript named on the hit, and delete the chat from Cursor's chat history "
        "so the copy in its state database goes too."
    ),
    "cursor-composer": (
        "Cursor Composer chats live in Cursor's state database, not in a file per chat. "
        "Delete the chat from Cursor's chat history panel."
    ),
    "codex": (
        "Codex keeps each session as a rollout .jsonl under ~/.codex/sessions/<year>/<month>/<day>/ "
        "and ~/.codex/archived_sessions/. Delete the rollout file named on the hit."
    ),
    "grok": (
        "Grok Build keeps each session in its own folder under ~/.grok/sessions/<workspace>/<session>/. "
        "Delete the session folder named on the hit."
    ),
    "copilot": (
        "GitHub Copilot chat sessions live under VS Code's workspaceStorage/<id>/chatSessions/. "
        "Delete the session file named on the hit, or clear the chat from the Chat view."
    ),
}

PURGE_SCAN_COPY = (
    "Delete this scan folder's raw/ directory when you are finished. It holds a second "
    "copy of every transcript, including the values listed here."
)

ROTATE_FIRST = (
    "Rotate before you delete. Removing the transcript does not undo the exposure: the value "
    "was already sent to the model provider and may be in backups or synced folders."
)

# One line per secret type, shown beside each distinct value.
SECRET_ACTIONS: dict[str, str] = {
    "aws_key": "Deactivate this access key in AWS IAM, then delete it.",
    "github_pat": "Revoke this token in GitHub and issue a new one with a narrower scope.",
    "slack_token": "Revoke this token in the Slack app's settings and reinstall the app to get a new one.",
    "vendor_token": "Revoke this API key in the vendor console and create a new one.",
    "google_api": "Delete or restrict this key in Google Cloud Console, APIs and Services, Credentials.",
    "authorization": "Find which service this header authenticates to and rotate that credential.",
    "bearer": "Find which service issued this bearer token and revoke it. Many expire on their own; check before assuming.",
    "password_assign": "Change this password where it is used. Check for reuse on other accounts.",
    "url_userinfo": "Change the password embedded in this URL and move it to a secret store or environment variable.",
    "generic_secret": "Identify what this value is. If it is a key or token, rotate it. Hashes, ids, and encoded data need no action.",
    "hex_secret": "Identify what this value is. If it is a key or token, rotate it. Commit ids and file hashes need no action.",
}

SECRET_LABELS: dict[str, str] = {
    "aws_key": "AWS access key ID",
    "github_pat": "GitHub token",
    "slack_token": "Slack token",
    "vendor_token": "AI vendor API key",
    "google_api": "Google API key",
    "authorization": "Authorization header",
    "bearer": "Bearer token",
    "password_assign": "Password assignment",
    "url_userinfo": "Credentials in a URL",
    "generic_secret": "Long random-looking value",
    "hex_secret": "Long hex value",
}

_SECRET_GUIDES: dict[str, Guide] = {
    "aws_key": {
        "risk": (
            "An AWS access key ID (AKIA...) is in a plaintext transcript. The ID alone cannot sign "
            "requests, but the secret access key is usually printed next to it. Read the surrounding "
            "text on each hit."
        ),
        "steps": [
            "Find the owner: aws sts get-access-key-info --access-key-id <the key> returns the account. "
            "In the IAM console, search for the key ID to find the user.",
            "Check use: aws iam get-access-key-last-used --access-key-id <the key>, then CloudTrail for "
            "activity you do not recognize.",
            "Create a replacement key, move the workloads that use it, then run "
            "aws iam update-access-key --status Inactive and, once nothing breaks, delete-access-key.",
            ROTATE_FIRST,
            "Remove the transcript at each location listed below.",
        ],
        "links": [("AWS: manage access keys", "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html")],
    },
    "github_pat": {
        "risk": (
            "A GitHub token is in a plaintext transcript. The prefix says what kind: ghp_ is a classic "
            "personal access token, gho_ an OAuth token, ghu_ and ghs_ GitHub App tokens, ghr_ a refresh token. "
            "A classic token carries every scope it was created with."
        ),
        "steps": [
            "Revoke it: GitHub, Settings, Developer settings, Personal access tokens. A gho_ token is "
            "revoked under Settings, Applications, Authorized OAuth Apps.",
            "Review Settings, Security log (and the organization audit log) for use you do not recognize.",
            "Reissue as a fine-grained token limited to the repositories and permissions it needs, with an expiry.",
            ROTATE_FIRST,
            "Remove the transcript at each location listed below.",
        ],
        "links": [("GitHub: personal access tokens", "https://github.com/settings/tokens")],
    },
    "slack_token": {
        "risk": "A Slack token (xox...) is in a plaintext transcript. It acts as the bot or user it was issued to.",
        "steps": [
            "Revoke it from the app's OAuth and Permissions page at api.slack.com/apps, or call auth.revoke with the token.",
            "Reinstall the app to the workspace to get a new token and update where it is stored.",
            ROTATE_FIRST,
            "Remove the transcript at each location listed below.",
        ],
        "links": [("Slack: your apps", "https://api.slack.com/apps")],
    },
    "vendor_token": {
        "risk": (
            "An AI vendor API key is in a plaintext transcript. sk-ant- is Anthropic, sk-proj- is OpenAI, "
            "xai- is xAI. Anyone holding it can spend against the account."
        ),
        "steps": [
            "Revoke the key in the vendor console and create a new one.",
            "Check the usage page for spend you do not recognize since the transcript date.",
            ROTATE_FIRST,
            "Remove the transcript at each location listed below.",
        ],
        "links": [
            ("Anthropic keys", "https://console.anthropic.com/settings/keys"),
            ("OpenAI keys", "https://platform.openai.com/api-keys"),
            ("xAI console", "https://console.x.ai"),
        ],
    },
    "google_api": {
        "risk": "A Google API key (AIza...) is in a plaintext transcript. An unrestricted key works from anywhere.",
        "steps": [
            "Open Google Cloud Console, APIs and Services, Credentials, and find the key.",
            "Regenerate or delete it. If it must stay, restrict it by API and by referrer or IP.",
            ROTATE_FIRST,
            "Remove the transcript at each location listed below.",
        ],
        "links": [("Google Cloud credentials", "https://console.cloud.google.com/apis/credentials")],
    },
    "authorization": {
        "risk": "An HTTP Authorization header with a value is in a plaintext transcript.",
        "steps": [
            "Read the surrounding text on each hit to find the host the request went to.",
            "Rotate the credential at that service. A Basic header is a base64 username and password.",
            ROTATE_FIRST,
            "Remove the transcript at each location listed below.",
        ],
    },
    "bearer": {
        "risk": "A bearer token is in a plaintext transcript. Whoever holds it is treated as the caller until it expires or is revoked.",
        "steps": [
            "Read the surrounding text on each hit to find the service.",
            "If the token is a JWT, decode the middle segment and check exp. An expired token needs no rotation.",
            "Revoke a live token at the issuer, or rotate the client secret or refresh token that mints it.",
            "Remove the transcript at each location listed below.",
        ],
    },
    "password_assign": {
        "risk": "A password=value assignment is in a plaintext transcript. Many of these are placeholders; the value tells you.",
        "steps": [
            "Read each value. Skip obvious placeholders such as password=changeme in a tutorial.",
            "Change every real password where it is used, and anywhere it was reused.",
            "Move it out of code and chat: an environment variable or a secret manager.",
            "Remove the transcript at each location listed below.",
        ],
    },
    "url_userinfo": {
        "risk": "A URL with a username and password before the @ is in a plaintext transcript (database and git remote URLs are the usual cases).",
        "steps": [
            "Read each hit to see the host. scheme://user@host with no password is low risk.",
            "Change the password for that database user or service account.",
            "Rewrite the connection string to read the password from the environment.",
            "Remove the transcript at each location listed below.",
        ],
    },
    "generic_secret": {
        "risk": (
            "A run of 32 or more base64-style characters containing a digit. This matcher has no idea what the "
            "value is. Most hits are hashes, encoded ids, file paths, and build artifacts. A few are real keys."
        ),
        "steps": [
            "Work down the distinct values below. Each one says how many places it appears and what it looks like.",
            "For each value that is a credential, find the service from the surrounding text and rotate it.",
            "Install a real scanner (betterleaks or gitleaks) so the next scan names the credential type instead of guessing.",
            "Remove the transcripts that hold real credentials.",
        ],
    },
    "hex_secret": {
        "risk": (
            "A run of 32 or more hex characters. Git commit ids (40), SHA-256 digests (64), and MD5 digests (32) all "
            "match, and so do many API keys and session secrets."
        ),
        "steps": [
            "Work down the distinct values below. The note beside each says which common hash length it matches.",
            "A value assigned to a name like key, secret, token, or session in the surrounding text is a credential. Rotate it.",
            "Install a real scanner (betterleaks or gitleaks) so the next scan names the credential type instead of guessing.",
            "Remove the transcripts that hold real credentials.",
        ],
    },
}

_PII_GUIDES: dict[str, Guide] = {
    "credit_card": {
        "risk": (
            "A number that passes the card prefix and Luhn checks is in a plaintext transcript. Published test "
            "cards are counted separately, so these are not the common test numbers. Stored card numbers are "
            "in scope for PCI DSS."
        ),
        "steps": [
            "Read each hit and decide whether it is a real card. The surrounding text usually settles it.",
            "For a real card: tell the cardholder or your payments team so the issuer can replace it.",
            "Delete the transcript at each location. Card numbers must not be kept in chat logs.",
            "Find how it got into a prompt (a pasted log, a database dump, a support ticket) and stop that at the source.",
            PURGE_SCAN_COPY,
        ],
    },
    "test_card": {
        "risk": "A published test card number (Stripe and card-network documentation). No real account is behind it.",
        "steps": ["No action is needed. These are listed so you can confirm they are test data."],
    },
    "us_ssn": {
        "risk": "A value shaped like a US Social Security number that passes the issuance rules is in a plaintext transcript.",
        "steps": [
            "Read each hit and decide whether it belongs to a real person.",
            "For a real SSN: follow your incident process. This is regulated personal data and may need notification.",
            "Delete the transcript at each location and find the source that put it in a prompt.",
            PURGE_SCAN_COPY,
        ],
    },
    "iban_code": {
        "risk": "A bank account number in IBAN form that passes the checksum is in a plaintext transcript.",
        "steps": [
            "Read each hit and decide whether it is a real account.",
            "An IBAN alone cannot move money, but with a name it enables direct-debit fraud in some countries. Tell the account owner.",
            "Delete the transcript at each location.",
            PURGE_SCAN_COPY,
        ],
    },
    "email_address": {
        "risk": (
            "Email addresses are in plaintext transcripts. Most are the operator's own address, git author lines, "
            "and example.com addresses. Customer addresses are the ones that matter."
        ),
        "steps": [
            "Scan the distinct values below. Your own and your team's addresses need no action.",
            "For customer or third-party addresses: find what pasted them in (a database export, a log, a CRM page) and stop it there.",
            "Delete transcripts that hold customer lists.",
        ],
    },
    "phone_number": {
        "risk": "Phone numbers are in plaintext transcripts. Published support lines and example numbers are common.",
        "steps": [
            "Scan the distinct values below. Public business numbers need no action.",
            "For personal numbers: find the source that put them in a prompt and delete those transcripts.",
        ],
    },
    "ip_address": {
        "risk": "Public IP addresses are in plaintext transcripts. Private and loopback addresses are not counted.",
        "steps": [
            "Scan the distinct values below. Public DNS resolvers and documentation ranges need no action.",
            "Addresses of your own servers show an attacker where to look. Check that those hosts are not exposing admin ports.",
        ],
    },
}

_EXACT: dict[str, Guide] = {
    "chat_history.retention.exceeds_90d": {
        "risk": "Transcripts older than 90 days are still on disk. Every secret and customer detail ever pasted into a chat stays readable for that long.",
        "steps": [
            "Set a retention period per tool. Claude Code: cleanupPeriodDays in ~/.claude/settings.json.",
            "Delete old sessions under ~/.claude/projects, ~/.codex/sessions, ~/.cursor/projects, and ~/.grok/sessions.",
            "Exclude those folders from cloud sync and from backups that leave the machine.",
        ],
    },
    "claude.history.global_prompt_log": {
        "risk": "~/.claude/history.jsonl records every prompt typed into Claude Code, across all projects, in plaintext.",
        "steps": [
            "Open ~/.claude/history.jsonl and search it for anything that should not be there.",
            "Delete the file to clear it. Claude Code creates a new one.",
            "Keep it out of cloud sync and backups that leave the machine.",
        ],
    },
    "claude.file_history.snapshots": {
        "risk": "~/.claude/file-history holds a copy of each file as it was before Claude edited it. A deleted secret can survive here.",
        "steps": [
            "If a file ever held a secret that you later removed, check for its snapshot under ~/.claude/file-history.",
            "Delete the folder's contents to clear them. Doing so removes the ability to rewind those edits.",
        ],
    },
    "claude.shell_audit.log_present": {
        "risk": "~/.claude/bash-audit.log records shell commands Claude ran. Commands can carry secrets as arguments.",
        "steps": [
            "Search the log for tokens passed on a command line.",
            "Keep the log if you use it for review. Rotate it, and keep it out of synced folders.",
        ],
    },
    "claude.telemetry.otel_configured": {
        "risk": "Claude Code is exporting OpenTelemetry data. That is useful for oversight. The question is where it goes and whether prompts are included.",
        "steps": [
            "Confirm the destination in the sample is a collector you control.",
            "Check whether OTEL_LOG_USER_PROMPTS is set. With it, prompt text is exported too.",
            "The variables are set in the places the sample names (process or user environment, or settings env).",
        ],
    },
    "claude.permission.bypass_mode": {
        "risk": "Claude Code starts in bypassPermissions mode. Every tool call, including shell commands, runs with no prompt.",
        "steps": [
            "Open the settings file named in the sample and remove \"defaultMode\": \"bypassPermissions\" from permissions.",
            "To block the mode for everyone, set permissions.disableBypassPermissionsMode to \"disable\" in managed settings.",
            "Use bypass mode only inside a container or VM with no credentials and no network you care about.",
        ],
    },
    "claude.permission.auto_mode": {
        "risk": "Claude Code starts in auto mode. A classifier decides which actions run without asking.",
        "steps": [
            "Decide whether that is intended on this machine. For a default that asks, set permissions.defaultMode to \"default\".",
            "Keep explicit deny rules for the commands you never want run unattended.",
        ],
    },
    "claude.permission.accept_edits_mode": {
        "risk": "Claude Code starts in acceptEdits mode. File edits apply without a prompt; shell commands still ask.",
        "steps": [
            "This is a common working mode. Confirm the repos it is used in are under version control so edits can be reviewed.",
            "Set permissions.defaultMode to \"default\" if every edit should be approved.",
        ],
    },
    "claude.permission.skip_dangerous_prompt": {
        "risk": "The confirmation shown before entering bypass mode is switched off, so the mode can be entered with no warning.",
        "steps": [
            "Remove skipDangerousModePermissionPrompt from the settings file named in the sample.",
        ],
    },
    "claude.permission.bash_wildcard": {
        "risk": "An allow rule matches any shell command, so Claude can run anything without asking.",
        "steps": [
            "Open the settings file for the scope shown and find the rule in permissions.allow.",
            "Replace it with rules for the specific commands you use, for example Bash(npm run test:*).",
            "Add deny rules for destructive commands you never want run.",
        ],
    },
    "claude.permission.bash_curl_wide": {
        "risk": "Claude can run curl or wget against any URL without asking. That is a ready path for sending files off the machine.",
        "steps": [
            "Remove the rule from permissions.allow in the settings file for the scope shown.",
            "If fetching is needed, allow WebFetch for named domains instead of a shell command.",
        ],
    },
    "claude.permission.mode_not_applied": {
        "risk": "A permission mode is written in a settings file where Claude Code ignores it. Nothing is exposed, but the file does not do what its author expected.",
        "steps": ["Remove the setting, or move it to the scope where Claude Code reads it."],
    },
    "claude.env.secret_value": {
        "risk": "A settings.json env block holds what looks like a credential in plaintext. Every Claude Code process and every tool it runs can read it.",
        "steps": [
            "Rotate the credential.",
            "Remove it from settings.json. Set it in your shell or a secret manager, or use apiKeyHelper to fetch it at start.",
            "If the settings file is in a repository, check whether it was committed.",
        ],
    },
    "codex.sandbox.full_access": {
        "risk": "Codex runs commands with no sandbox: full disk and network access as your user.",
        "steps": [
            "In ~/.codex/config.toml set sandbox_mode = \"workspace-write\" (or \"read-only\").",
            "Check for a profile or a project-level .codex/config.toml that sets it back.",
        ],
    },
    "codex.approval.never": {
        "risk": "Codex never asks before running a command.",
        "steps": [
            "In ~/.codex/config.toml set approval_policy = \"on-request\" (or \"untrusted\" to approve everything outside a safe list).",
            "If the granular form is used, turn the disabled gates back on.",
        ],
    },
    "codex.network.workspace_write": {
        "risk": "Codex's workspace-write sandbox has network access on, so a command it runs can send data out.",
        "steps": ["In ~/.codex/config.toml set network_access = false under [sandbox_workspace_write]."],
    },
    "codex.env.inherit_all": {
        "risk": "Every environment variable, including cloud credentials and tokens, is passed to commands Codex runs.",
        "steps": ["In ~/.codex/config.toml set inherit = \"core\" under [shell_environment_policy], and list any extra variables with include_only."],
    },
    "codex.env.ignore_excludes": {
        "risk": "Codex's built-in filter that drops variables named like KEY, SECRET, and TOKEN is switched off.",
        "steps": ["In ~/.codex/config.toml remove ignore_default_excludes = true from [shell_environment_policy]."],
    },
    "codex.trust.broad": {
        "risk": "Each trusted project lets Codex load that project's own config and run with fewer prompts there. A long list is easy to stop reviewing.",
        "steps": [
            "Open ~/.codex/config.toml and read the [projects.\"<path>\"] entries with trust_level = \"trusted\". The list is in the rules below.",
            "Delete the entries for projects you no longer work in, and for any repository you cloned from someone else.",
        ],
    },
    "codex.telemetry.log_user_prompt_configured": {
        "risk": "Codex is set to include prompt text in its telemetry export. Anything typed into a prompt goes to the destination shown.",
        "steps": [
            "Confirm the destination in the sample is a collector you control.",
            "To stop exporting prompt text, set log_user_prompt = false under [otel] in ~/.codex/config.toml.",
        ],
    },
    "codex.rules.interpreter_prefix": {
        "risk": "A saved always-allow rule covers an interpreter such as python or bash -c. That allows any code at all.",
        "steps": ["Remove the rules shown in the sample from Codex's saved rules, and approve interpreters case by case."],
    },
    "codex.rules.saved_allow": {
        "risk": "Commands approved with \"always allow\" are saved and never asked about again.",
        "steps": ["Review the saved rules under ~/.codex and delete the ones you no longer want."],
    },
    "codex.desktop.full_access_mode": {
        "risk": "Codex Desktop is in Full access mode: no sandbox and no approvals.",
        "steps": ["Switch the agent mode in Codex Desktop back to the default that asks for approval."],
    },
    "codex.desktop.thread_full_access": {
        "risk": "Some Codex Desktop threads ran with full access or with approvals bypassed.",
        "steps": ["Review what those threads did, and start new threads in the default mode."],
    },
    "grok.permission.always_approve": {
        "risk": "Grok Build runs every tool call without asking.",
        "steps": [
            "In ~/.grok/config.toml, under [ui], remove permission_mode = \"always-approve\" and any yolo = true.",
            "Check each repository for a .grok/config.toml that sets it again.",
        ],
    },
    "grok.sandbox.off": {
        "risk": "Grok Build sessions ran with the sandbox off, so commands had the full access of your user account.",
        "steps": [
            "Start Grok Build with a sandbox profile for normal work.",
            "The count is sessions recorded with sandbox_profile off in their summary.json under ~/.grok/sessions.",
        ],
    },
    "grok.permission.bash_wildcard": {
        "risk": "A Grok allow pattern matches any shell command.",
        "steps": ["Edit [permission].allow in ~/.grok/config.toml and replace the wildcard with the specific commands you use."],
    },
    "grok.permission.bash_curl_wide": {
        "risk": "Grok can run curl or wget against any URL without asking.",
        "steps": ["Remove the pattern from [permission].allow in ~/.grok/config.toml."],
    },
    "grok.auth.present_excluded": {
        "risk": "~/.grok/auth.json holds the Grok sign-in. The scan noted that it exists and did not read it.",
        "steps": ["No action is needed. Keep the file out of synced folders and backups that leave the machine."],
    },
    "cursor.permissions.no_durable_allowlist": {
        "risk": "No saved command allow-list was found for Cursor. Approvals are per prompt, or decided by Cursor's auto-run setting, which this scan cannot read from every version.",
        "steps": [
            "Open Cursor Settings and check the agent auto-run mode and its command allowlist.",
            "If auto-run is on with no allowlist, the agent runs any command without asking.",
        ],
    },
    "cursor.permissions.events_observed": {
        "risk": "Approval events were seen in Cursor transcripts. This is a count of activity, not a misconfiguration.",
        "steps": ["No action is needed. The allowed tools are listed under Agents, Permissions."],
    },
    "vscode.copilot.exclude.none_configured": {
        "risk": "Copilot has no content exclusions, so it can read every file in an open workspace, including .env files.",
        "steps": [
            "Add content exclusion paths for the repository or organization in GitHub Copilot settings (Business and Enterprise plans).",
            "Keep secrets out of the workspace regardless: exclusions do not cover every Copilot feature.",
        ],
    },
    "copilot.exclude.none_configured": {
        "risk": "Copilot has no content exclusions, so it can read every file in an open workspace, including .env files.",
        "steps": [
            "Add content exclusion paths for the repository or organization in GitHub Copilot settings (Business and Enterprise plans).",
            "Keep secrets out of the workspace regardless: exclusions do not cover every Copilot feature.",
        ],
    },
    "vscode.copilot.tools.auto_approve": {
        "risk": "Copilot's agent runs tools, including terminal commands, without asking.",
        "steps": ["Turn off the auto-approve setting named in the sample in VS Code settings, or limit it to named tools."],
    },
    "vscode.workspace_trust.disabled": {
        "risk": "VS Code Workspace Trust is off, so any folder you open can run tasks and extensions as you.",
        "steps": ["Set security.workspace.trust.enabled to true in VS Code settings."],
    },
    "cowork.sessions.transcripts_on_disk": {
        "risk": "Cowork session transcripts are stored in plaintext under %APPDATA%\\Claude.",
        "steps": [
            "Delete old sessions from the Claude desktop app, or remove their folders under local-agent-mode-sessions.",
            "Keep that folder out of roaming profiles and backups that leave the machine.",
        ],
    },
    "cowork.retention.exceeds_90d": {
        "risk": "Cowork session workspaces older than 90 days are still on disk with their uploads and outputs.",
        "steps": ["Delete sessions you no longer need from the Claude desktop app."],
    },
    "cowork.office_cache.previews": {
        "risk": "Cowork keeps rendered PDF previews of Office documents it opened. A confidential document stays readable there after the session ends.",
        "steps": ["Clear the cowork-file-preview/office-cache folder under %APPDATA%\\Claude."],
    },
    "cowork.bridge.remote_sync": {
        "risk": "A Cowork session is bridged to a remote environment, so its files exist off this machine too.",
        "steps": ["Confirm the remote environment is one you expect, and end sessions you are not using."],
    },
    "grok_bot.secrets.store_present": {
        "risk": "Grok Bot keeps a secrets store on disk. The scan noted the files and did not open them.",
        "steps": [
            "Review which secrets you gave Grok Bot in its own settings.",
            "Keep %APPDATA%\\Grok Bot out of synced folders and backups that leave the machine.",
        ],
    },
    "git.env.in_history": {
        "risk": (
            "A .env file was committed. Deleting the file later does not remove it: every clone and every "
            "fork still has the old commit. Treat each value in it as exposed."
        ),
        "steps": [
            "Read what was committed: git show <commit>:<path> in the repository shown on each row.",
            "Rotate every credential in that file. This is the step that fixes the exposure.",
            "If the note says still tracked: git rm --cached <path>, add it to .gitignore, and commit.",
            "Check whether the commit reached a remote: git branch -r --contains <commit>.",
            "To remove it from history, use git filter-repo --invert-paths --path <path>, force-push, and have "
            "everyone re-clone. On GitHub, ask support to clear cached views of the old commits.",
        ],
        "links": [("GitHub: removing sensitive data", "https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/removing-sensitive-data-from-a-repository")],
    },
    "git.hooks.missing": {
        "risk": "Nothing checks a commit for secrets before it is made in these repositories.",
        "steps": [
            "Add a secret scanner as a pre-commit hook. With the pre-commit framework, add the gitleaks hook to "
            ".pre-commit-config.yaml and run pre-commit install.",
            "Turn on GitHub push protection for the repository as a second check.",
        ],
    },
    "git.branch.no_protection": {
        "risk": "The default branch accepts direct and force pushes. An agent with repository access can rewrite it.",
        "steps": ["In the repository on GitHub: Settings, Branches (or Rules), add a rule for the default branch that requires a pull request and blocks force pushes."],
    },
    "git.blob.large": {
        "risk": "Large files are in git history. They are often data exports or archives that were not meant to be committed.",
        "steps": [
            "Check what each file is. A database dump or an export may hold personal data or secrets.",
            "If it should not be there, remove it from history with git filter-repo and add the pattern to .gitignore.",
        ],
    },
    "secrets-scan.tool_unavailable": {
        "risk": "No dedicated secrets scanner ran. The built-in patterns still ran, but they recognize far fewer credential types and guess at the rest.",
        "steps": [
            "Run .\\scripts\\get-betterleaks.ps1 from the aiscan folder, or install gitleaks and put it on PATH.",
            "Scan again. Hits will then name the credential type and the rule that matched.",
        ],
    },
    "secrets-scan.no_repo_roots": {
        "risk": "No code directories were scanned for secrets, only chat transcripts.",
        "steps": ["Scan again with -RepoRoots pointing at the folders that hold your repositories."],
    },
    "accounts.identity.multiple": {
        "risk": "The AI tools on this machine are signed in under more than one account. Work data may be going through a personal account.",
        "steps": [
            "Read the account table under Agents and collectors.",
            "Sign each tool out of any account that is not the one your organization manages.",
        ],
    },
    "accounts.auth.api_key_and_subscription": {
        "risk": "A tool has both an API key and a subscription sign-in. Usage may bill to, and be governed by, a different account than you expect.",
        "steps": ["Decide which one is intended and remove the other (unset the API key variable, or sign out)."],
    },
}

# Matched anywhere in the id, so one guide covers the same check in every tool.
_PATTERNS: list[tuple[re.Pattern[str], Guide]] = [
    (
        re.compile(r"\.mcp\.(env_secret|args_secret)$"),
        {
            "risk": "An MCP server entry has a credential written in plaintext in its env block or command line. Any process that can read the config file can read it.",
            "steps": [
                "Rotate the credential.",
                "Open the MCP config named in the sample and replace the literal with a reference to an environment variable.",
                "If the config file is inside a repository, check whether it was committed.",
            ],
        },
    ),
    (
        re.compile(r"\.mcp\.(external_server|non_localhost|http_remote|non_local_server)$"),
        {
            "risk": "An MCP server runs somewhere other than this machine. Whatever the agent passes to its tools leaves the endpoint, and its tool descriptions are instructions the agent will read.",
            "steps": [
                "Confirm you know who operates the server named in the sample.",
                "Remove the entry from the MCP config if it is not needed.",
                "Prefer servers that run locally over stdio for anything that touches source code or credentials.",
            ],
        },
    ),
    (
        re.compile(r"\.mcp\.(runtime_only|workspace_servers_present)$"),
        {
            "risk": "MCP servers are being loaded from a place other than the user config, such as a repository's own config file. Opening that repository is enough to add tools to the agent.",
            "steps": ["Read the MCP config inside each workspace and remove servers you did not add."],
        },
    ),
    (
        re.compile(r"\.config\.parse_error$|\.parse_error$"),
        {
            "risk": "A config file exists but could not be read, so its settings are missing from this report. The tool itself may be ignoring the file too.",
            "steps": ["Open the file named in the sample and fix the syntax error, then scan again."],
        },
    ),
    (
        re.compile(r"compressed_(not_scanned|unreadable)|files_too_large|coverage|target_missing|sqlite_history_not_counted|format_drift|chat_corpus_not_scanned|scanner_error|read_error"),
        {
            "risk": "Part of the data could not be read, so this report is incomplete for it. This is a gap in the scan, not a problem on the machine.",
            "steps": ["See the Coverage gaps tab for what was skipped and how to include it next time."],
        },
    ),
    (
        re.compile(r"^cloud_agents\."),
        {
            "risk": "A Cursor cloud agent holds repository access and runs away from this machine.",
            "steps": [
                "Open the agent from the link in the Agents tab and confirm it is still needed.",
                "Archive agents that are finished. Give long-running agents their own branch, not the current one.",
            ],
        },
    ),
]

_BY_CATEGORY: dict[str, Guide] = {
    "Secrets Exposure": {
        "risk": "A credential is stored where it can be read in plaintext.",
        "steps": ["Rotate the credential, then remove the stored copy."],
    },
    "PII Exposure": {
        "risk": "Personal data is stored in plaintext transcripts.",
        "steps": ["Decide whether it belongs to a real person, find how it got into a prompt, and delete the transcripts that hold it."],
    },
    "Shell Execution": {
        "risk": "The agent can run shell commands with less review than the default.",
        "steps": ["Narrow the rule or mode shown in the sample to the specific commands you use."],
    },
    "Network Egress": {
        "risk": "The agent has a path to send data off the machine.",
        "steps": ["Confirm the destination is one you expect, and remove the rule or server if it is not needed."],
    },
    "MCP Tooling": {
        "risk": "An MCP server extends what the agent can do.",
        "steps": ["Confirm you know what each server does and who runs it. Remove the ones you do not use."],
    },
    "Cross-Agent Visibility": {
        "risk": "Data from past sessions stays on disk where other tools and other users of the machine can read it.",
        "steps": ["Set a retention period, delete what you do not need, and keep the folder out of sync and backup."],
    },
    "Telemetry Configuration": {
        "risk": "The tool is sending usage data somewhere.",
        "steps": ["Confirm the destination and whether prompt text is included."],
    },
    "Git Posture": {
        "risk": "A repository is missing a guard that keeps secrets and unreviewed changes out.",
        "steps": ["Add the missing control in the repositories listed."],
    },
    "Identity & SSO": {
        "risk": "The account a tool is signed in as decides who can see its data and who governs it.",
        "steps": ["Confirm each tool is signed in with the account your organization manages."],
    },
}


def secret_type_of(finding_id: str) -> str:
    """'aws_key' for 'pii_scan.secret_aws_key', else ''."""
    fid = str(finding_id or "").lower()
    if fid.startswith("pii_scan.secret_"):
        return fid[len("pii_scan.secret_"):]
    return ""


def _chat_secret_guide(tool: str) -> Guide:
    home = TRANSCRIPT_HOMES.get(tool, "Delete the session file named on each hit from the tool's own history folder.")
    return {
        "risk": (
            "Values that look like credentials are sitting in this tool's chat transcripts in plaintext. "
            "They got there by being pasted into a prompt, printed by a command, or read from a file. "
            "The specific matchers (AWS, GitHub, vendor keys) are reliable. The two length-only matchers are not."
        ),
        "steps": [
            "Start with the named credential types below. Each distinct value is listed once with every place it appears.",
            ROTATE_FIRST,
            "Rotate each real credential at its issuer. The line beside each value says where.",
            home,
            PURGE_SCAN_COPY,
        ],
    }


def guidance_for(finding: dict[str, Any]) -> Guide | None:
    """The guide for one finding, or None when nothing fits."""
    fid = str(finding.get("id") or "").strip().lower()
    if fid in _EXACT:
        return _EXACT[fid]
    if fid.startswith("chat_history.secret."):
        return _chat_secret_guide(fid[len("chat_history.secret."):])
    secret_type = secret_type_of(fid)
    if secret_type:
        guide = _SECRET_GUIDES.get(secret_type)
        if guide:
            return guide
    if fid.startswith("pii_scan."):
        guide = _PII_GUIDES.get(fid[len("pii_scan."):])
        if guide:
            return guide
    best: tuple[int, Guide] | None = None
    for key, guide in _EXACT.items():
        if fid.startswith(key + ".") and (best is None or len(key) > best[0]):
            best = (len(key), guide)
    if best:
        return best[1]
    for pattern, guide in _PATTERNS:
        if pattern.search(fid):
            return guide
    return _BY_CATEGORY.get(str(finding.get("category") or ""))
