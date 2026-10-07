"""
List GitHub Apps installed on organizations you own, and SAML-authorized
credentials for your login.

Not part of aiscan. This tool makes network calls. It is read-only: it never
revokes an app, token, or key.

Auth, first match: --token, then GH_TOKEN, then GITHUB_TOKEN, then `gh auth token`.
The token is not printed.

What GitHub will not return to a personal access token, so this tool does not
pretend to:

- GitHub Apps installed on your personal account (settings/installations)
- OAuth apps you have authorized (settings/applications). The old grants API
  required a password and is not available with a token.
- The list of personal access tokens you created (settings/tokens)
- Which repositories a "selected" installation can see. That list belongs to
  the app's own installation token.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Callable

API = "https://api.github.com"
API_VERSION = "2026-03-10"
MAX_PAGES = 20

HttpGet = Callable[[str, str], tuple[int, dict[str, str], bytes]]

GAPS = (
    "GitHub Apps installed on your personal account are not returned to a token. "
    "See https://github.com/settings/installations",
    "Authorized OAuth apps are not returned to a token. "
    "See https://github.com/settings/applications",
    "Your own personal access tokens are not listable. "
    "See https://github.com/settings/tokens",
    "When an app's repository access is \"selected\", GitHub does not tell a "
    "normal token which repositories those are.",
)


class GitHubError(Exception):
    def __init__(self, status: int, message: str, path: str) -> None:
        super().__init__(f"{status} {path}: {message}")
        self.status = status
        self.message = message
        self.path = path


def scrub(text: str, token: str | None) -> str:
    if token and token in text:
        text = text.replace(token, "[token]")
    text = re.sub(r"\bgh[pousr]_[A-Za-z0-9_]{8,}", "[token]", text)
    text = re.sub(r"\bgithub_pat_[A-Za-z0-9_]{8,}", "[token]", text)
    return text


def _allowed(url: str) -> bool:
    parsed = urllib.parse.urlparse(url)
    return parsed.scheme == "https" and parsed.netloc == "api.github.com"


def _next_link(headers: dict[str, str]) -> str | None:
    link = ""
    for key, value in headers.items():
        if key.lower() == "link":
            link = value
            break
    for part in link.split(","):
        if 'rel="next"' not in part:
            continue
        match = re.search(r"<([^>]+)>", part)
        if match:
            return match.group(1)
    return None


def _message(body: bytes) -> str:
    try:
        data = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return "unreadable response"
    if isinstance(data, dict) and data.get("message"):
        return str(data["message"])
    return "request failed"


class _StayOnApi(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if not _allowed(newurl):
            raise urllib.error.HTTPError(req.full_url, code, "refused redirect", headers, fp)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def http_get(url: str, token: str, timeout: int = 30) -> tuple[int, dict[str, str], bytes]:
    if not _allowed(url):
        raise GitHubError(0, "refused non-GitHub URL", url)
    request = urllib.request.Request(
        url,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": API_VERSION,
            "User-Agent": "ai-agent-audit-github-access",
        },
        method="GET",
    )
    opener = urllib.request.build_opener(_StayOnApi)
    try:
        with opener.open(request, timeout=timeout) as response:
            return response.status, dict(response.headers.items()), response.read()
    except urllib.error.HTTPError as exc:
        raw = exc.read() if exc.fp is not None else b""
        headers = dict(exc.headers.items()) if exc.headers else {}
        return exc.code, headers, raw


def build_url(path: str, params: dict[str, Any] | None = None) -> str:
    if not path.startswith("/"):
        path = "/" + path
    query = urllib.parse.urlencode(
        {key: value for key, value in (params or {}).items() if value is not None}
    )
    url = API + path
    if query:
        url += "?" + query
    return url


class GitHubClient:
    def __init__(self, token: str, http_get_fn: HttpGet = http_get) -> None:
        self.token = token
        self._http_get = http_get_fn

    def get_json(self, path: str, params: dict[str, Any] | None = None) -> Any:
        url = build_url(path, params)
        status, _headers, body = self._read(url)
        if status != 200:
            raise GitHubError(status, scrub(_message(body), self.token), path)
        return json.loads(body.decode("utf-8"))

    def get_all(
        self,
        path: str,
        params: dict[str, Any] | None = None,
        *,
        list_key: str | None = None,
    ) -> list[Any]:
        url = build_url(path, {**(params or {}), "per_page": 100})
        items: list[Any] = []
        for _page in range(MAX_PAGES):
            if not _allowed(url):
                raise GitHubError(0, "refused pagination URL", path)
            status, headers, body = self._read(url)
            if status != 200:
                raise GitHubError(status, scrub(_message(body), self.token), path)
            data = json.loads(body.decode("utf-8"))
            if list_key is not None:
                chunk = data.get(list_key) if isinstance(data, dict) else None
                if not isinstance(chunk, list):
                    raise GitHubError(status, "unexpected payload", path)
                items.extend(chunk)
            elif isinstance(data, list):
                items.extend(data)
            else:
                raise GitHubError(status, "unexpected payload", path)
            nxt = _next_link(headers)
            if not nxt:
                return items
            if not _allowed(nxt):
                raise GitHubError(0, "refused pagination URL", path)
            url = nxt
        raise GitHubError(0, "too many pages", path)

    def _read(self, url: str) -> tuple[int, dict[str, str], bytes]:
        try:
            return self._http_get(url, self.token)
        except GitHubError:
            raise
        except OSError as exc:
            raise GitHubError(0, scrub(str(exc), self.token), url) from exc


def gh_auth_token() -> str | None:
    gh = shutil.which("gh")
    if not gh:
        return None
    try:
        proc = subprocess.run(
            [gh, "auth", "token"],
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if proc.returncode != 0:
        return None
    token = (proc.stdout or "").strip()
    return token or None


def resolve_token(
    explicit: str | None,
    environ: dict[str, str] | None = None,
    gh_token_fn: Callable[[], str | None] = gh_auth_token,
) -> str | None:
    if explicit:
        return explicit
    env = environ if environ is not None else os.environ
    for key in ("GH_TOKEN", "GITHUB_TOKEN"):
        value = env.get(key)
        if value:
            return value
    return gh_token_fn()


def normalize_installation(raw: dict[str, Any]) -> dict[str, Any]:
    permissions = raw.get("permissions") if isinstance(raw.get("permissions"), dict) else {}
    account = raw.get("account") if isinstance(raw.get("account"), dict) else {}
    return {
        "app_slug": str(raw.get("app_slug") or ""),
        "app_id": raw.get("app_id"),
        "installation_id": raw.get("id"),
        "account_login": account.get("login"),
        "target_type": raw.get("target_type"),
        "repository_selection": raw.get("repository_selection"),
        "permissions": {str(key): value for key, value in permissions.items() if value},
        "suspended": bool(raw.get("suspended_at")),
        "html_url": raw.get("html_url"),
    }


def normalize_credential(raw: dict[str, Any]) -> dict[str, Any]:
    scopes = raw.get("scopes") if isinstance(raw.get("scopes"), list) else []
    return {
        "login": raw.get("login"),
        "credential_type": raw.get("credential_type"),
        "credential_authorized_at": raw.get("credential_authorized_at"),
        "credential_accessed_at": raw.get("credential_accessed_at"),
        "scopes": [str(scope) for scope in scopes],
        "token_last_eight": raw.get("token_last_eight"),
        "authorized_credential_title": raw.get("authorized_credential_title"),
        "authorized_credential_note": raw.get("authorized_credential_note"),
        "authorized_credential_expires_at": raw.get("authorized_credential_expires_at"),
        "fingerprint": raw.get("fingerprint"),
    }


def _org_login(row: dict[str, Any]) -> str | None:
    org = row.get("organization")
    if isinstance(org, dict) and org.get("login"):
        return str(org["login"])
    if row.get("login"):
        return str(row["login"])
    return None


def list_orgs(client: GitHubClient) -> tuple[list[dict[str, Any]], str | None]:
    try:
        rows = client.get_all("/user/memberships/orgs")
    except GitHubError as exc:
        if exc.status not in (403, 404):
            raise
        fallback = client.get_all("/user/orgs")
        orgs = []
        for row in fallback:
            if isinstance(row, dict) and row.get("login"):
                orgs.append({"login": str(row["login"]), "role": None, "state": "active"})
        return orgs, f"organization role unknown ({exc.status} on /user/memberships/orgs)"
    orgs = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        login = _org_login(row)
        if not login:
            continue
        orgs.append(
            {
                "login": login,
                "role": row.get("role"),
                "state": row.get("state") or "active",
            }
        )
    return orgs, None


def collect(
    client: GitHubClient,
    *,
    org_filter: str | None = None,
    all_members: bool = False,
) -> dict[str, Any]:
    user = client.get_json("/user")
    login = str(user.get("login") or "")
    orgs, role_note = list_orgs(client)
    if org_filter:
        orgs = [org for org in orgs if org["login"].lower() == org_filter.lower()]
    report_orgs = []
    for org in orgs:
        if org.get("state") not in (None, "active"):
            continue
        entry: dict[str, Any] = {
            "login": org["login"],
            "role": org.get("role"),
            "installations": [],
            "installations_error": None,
            "credential_authorizations": [],
            "credential_authorizations_error": None,
        }
        if org.get("role") == "member":
            entry["installations_error"] = (
                "not an organization owner; GitHub only lets owners list installed apps"
            )
            entry["credential_authorizations_error"] = entry["installations_error"]
            report_orgs.append(entry)
            continue
        try:
            raw_installations = client.get_all(
                f"/orgs/{org['login']}/installations",
                list_key="installations",
            )
            entry["installations"] = [
                normalize_installation(item)
                for item in raw_installations
                if isinstance(item, dict)
            ]
        except GitHubError as exc:
            entry["installations_error"] = exc.message
        cred_params: dict[str, Any] = {}
        if not all_members and login:
            cred_params["login"] = login
        try:
            raw_creds = client.get_all(
                f"/orgs/{org['login']}/credential-authorizations",
                cred_params,
            )
            entry["credential_authorizations"] = [
                normalize_credential(item) for item in raw_creds if isinstance(item, dict)
            ]
        except GitHubError as exc:
            if exc.status == 404:
                entry["credential_authorizations_error"] = (
                    "no SAML credential-authorization list for this organization"
                )
            else:
                entry["credential_authorizations_error"] = exc.message
        report_orgs.append(entry)
    return {
        "login": login,
        "role_note": role_note,
        "orgs": report_orgs,
        "not_in_api": list(GAPS),
    }


def _permission_text(permissions: dict[str, Any]) -> str:
    if not permissions:
        return "no permissions reported"
    preferred = (
        "contents",
        "administration",
        "secrets",
        "workflows",
        "pull_requests",
        "metadata",
        "members",
        "organization_administration",
    )
    keys = [key for key in preferred if key in permissions]
    keys.extend(sorted(key for key in permissions if key not in keys))
    return ", ".join(f"{key}:{permissions[key]}" for key in keys)


def format_summary(report: dict[str, Any]) -> str:
    lines = [f"Authenticated as {report.get('login') or 'unknown'}", ""]
    if report.get("role_note"):
        lines.append(str(report["role_note"]))
        lines.append("")
    orgs = report.get("orgs") or []
    if not orgs:
        lines.append("No matching organization memberships.")
        lines.append("")
    for org in orgs:
        role = org.get("role") or "role unknown"
        lines.append(f"{org.get('login')} ({role})")
        if org.get("installations_error"):
            lines.append(f"  GitHub Apps: {org['installations_error']}")
        else:
            installations = org.get("installations") or []
            lines.append(f"  GitHub Apps: {len(installations)}")
            for app in installations:
                state = "suspended" if app.get("suspended") else app.get("repository_selection")
                name = app.get("app_slug") or f"app {app.get('app_id')}"
                lines.append(f"    {name}  {state}  {_permission_text(app.get('permissions') or {})}")
                if app.get("html_url"):
                    lines.append(f"      {app['html_url']}")
        if org.get("credential_authorizations_error"):
            lines.append(f"  SAML-authorized credentials: {org['credential_authorizations_error']}")
        else:
            creds = org.get("credential_authorizations") or []
            lines.append(f"  SAML-authorized credentials: {len(creds)}")
            for cred in creds:
                last = cred.get("token_last_eight")
                tail = f" ending {last}" if last else ""
                title = cred.get("authorized_credential_note") or cred.get("authorized_credential_title") or ""
                title_bit = f" ({title})" if title else ""
                scopes = ",".join(cred.get("scopes") or [])
                scope_bit = f" scopes={scopes}" if scopes else ""
                lines.append(
                    f"    {cred.get('credential_type') or 'credential'}{tail}{title_bit}{scope_bit}"
                )
        lines.append("")
    lines.append("Not available from this token:")
    for gap in report.get("not_in_api") or []:
        lines.append(f"  - {gap}")
    return "\n".join(lines).rstrip() + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="List GitHub Apps and SAML credentials your account has granted on orgs you own."
    )
    parser.add_argument("--token", default=None, help="GitHub token. Prefer GH_TOKEN instead.")
    parser.add_argument("--org", default=None, help="Limit the report to one organization login.")
    parser.add_argument(
        "--all-members",
        action="store_true",
        help="List every member's SAML-authorized credential, not only yours.",
    )
    parser.add_argument(
        "--format",
        choices=("summary", "json"),
        default="summary",
        help="summary (default) or json. Both stay on stdout and omit the token.",
    )
    args = parser.parse_args(argv)
    token = resolve_token(args.token)
    if not token:
        print(
            "No GitHub token. Set GH_TOKEN, or run `gh auth login` and retry.",
            file=sys.stderr,
        )
        return 2
    if args.org and not re.fullmatch(r"[A-Za-z0-9-]+", args.org):
        print("Organization login must be letters, numbers, and hyphens.", file=sys.stderr)
        return 2
    client = GitHubClient(token)
    try:
        report = collect(client, org_filter=args.org, all_members=args.all_members)
    except GitHubError as exc:
        print(scrub(str(exc), token), file=sys.stderr)
        return 1
    if args.format == "json":
        print(json.dumps(report, indent=2, ensure_ascii=False))
    else:
        print(format_summary(report), end="")
    return 0


if __name__ == "__main__":
    sys.exit(main())
