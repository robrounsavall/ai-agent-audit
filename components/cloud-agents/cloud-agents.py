"""
Opt-in, read-only inventory of the user's Cursor cloud agents.

Not part of `aiscan all`. The offline collectors never call the network.
This command does, and only as follows:

- HTTPS GET to https://api.cursor.com (the official Cloud Agents API).
- Authorization is the user-supplied CURSOR_API_KEY (Bearer). The key is
  never printed, logged, or written to evidence.
- No other HTTP method is issued. Hosts other than api.cursor.com are
  refused, including pagination cursors and redirects.
- GET /v1/repositories is refused (strict rate limit, not needed).
- The enterprise Admin API is not called, so dollar cost is not collected.
- The Cursor IDE session token and cursor.com/api/dashboard are not read.

Usage:
    CURSOR_API_KEY=crsr_... python cloud-agents.py --evidence-root ./audit-run
"""

from __future__ import annotations

import argparse
import email.utils
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter
from datetime import datetime, timedelta, timezone
from typing import Any, Callable

from common import (
    add_base_args,
    finish_collector,
    make_envelope,
    make_finding,
    sanitize_text,
    sha256_full,
    validate_evidence_root,
)

__version__ = "1.0.0"
COLLECTOR = "cloud-agents"

API_HOST = "api.cursor.com"
API_BASE = "https://api.cursor.com"
API_SCOPE = "https://api.cursor.com/v1/agents"

# Stay near 20 requests/minute. The public spec does not publish one global
# budget; /v1/repositories is much stricter and is never called.
MIN_INTERVAL_SECONDS = 3.0
MAX_RETRY_SLEEP = 120.0
DEFAULT_BACKOFF = 3.0
MAX_ATTEMPTS = 4
MAX_PAGES = 50
LONG_LIVED_DAYS = 30
PAGE_LIMIT = 100

_ID = r"[A-Za-z0-9][A-Za-z0-9_-]{0,200}"
_ID_RE = re.compile(rf"^{_ID}$")
_PATH_RE = re.compile(
    rf"^(?:/v1/me"
    rf"|/v1/agents"
    rf"|/v1/agents/{_ID}"
    rf"|/v1/agents/{_ID}/runs/{_ID}"
    rf"|/v1/agents/{_ID}/usage)$"
)
_CURSOR_KEY_RE = re.compile(r"crsr_[A-Za-z0-9_\-]{8,}")
_RUNNING = {"CREATING", "RUNNING"}

HttpGet = Callable[[str, str], tuple[int, dict[str, str], bytes]]

LIMITS: tuple[str, ...] = (
    "Dollar cost is not in the Cloud Agents API. Per-agent cost exists only on the enterprise Admin API, which this command does not call.",
    "Full conversations are not collected. Run result text is omitted unless --include-run-result (aiscan -IncludeRunResult), and then it follows AISCAN_REDACT.",
    "Personal user API keys cannot be scoped to read-only. The same key can create or delete agents. This command only sends HTTPS GET requests to api.cursor.com.",
    "Pull request open, merged, or closed state is not in the API response. This command records prUrl values and does not call GitHub.",
    "GET /v1/repositories is not called. Repository URLs come only from each agent's repos and run git branches.",
    "The Cursor IDE session token and cursor.com/api/dashboard endpoints are not read or called. Auth is the user-supplied CURSOR_API_KEY only.",
)

MISSING_KEY_MESSAGE = """\
Cursor cloud agent inventory did not run: CURSOR_API_KEY is not set.

Create a user API key at Cursor Dashboard -> API Keys, then:
  PowerShell:  $env:CURSOR_API_KEY = "crsr_..."
               .\\aiscan.ps1 cloud-agents

This command is opt-in and is not part of aiscan all. It sends HTTPS GET
requests only to https://api.cursor.com using that key as a Bearer token.
The key is never printed or written to evidence.

It does not read the Cursor IDE session token, and it does not call
cursor.com/api/dashboard. Personal API keys cannot be limited to read-only;
this tool still refuses every method except GET.
"""


class CursorApiError(Exception):
    def __init__(self, status: int, message: str) -> None:
        self.status = status
        super().__init__(message)


def scrub(text: str, api_key: str | None) -> str:
    """Remove the live key and any crsr_ token from text that might be stored."""
    if not text:
        return text
    if api_key and len(api_key) >= 8 and api_key in text:
        text = text.replace(api_key, "[redacted-key]")
    return _CURSOR_KEY_RE.sub("[redacted-key]", text)


def scrub_obj(value: Any, api_key: str | None) -> Any:
    if isinstance(value, str):
        return scrub(value, api_key)
    if isinstance(value, list):
        return [scrub_obj(item, api_key) for item in value]
    if isinstance(value, dict):
        return {
            scrub(key, api_key) if isinstance(key, str) else key: scrub_obj(item, api_key)
            for key, item in value.items()
        }
    return value


def enforce_request(method: str, url: str) -> None:
    """GET only, and only https://api.cursor.com paths this inventory needs."""
    verb = (method or "").upper()
    if verb != "GET":
        raise CursorApiError(0, f"refused non-GET method {verb or 'UNKNOWN'}")
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme != "https":
        raise CursorApiError(0, "refused non-https URL")
    if parsed.username or parsed.password:
        raise CursorApiError(0, "refused URL with userinfo")
    if parsed.fragment:
        raise CursorApiError(0, "refused URL fragment")
    host = parsed.hostname
    if host != API_HOST:
        raise CursorApiError(0, f"refused host {host or 'unknown'}")
    if parsed.port not in (None, 443):
        raise CursorApiError(0, "refused port")
    path = parsed.path or "/"
    if path == "/v1/repositories" or path.startswith("/v1/repositories/"):
        raise CursorApiError(0, "refused /v1/repositories")
    if not _PATH_RE.match(path):
        raise CursorApiError(0, "refused path")


def _is_absolute_url(value: str) -> bool:
    lowered = value.strip().lower()
    return "://" in lowered or lowered.startswith("//")


def build_url(path: str, params: list[tuple[str, str]] | None = None) -> str:
    if not path.startswith("/") or "://" in path or path.startswith("//"):
        raise CursorApiError(0, "refused path")
    query = urllib.parse.urlencode(params or [])
    url = API_BASE + path + (("?" + query) if query else "")
    enforce_request("GET", url)
    return url


def _header(headers: dict[str, str], name: str) -> str:
    for key, value in headers.items():
        if key.lower() == name.lower():
            return str(value).strip()
    return ""


def _error_message(body: bytes, api_key: str) -> str:
    text = body.decode("utf-8", errors="replace")[:500]
    message = "request failed"
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        data = None
    if isinstance(data, dict):
        err = data.get("error")
        if isinstance(err, dict) and err.get("message"):
            message = str(err["message"])
        elif data.get("message"):
            message = str(data["message"])
        elif data.get("code"):
            message = str(data["code"])
    elif text.strip():
        message = text.strip()
    return scrub(message, api_key)[:200]


class _StayOnApi(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        enforce_request("GET", newurl)
        redirected = super().redirect_request(req, fp, code, msg, headers, newurl)
        if redirected is not None and redirected.get_method() != "GET":
            raise CursorApiError(0, "refused non-GET redirect")
        return redirected


def http_get(url: str, api_key: str, timeout: int = 30) -> tuple[int, dict[str, str], bytes]:
    """Real transport. GET only; the key is a header and is not written."""
    enforce_request("GET", url)
    request = urllib.request.Request(
        url,
        headers={
            "Authorization": f"Bearer {api_key}",
            "Accept": "application/json",
            "User-Agent": "ai-agent-audit-cloud-agents",
        },
        method="GET",
    )
    opener = urllib.request.build_opener(_StayOnApi)
    try:
        with opener.open(request, timeout=timeout) as response:
            raw_headers = dict(response.headers.items())
            return response.status, raw_headers, response.read()
    except urllib.error.HTTPError as exc:
        raw = exc.read() if exc.fp is not None else b""
        headers = dict(exc.headers.items()) if exc.headers else {}
        return exc.code, headers, raw
    except urllib.error.URLError as exc:
        raise CursorApiError(0, scrub(str(exc.reason), api_key)) from None


class CursorClient:
    """Scriptable GET client. Tests pass a fake transport and a fake clock."""

    def __init__(
        self,
        api_key: str,
        transport: HttpGet | None = None,
        *,
        sleep: Callable[[float], None] = time.sleep,
        monotonic: Callable[[], float] = time.monotonic,
        wall: Callable[[], datetime] | None = None,
        min_interval: float = MIN_INTERVAL_SECONDS,
        max_attempts: int = MAX_ATTEMPTS,
        max_pages: int = MAX_PAGES,
    ) -> None:
        self._api_key = api_key
        self._transport = transport or http_get
        self._sleep = sleep
        self._monotonic = monotonic
        self._wall = wall or (lambda: datetime.now(timezone.utc))
        self.min_interval = min_interval
        self.max_attempts = max_attempts
        self.max_pages = max_pages
        self._last_request: float | None = None

    def __repr__(self) -> str:
        return "CursorClient(api_key='[redacted-key]')"

    def request(self, method: str, url: str) -> tuple[int, dict[str, str], bytes]:
        enforce_request(method, url)
        for attempt in range(self.max_attempts):
            self._throttle()
            try:
                status, headers, body = self._transport(url, self._api_key)
            except CursorApiError:
                raise
            except OSError as exc:
                raise CursorApiError(0, scrub(str(exc), self._api_key)) from None
            headers = headers or {}
            if status != 429:
                return status, headers, body
            if attempt >= self.max_attempts - 1:
                break
            self._sleep(self._retry_delay(headers))
        raise CursorApiError(429, "rate limited")

    def get_json(self, url: str) -> Any:
        status, _headers, body = self.request("GET", url)
        if status != 200:
            raise CursorApiError(status, _error_message(body, self._api_key))
        try:
            return json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise CursorApiError(status, "unreadable response") from exc

    def get_path(self, path: str, params: list[tuple[str, str]] | None = None) -> Any:
        return self.get_json(build_url(path, params))

    def list_agents(self) -> list[dict[str, Any]]:
        items: list[dict[str, Any]] = []
        cursor: str | None = None
        seen: set[str] = set()
        for _page in range(self.max_pages):
            if cursor is None:
                page = self.get_path(
                    "/v1/agents",
                    [("limit", str(PAGE_LIMIT)), ("includeArchived", "true")],
                )
            elif _is_absolute_url(cursor):
                # Host, method, and path are checked again inside request().
                enforce_request("GET", cursor)
                page = self.get_json(cursor)
            else:
                page = self.get_path(
                    "/v1/agents",
                    [
                        ("limit", str(PAGE_LIMIT)),
                        ("includeArchived", "true"),
                        ("cursor", cursor),
                    ],
                )
            if not isinstance(page, dict) or not isinstance(page.get("items"), list):
                raise CursorApiError(0, "unexpected agent list payload")
            for item in page["items"]:
                if isinstance(item, dict):
                    items.append(item)
            nxt = page.get("nextCursor")
            if nxt is None or nxt == "":
                return items
            if not isinstance(nxt, str):
                raise CursorApiError(0, "unexpected pagination cursor")
            if nxt in seen:
                raise CursorApiError(0, "repeated pagination cursor")
            seen.add(nxt)
            cursor = nxt
        raise CursorApiError(0, "too many agent pages")

    def _throttle(self) -> None:
        now = self._monotonic()
        if self._last_request is not None and self.min_interval > 0:
            elapsed = now - self._last_request
            if elapsed < self.min_interval:
                self._sleep(self.min_interval - elapsed)
                now = self._monotonic()
        self._last_request = now

    def _retry_delay(self, headers: dict[str, str]) -> float:
        raw = _header(headers, "Retry-After")
        if not raw:
            return DEFAULT_BACKOFF
        if re.fullmatch(r"\d+(?:\.\d+)?", raw):
            delay = float(raw)
        else:
            try:
                parsed = email.utils.parsedate_to_datetime(raw)
            except (TypeError, ValueError, IndexError, OverflowError):
                return DEFAULT_BACKOFF
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            delay = (parsed - self._wall()).total_seconds()
        if delay < 0:
            delay = 0.0
        if delay > MAX_RETRY_SLEEP:
            return MAX_RETRY_SLEEP
        return delay


def _safe_id(value: Any) -> str | None:
    if isinstance(value, str) and _ID_RE.fullmatch(value):
        return value
    return None


def _label(value: Any, api_key: str) -> str:
    if value is None:
        return ""
    return scrub(str(value).strip(), api_key)


def _text(value: Any, api_key: str) -> str:
    if value is None:
        return ""
    return scrub(sanitize_text(str(value).strip()), api_key)


def _as_int(value: Any) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    if value < 0:
        return None
    return value


def _as_bool(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    return None


def _token_block(raw: Any) -> dict[str, int] | None:
    if not isinstance(raw, dict):
        return None
    fields = {
        "input_tokens": _as_int(raw.get("inputTokens")),
        "output_tokens": _as_int(raw.get("outputTokens")),
        "cache_write_tokens": _as_int(raw.get("cacheWriteTokens")),
        "cache_read_tokens": _as_int(raw.get("cacheReadTokens")),
        "total_tokens": _as_int(raw.get("totalTokens")),
    }
    if all(value is None for value in fields.values()):
        return None
    numbers = {key: (value if value is not None else 0) for key, value in fields.items()}
    if raw.get("totalTokens") is None:
        numbers["total_tokens"] = (
            numbers["input_tokens"]
            + numbers["output_tokens"]
            + numbers["cache_write_tokens"]
            + numbers["cache_read_tokens"]
        )
    return numbers


def _parse_time(value: str) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def _env_from(source: dict[str, Any]) -> dict[str, Any]:
    env = source.get("env")
    return env if isinstance(env, dict) else {}


def _load_agent(
    client: CursorClient,
    summary: dict[str, Any],
    *,
    include_run_result: bool,
) -> dict[str, Any]:
    api_key = client._api_key
    agent_id = _safe_id(summary.get("id"))
    errors: list[str] = []
    detail: dict[str, Any] = {}
    run: dict[str, Any] = {}
    usage: dict[str, Any] = {}
    usage_unavailable = False

    if agent_id is None:
        errors.append("refused agent id")
    else:
        try:
            loaded = client.get_path(f"/v1/agents/{agent_id}")
            if isinstance(loaded, dict):
                detail = loaded
            else:
                errors.append("unexpected agent payload")
        except CursorApiError as exc:
            errors.append(f"agent HTTP {exc.status}: {exc}")
        run_id = _safe_id(detail.get("latestRunId") or summary.get("latestRunId"))
        if run_id:
            try:
                loaded_run = client.get_path(f"/v1/agents/{agent_id}/runs/{run_id}")
                if isinstance(loaded_run, dict):
                    run = loaded_run
                else:
                    errors.append("unexpected run payload")
            except CursorApiError as exc:
                errors.append(f"run HTTP {exc.status}: {exc}")
        try:
            loaded_usage = client.get_path(f"/v1/agents/{agent_id}/usage")
            if isinstance(loaded_usage, dict):
                usage = loaded_usage
            else:
                errors.append("unexpected usage payload")
        except CursorApiError as exc:
            if exc.status in (403, 404):
                usage_unavailable = True
            else:
                errors.append(f"usage HTTP {exc.status}: {exc}")

    source = detail or summary
    env = _env_from(source) or _env_from(summary)
    repos: list[dict[str, str]] = []
    raw_repos = source.get("repos") if isinstance(source.get("repos"), list) else []
    for repo in raw_repos:
        if not isinstance(repo, dict):
            continue
        repos.append(
            {
                "url": _text(repo.get("url"), api_key),
                "starting_ref": _text(repo.get("startingRef"), api_key),
                "pr_url": _text(repo.get("prUrl"), api_key),
            }
        )

    branches: list[dict[str, str]] = []
    git = run.get("git") if isinstance(run.get("git"), dict) else {}
    raw_branches = git.get("branches") if isinstance(git.get("branches"), list) else []
    for branch in raw_branches:
        if not isinstance(branch, dict):
            continue
        branches.append(
            {
                "repo_url": _text(branch.get("repoUrl"), api_key),
                "branch": _text(branch.get("branch"), api_key),
                "pr_url": _text(branch.get("prUrl"), api_key),
            }
        )

    status = _label(source.get("status") if source.get("status") is not None else summary.get("status"), api_key)
    latest: dict[str, Any] | None = None
    if run:
        latest = {
            "id": _label(run.get("id"), api_key),
            "status": _label(run.get("status"), api_key) or "UNKNOWN",
            "duration_ms": _as_int(run.get("durationMs")),
        }
        if include_run_result and isinstance(run.get("result"), str):
            latest["result"] = _text(run["result"], api_key)
    elif _safe_id(summary.get("latestRunId")) and agent_id is None:
        latest = None

    record: dict[str, Any] = {
        "id": _label(summary.get("id"), api_key),
        "name": _text(source.get("name") if source.get("name") is not None else summary.get("name"), api_key),
        "status": status or "UNKNOWN",
        "url": _text(source.get("url") or summary.get("url"), api_key),
        "env_type": _label(env.get("type"), api_key),
        "env_name": _text(env.get("name"), api_key),
        "created_at": _label(source.get("createdAt") or summary.get("createdAt"), api_key),
        "updated_at": _label(source.get("updatedAt") or summary.get("updatedAt"), api_key),
        "repos": repos,
        "work_on_current_branch": _as_bool(source.get("workOnCurrentBranch")),
        "auto_create_pr": _as_bool(source.get("autoCreatePR")),
        "branches": branches,
        "latest_run": latest,
        "tokens": _token_block(usage.get("totalUsage")),
        "usage_unavailable": usage_unavailable,
    }
    if errors:
        record["error"] = _text("; ".join(errors), api_key)[:300]
    return record


def _has_repos(agent: dict[str, Any]) -> bool:
    return any(str(repo.get("url") or "").strip() for repo in agent.get("repos") or [])


def _has_pr(agent: dict[str, Any]) -> bool:
    for repo in agent.get("repos") or []:
        if str(repo.get("pr_url") or "").strip():
            return True
    for branch in agent.get("branches") or []:
        if str(branch.get("pr_url") or "").strip():
            return True
    return False


def _is_running(agent: dict[str, Any]) -> bool:
    run = agent.get("latest_run") or {}
    return str(run.get("status") or "").upper() in _RUNNING


def _is_active_status(agent: dict[str, Any]) -> bool:
    return str(agent.get("status") or "").casefold() == "active"


def _is_archived(agent: dict[str, Any]) -> bool:
    return str(agent.get("status") or "").casefold() == "archived"


def _live_writer(agent: dict[str, Any]) -> bool:
    if not _has_repos(agent):
        return False
    return _is_active_status(agent) or _is_running(agent)


def _sample_names(agents: list[dict[str, Any]], limit: int = 3) -> str:
    parts: list[str] = []
    for agent in agents[:limit]:
        name = agent.get("name") or agent.get("id") or "(unnamed)"
        status = agent.get("status") or "UNKNOWN"
        run = (agent.get("latest_run") or {}).get("status") or ""
        run_bit = f" run={run}" if run else ""
        repos = [repo.get("url") for repo in agent.get("repos") or [] if repo.get("url")]
        repo_bit = f" repo={repos[0]}" if repos else ""
        if len(repos) > 1:
            repo_bit += f" +{len(repos) - 1}"
        parts.append(f"{name} [{status}{run_bit}{repo_bit}]")
    extra = len(agents) - limit
    if extra > 0:
        parts.append(f"+{extra} more")
    return "; ".join(parts)


def _span(agents: list[dict[str, Any]]) -> tuple[str, str]:
    created = [agent.get("created_at") or "" for agent in agents if agent.get("created_at")]
    updated = [agent.get("updated_at") or "" for agent in agents if agent.get("updated_at")]
    return (min(created) if created else ""), (max(updated) if updated else "")


def _findings(agents: list[dict[str, Any]], now: datetime) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    current_branch = [
        agent for agent in agents if _live_writer(agent) and agent.get("work_on_current_branch") is True
    ]
    other_writers = [
        agent for agent in agents if _live_writer(agent) and agent.get("work_on_current_branch") is not True
    ]
    if current_branch:
        first, last = _span(current_branch)
        findings.append(
            make_finding(
                "cloud_agents.active_current_branch",
                "high",
                "Source Code Egress",
                "Active cloud agent can push to the repository's current branch",
                evidence_count=len(current_branch),
                first_seen=first,
                last_seen=last,
                sample_redacted=_sample_names(current_branch),
                tags=["cloud_agent", "repo_write", "current_branch"],
            )
        )
    if other_writers:
        first, last = _span(other_writers)
        findings.append(
            make_finding(
                "cloud_agents.active_repo_write",
                "medium",
                "Source Code Egress",
                "Active cloud agent has write access to a repository",
                evidence_count=len(other_writers),
                first_seen=first,
                last_seen=last,
                sample_redacted=_sample_names(other_writers),
                tags=["cloud_agent", "repo_write", "active"],
            )
        )

    long_lived: list[dict[str, Any]] = []
    for agent in agents:
        if _is_archived(agent):
            continue
        created = _parse_time(str(agent.get("created_at") or ""))
        if created is None:
            continue
        if now - created >= timedelta(days=LONG_LIVED_DAYS):
            long_lived.append(agent)
    if long_lived:
        first, last = _span(long_lived)
        severity = "medium" if any(_has_repos(agent) for agent in long_lived) else "low"
        findings.append(
            make_finding(
                "cloud_agents.long_lived_unarchived",
                severity,
                "General Tooling",
                f"Cloud agent has stayed unarchived for more than {LONG_LIVED_DAYS} days",
                evidence_count=len(long_lived),
                first_seen=first,
                last_seen=last,
                sample_redacted=_sample_names(long_lived),
                tags=["cloud_agent", "unarchived", "long_lived"],
            )
        )

    unread = [agent for agent in agents if agent.get("error")]
    if unread:
        findings.append(
            make_finding(
                "cloud_agents.read_error",
                "low",
                "General Tooling",
                "Cloud agent metadata could not be fully read",
                evidence_count=len(unread),
                sample_redacted=_sample_names(unread),
                tags=["cloud_agent", "collection_gap"],
            )
        )

    findings.append(
        make_finding(
            "cloud_agents.coverage",
            "low",
            "General Tooling",
            "Cloud agent inventory omits cost, conversations, and key scope",
            evidence_count=1,
            sample_redacted=" ".join(LIMITS),
            tags=["coverage_gap", "cloud_agent"],
        )
    )
    return findings


def _summary(agents: list[dict[str, Any]], *, include_run_result: bool, key_configured: bool) -> dict[str, Any]:
    statuses = [str(agent.get("status") or "UNKNOWN") for agent in agents]
    counts = Counter(statuses)
    total_tokens = 0
    usage_unavailable = 0
    for agent in agents:
        if agent.get("usage_unavailable"):
            usage_unavailable += 1
        tokens = agent.get("tokens") or {}
        total_tokens += int(tokens.get("total_tokens") or 0)
    return {
        "key_configured": key_configured,
        "api": API_BASE,
        "total_agents": len(agents),
        "agents_active": sum(1 for agent in agents if _is_active_status(agent)),
        "agents_running": sum(1 for agent in agents if _is_running(agent)),
        "agents_with_prs": sum(1 for agent in agents if _has_pr(agent)),
        "total_tokens": total_tokens,
        "by_status": {status: counts[status] for status in sorted(counts)},
        "agent_errors": sum(1 for agent in agents if agent.get("error")),
        "usage_unavailable": usage_unavailable,
        "include_run_result": include_run_result,
    }


def collect(
    client: CursorClient,
    *,
    include_run_result: bool = False,
    now: datetime | None = None,
) -> dict[str, Any]:
    """List every agent and attach detail, latest run, and token totals."""
    clock = now or datetime.now(timezone.utc)
    me = client.get_path("/v1/me")
    if not isinstance(me, dict):
        raise CursorApiError(0, "unexpected /v1/me payload")
    # /v1/me identifies the key (name, email). None of that is stored.
    summaries = client.list_agents()
    agents = [
        _load_agent(client, summary, include_run_result=include_run_result)
        for summary in summaries
    ]
    return {
        "agents": agents,
        "summary": _summary(agents, include_run_result=include_run_result, key_configured=True),
        "findings": _findings(agents, clock),
        "limits": list(LIMITS),
    }


def _empty_envelope(*, include_run_result: bool) -> dict[str, Any]:
    envelope = make_envelope(
        COLLECTOR,
        __version__,
        sha256_full(API_SCOPE),
        platform_detected=False,
    )
    envelope["summary"] = _summary([], include_run_result=include_run_result, key_configured=False)
    envelope["agents"] = []
    envelope["limits"] = list(LIMITS)
    return envelope


def _scanned_envelope(result: dict[str, Any]) -> dict[str, Any]:
    envelope = make_envelope(
        COLLECTOR,
        __version__,
        sha256_full(API_SCOPE),
        platform_detected=True,
    )
    envelope["summary"] = result["summary"]
    envelope["findings"] = result["findings"]
    envelope["agents"] = result["agents"]
    envelope["limits"] = result["limits"]
    return envelope


def _key_leaked(envelope: dict[str, Any], api_key: str) -> bool:
    if len(api_key) < 8:
        return False
    return api_key in json.dumps(envelope, ensure_ascii=False)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Read-only inventory of Cursor cloud agents (official API, GET only)."
    )
    add_base_args(parser)
    parser.add_argument(
        "--include-run-result",
        action="store_true",
        help="Store the latest run result text. Omitted by default. Honors AISCAN_REDACT.",
    )
    return parser


def main(
    argv: list[str] | None = None,
    environ: dict[str, str] | None = None,
    client_factory: Callable[[str], CursorClient] | None = None,
) -> int:
    args = build_parser().parse_args(argv)
    env = os.environ if environ is None else environ
    api_key = (env.get("CURSOR_API_KEY") or "").strip()
    evidence_root = validate_evidence_root(args.evidence_root)
    if not api_key:
        print(MISSING_KEY_MESSAGE, file=sys.stderr)
        finish_collector(
            _empty_envelope(include_run_result=args.include_run_result),
            evidence_root,
            dry_run=args.dry_run,
        )
        return 0

    client = (
        CursorClient(api_key)
        if client_factory is None
        else client_factory(api_key)
    )
    try:
        result = collect(client, include_run_result=args.include_run_result)
    except CursorApiError as exc:
        print(scrub(str(exc), api_key), file=sys.stderr)
        if exc.status == 401:
            print(
                "The Cursor API rejected CURSOR_API_KEY. The key was not printed.",
                file=sys.stderr,
            )
        return 1

    envelope = scrub_obj(_scanned_envelope(result), api_key)
    if _key_leaked(envelope, api_key):
        print("Refusing to write evidence that contains the API key.", file=sys.stderr)
        return 1
    finish_collector(envelope, evidence_root, dry_run=args.dry_run)
    return 0


if __name__ == "__main__":
    sys.exit(main())
