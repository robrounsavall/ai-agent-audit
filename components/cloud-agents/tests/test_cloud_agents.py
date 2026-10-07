"""Unit tests for the Cursor cloud-agent inventory. No network."""

from __future__ import annotations

import importlib.util
import io
import json
import os
import tempfile
import unittest
import urllib.parse
from contextlib import redirect_stderr
from datetime import datetime, timedelta, timezone
from email.utils import format_datetime
from pathlib import Path

import bootstrap  # noqa: E402,F401

_mod_path = Path(__file__).resolve().parent.parent / "cloud-agents.py"
_spec = importlib.util.spec_from_file_location("cloud_agents_mod", _mod_path)
ca = importlib.util.module_from_spec(_spec)
assert _spec.loader is not None
_spec.loader.exec_module(ca)

KEY = "crsr_unit_test_key_do_not_use"
NOW = datetime(2026, 10, 1, tzinfo=timezone.utc)
RECENT = "2026-09-20T12:00:00Z"
OLD = "2026-08-01T12:00:00Z"


class Clock:
    def __init__(self) -> None:
        self.mono = 0.0
        self.wall_dt = datetime(2026, 1, 1, tzinfo=timezone.utc)
        self.slept: list[float] = []

    def monotonic(self) -> float:
        return self.mono

    def wall(self) -> datetime:
        return self.wall_dt

    def sleep(self, seconds: float) -> None:
        self.slept.append(seconds)
        self.mono += seconds
        self.wall_dt += timedelta(seconds=seconds)


def _json(body: object) -> bytes:
    return json.dumps(body).encode("utf-8")


def _summary(agent_id: str, status: str, *, name: str, created: str, run_id: str | None) -> dict:
    item = {
        "id": agent_id,
        "name": name,
        "status": status,
        "env": {"type": "cloud"},
        "url": f"https://cursor.com/agents/{agent_id}",
        "createdAt": created,
        "updatedAt": created,
    }
    if run_id:
        item["latestRunId"] = run_id
    return item


def _detail(summary: dict, **extra: object) -> dict:
    detail = dict(summary)
    detail.update(extra)
    return detail


class Scripted:
    """Path router. Responses may be a tuple or a zero-arg callable returning one."""

    def __init__(self, routes: dict[str, object], key: str = KEY) -> None:
        self.routes = routes
        self.key = key
        self.calls: list[str] = []

    def __call__(self, url: str, api_key: str):
        self.calls.append(url)
        if api_key != self.key:
            raise AssertionError("unexpected key passed to transport")
        parsed = urllib.parse.urlsplit(url)
        query = urllib.parse.parse_qs(parsed.query)
        cursor = query.get("cursor", [None])[0]
        if parsed.path == "/v1/agents" and cursor:
            key = f"/v1/agents?cursor={cursor}"
        else:
            key = parsed.path
        if key not in self.routes:
            raise AssertionError(f"unexpected URL {url}")
        route = self.routes[key]
        status, body, headers = route() if callable(route) else route
        if isinstance(body, (dict, list)):
            body = _json(body)
        return status, headers or {}, body


def _client(routes: dict[str, object], **kwargs) -> tuple[ca.CursorClient, Scripted]:
    scripted = Scripted(routes)
    clock = kwargs.pop("clock", None)
    client = ca.CursorClient(
        scripted.key,
        scripted,
        sleep=clock.sleep if clock else (lambda _seconds: None),
        monotonic=clock.monotonic if clock else (lambda: 0.0),
        wall=clock.wall if clock else (lambda: NOW),
        min_interval=kwargs.pop("min_interval", 0),
        **kwargs,
    )
    return client, scripted


def _world() -> dict[str, object]:
    """Six agents across two pages, plus one unsafe id that must not be fetched."""
    active = _summary("bc-active", "ACTIVE", name="Readme agent", created=RECENT, run_id="run-active")
    branch = _summary("bc-branch", "ACTIVE", name="Branch agent", created=RECENT, run_id="run-branch")
    idle = _summary("bc-old", "IDLE", name="Old idle agent", created=OLD, run_id="run-old")
    archived = _summary("bc-archived", "ARCHIVED", name="Done agent", created=OLD, run_id="run-done")
    weird = _summary("bc-weird", "FROBNICATED", name="Weird status", created=OLD, run_id=None)
    quiet = _summary("bc-quiet", "Active", name="No repo agent", created=RECENT, run_id="run-quiet")
    return {
        "/v1/me": (
            200,
            {
                "apiKeyName": "laptop",
                "userEmail": "person@example.com",
                "userFirstName": "Ada",
                "userId": 42,
            },
            None,
        ),
        "/v1/agents": (
            200,
            {"items": [active, branch, idle, archived], "nextCursor": "page-2"},
            None,
        ),
        "/v1/agents?cursor=page-2": (
            200,
            {"items": [weird, quiet]},
            None,
        ),
        "/v1/agents/bc-active": (
            200,
            _detail(
                active,
                repos=[{"url": "https://github.com/example/demo", "startingRef": "main"}],
                workOnCurrentBranch=False,
                autoCreatePR=True,
            ),
            None,
        ),
        "/v1/agents/bc-branch": (
            200,
            _detail(
                branch,
                repos=[{"url": "https://github.com/example/demo", "startingRef": "release"}],
                workOnCurrentBranch=True,
                autoCreatePR=False,
            ),
            None,
        ),
        "/v1/agents/bc-old": (
            200,
            _detail(
                idle,
                repos=[{"url": "https://github.com/example/legacy", "startingRef": "main"}],
                workOnCurrentBranch=False,
                autoCreatePR=False,
            ),
            None,
        ),
        "/v1/agents/bc-archived": (
            200,
            _detail(
                archived,
                repos=[{"url": "https://github.com/example/demo", "startingRef": "main"}],
                workOnCurrentBranch=False,
            ),
            None,
        ),
        "/v1/agents/bc-weird": (
            200,
            _detail(weird, repos=[], workOnCurrentBranch=False),
            None,
        ),
        "/v1/agents/bc-quiet": (
            200,
            _detail(quiet, repos=[], workOnCurrentBranch=False),
            None,
        ),
        "/v1/agents/bc-active/runs/run-active": (
            200,
            {
                "id": "run-active",
                "agentId": "bc-active",
                "status": "FINISHED",
                "createdAt": RECENT,
                "updatedAt": RECENT,
                "durationMs": 12000,
                "result": "RESULTMARKER should stay out unless asked",
                "git": {
                    "branches": [
                        {
                            "repoUrl": "github.com/example/demo",
                            "branch": "cursor/readme",
                            "prUrl": "https://github.com/example/demo/pull/7",
                        }
                    ]
                },
            },
            None,
        ),
        "/v1/agents/bc-branch/runs/run-branch": (
            200,
            {
                "id": "run-branch",
                "status": "RUNNING",
                "createdAt": RECENT,
                "updatedAt": RECENT,
                "result": "still going",
                "git": {"branches": [{"repoUrl": "github.com/example/demo", "branch": "release"}]},
            },
            None,
        ),
        "/v1/agents/bc-old/runs/run-old": (
            200,
            {
                "id": "run-old",
                "status": "FINISHED",
                "durationMs": 5000,
                "git": {"branches": []},
            },
            None,
        ),
        "/v1/agents/bc-archived/runs/run-done": (
            200,
            {"id": "run-done", "status": "FINISHED", "durationMs": 1000, "git": {"branches": []}},
            None,
        ),
        "/v1/agents/bc-quiet/runs/run-quiet": (
            200,
            {"id": "run-quiet", "status": "EXPIRED", "durationMs": 10, "git": {"branches": []}},
            None,
        ),
        "/v1/agents/bc-active/usage": (200, {"totalUsage": _tokens(100), "runs": []}, None),
        "/v1/agents/bc-branch/usage": (200, {"totalUsage": _tokens(50), "runs": []}, None),
        "/v1/agents/bc-old/usage": (200, {"totalUsage": _tokens(25), "runs": []}, None),
        "/v1/agents/bc-archived/usage": (200, {"totalUsage": _tokens(5), "runs": []}, None),
        "/v1/agents/bc-weird/usage": (403, {"message": "feature_unavailable"}, None),
        "/v1/agents/bc-quiet/usage": (200, {"totalUsage": _tokens(1), "runs": []}, None),
    }


def _tokens(total: int) -> dict[str, int]:
    return {
        "inputTokens": total,
        "outputTokens": 0,
        "cacheWriteTokens": 0,
        "cacheReadTokens": 0,
        "totalTokens": total,
    }


class TestEnforceRequest(unittest.TestCase):
    def test_get_only_and_host_pin(self):
        calls: list[str] = []

        def transport(url: str, api_key: str):
            calls.append(url)
            return 200, {}, b"{}"

        client = ca.CursorClient(KEY, transport, min_interval=0, sleep=lambda _s: None)
        with self.assertRaises(ca.CursorApiError):
            client.request("POST", "https://api.cursor.com/v1/me")
        with self.assertRaises(ca.CursorApiError):
            client.request("DELETE", "https://api.cursor.com/v1/agents/bc-active")
        with self.assertRaises(ca.CursorApiError):
            client.request("PUT", "https://api.cursor.com/v1/me")
        with self.assertRaises(ca.CursorApiError):
            client.request("PATCH", "https://api.cursor.com/v1/me")
        for url in (
            "http://api.cursor.com/v1/me",
            "https://evil.example/v1/me",
            "https://api.cursor.com.evil.example/v1/me",
            "https://cursor.com/api/dashboard/get-me",
            "https://api.cursor.com:8443/v1/me",
            f"https://{KEY}@api.cursor.com/v1/me",
            "https://api.cursor.com/v1/repositories",
            "https://api.cursor.com/v1/agents/bc-active/runs",
        ):
            with self.assertRaises(ca.CursorApiError):
                client.request("GET", url)
        self.assertEqual(calls, [])
        status, _headers, _body = client.request("get", "https://api.cursor.com/v1/me")
        self.assertEqual(status, 200)
        self.assertEqual(calls, ["https://api.cursor.com/v1/me"])
        self.assertNotIn(KEY, repr(client))

    def test_http_get_refuses_before_opening_a_socket(self):
        with self.assertRaises(ca.CursorApiError) as caught:
            ca.http_get("https://evil.example/v1/me", KEY)
        self.assertNotIn(KEY, str(caught.exception))
        with self.assertRaises(ca.CursorApiError):
            ca.http_get("https://api.cursor.com/v1/repositories", KEY)

    def test_redirect_off_host_is_refused(self):
        handler = ca._StayOnApi()
        request = urllib_request("https://api.cursor.com/v1/me")
        with self.assertRaises(ca.CursorApiError):
            handler.redirect_request(request, None, 302, "Found", {}, "https://evil.example/steal")


def urllib_request(url: str):
    import urllib.request

    return urllib.request.Request(url, method="GET")


class TestPaginationAndThrottle(unittest.TestCase):
    def test_paginates_until_cursor_absent(self):
        client, scripted = _client(_world())
        result = ca.collect(client, now=NOW)
        ids = [agent["id"] for agent in result["agents"]]
        self.assertEqual(ids, ["bc-active", "bc-branch", "bc-old", "bc-archived", "bc-weird", "bc-quiet"])
        joined = "\n".join(scripted.calls)
        self.assertIn("cursor=page-2", joined)
        self.assertNotIn("/v1/repositories", joined)
        self.assertTrue(all(call.startswith("https://api.cursor.com/") for call in scripted.calls))

    def test_refuses_foreign_pagination_cursor(self):
        routes = {
            "/v1/me": (200, {"apiKeyName": "laptop"}, None),
            "/v1/agents": (
                200,
                {"items": [], "nextCursor": "https://evil.example/v1/agents?cursor=x"},
                None,
            ),
        }
        client, scripted = _client(routes)
        with self.assertRaises(ca.CursorApiError) as caught:
            ca.collect(client, now=NOW)
        self.assertIn("refused", str(caught.exception).lower())
        self.assertFalse(any("evil.example" in call for call in scripted.calls))

    def test_follows_same_host_pagination_url(self):
        nxt = "https://api.cursor.com/v1/agents?cursor=page-2&limit=100&includeArchived=true"
        routes = dict(_world())
        routes["/v1/agents"] = (200, {"items": [_summary("bc-active", "ARCHIVED", name="A", created=RECENT, run_id=None)], "nextCursor": nxt}, None)
        # The absolute cursor is fetched as a URL. Serve the second page from that exact path key.
        # Scripted keys absolute /v1/agents?cursor=page-2 the same way as an opaque cursor.
        client, scripted = _client(routes)
        result = ca.collect(client, now=NOW)
        self.assertGreaterEqual(len(result["agents"]), 2)
        self.assertTrue(any("cursor=page-2" in call for call in scripted.calls))

    def test_refuses_pagination_onto_repositories(self):
        routes = {
            "/v1/me": (200, {"apiKeyName": "laptop"}, None),
            "/v1/agents": (
                200,
                {"items": [], "nextCursor": "https://api.cursor.com/v1/repositories"},
                None,
            ),
        }
        client, scripted = _client(routes)
        with self.assertRaises(ca.CursorApiError) as caught:
            ca.collect(client, now=NOW)
        self.assertIn("repositories", str(caught.exception))
        self.assertFalse(any(urllib.parse.urlsplit(call).path.startswith("/v1/repositories") for call in scripted.calls))

    def test_unsafe_agent_id_is_not_requested(self):
        routes = {
            "/v1/me": (200, {"apiKeyName": "laptop"}, None),
            "/v1/agents": (
                200,
                {"items": [{"id": "../v1/repositories", "status": "ACTIVE", "name": "bad", "createdAt": RECENT}]},
                None,
            ),
        }
        client, scripted = _client(routes)
        result = ca.collect(client, now=NOW)
        self.assertEqual(result["agents"][0]["error"], "refused agent id")
        self.assertFalse(any("repositories" in call for call in scripted.calls))

    def test_429_honors_retry_after(self):
        clock = Clock()
        hits = {"n": 0}

        def flaky(url: str, api_key: str):
            path = urllib.parse.urlsplit(url).path
            if path == "/v1/agents":
                hits["n"] += 1
                if hits["n"] == 1:
                    return 429, {"Retry-After": "7"}, b'{"message":"slow down"}'
            return Scripted(_world())(url, api_key)

        client = ca.CursorClient(
            KEY,
            flaky,
            sleep=clock.sleep,
            monotonic=clock.monotonic,
            wall=clock.wall,
            min_interval=0,
        )
        result = ca.collect(client, now=NOW)
        self.assertEqual(result["summary"]["total_agents"], 6)
        self.assertEqual(clock.slept, [7.0])

    def test_retry_after_http_date_and_cap(self):
        clock = Clock()
        when = format_datetime(clock.wall_dt + timedelta(seconds=5), usegmt=True)
        calls = {"n": 0}

        def transport(url: str, api_key: str):
            calls["n"] += 1
            if calls["n"] == 1:
                return 429, {"Retry-After": when}, b"{}"
            return 200, {}, b'{"apiKeyName":"laptop"}'

        client = ca.CursorClient(KEY, transport, sleep=clock.sleep, monotonic=clock.monotonic, wall=clock.wall, min_interval=0)
        data = client.get_path("/v1/me")
        self.assertEqual(data["apiKeyName"], "laptop")
        self.assertEqual(clock.slept, [5.0])

        calls["n"] = 0

        def huge(url: str, api_key: str):
            calls["n"] += 1
            if calls["n"] == 1:
                return 429, {"Retry-After": "10000"}, b"{}"
            return 200, {}, b'{"apiKeyName":"laptop"}'

        clock2 = Clock()
        client = ca.CursorClient(KEY, huge, sleep=clock2.sleep, monotonic=clock2.monotonic, wall=clock2.wall, min_interval=0)
        client.get_path("/v1/me")
        self.assertEqual(clock2.slept, [120.0])

    def test_gives_up_after_repeated_429(self):
        clock = Clock()
        calls = {"n": 0}

        def transport(url: str, api_key: str):
            calls["n"] += 1
            return 429, {"Retry-After": "1"}, b"{}"

        client = ca.CursorClient(
            KEY,
            transport,
            sleep=clock.sleep,
            monotonic=clock.monotonic,
            wall=clock.wall,
            min_interval=0,
            max_attempts=4,
        )
        with self.assertRaises(ca.CursorApiError) as caught:
            client.get_path("/v1/me")
        self.assertEqual(caught.exception.status, 429)
        self.assertEqual(calls["n"], 4)
        self.assertEqual(len(clock.slept), 3)

    def test_throttles_per_agent_calls(self):
        clock = Clock()
        summary = _summary("bc-active", "ARCHIVED", name="A", created=RECENT, run_id="run-active")
        routes = {
            "/v1/me": (200, {"apiKeyName": "laptop"}, None),
            "/v1/agents": (200, {"items": [summary]}, None),
            "/v1/agents/bc-active": (200, _detail(summary, repos=[]), None),
            "/v1/agents/bc-active/runs/run-active": (200, {"id": "run-active", "status": "FINISHED", "durationMs": 1}, None),
            "/v1/agents/bc-active/usage": (200, {"totalUsage": _tokens(1)}, None),
        }
        client, scripted = _client(routes, clock=clock, min_interval=3)
        ca.collect(client, now=NOW)
        # me + list + detail + run + usage, spaced by the minimum interval.
        self.assertEqual(len(scripted.calls), 5)
        self.assertEqual(clock.slept, [3.0, 3.0, 3.0, 3.0])


class TestInventory(unittest.TestCase):
    def test_summary_findings_and_unknown_status(self):
        client, _scripted = _client(_world())
        result = ca.collect(client, now=NOW)
        blob = json.dumps(result)
        self.assertNotIn(KEY, blob)
        self.assertNotIn("person@example.com", blob)
        self.assertNotIn("Ada", blob)
        self.assertNotIn("RESULTMARKER", blob)
        summary = result["summary"]
        self.assertEqual(summary["total_agents"], 6)
        self.assertEqual(summary["agents_active"], 3)  # ACTIVE, ACTIVE, and "Active"
        self.assertEqual(summary["agents_running"], 1)
        self.assertEqual(summary["agents_with_prs"], 1)
        self.assertEqual(summary["total_tokens"], 181)
        self.assertEqual(summary["usage_unavailable"], 1)
        self.assertEqual(summary["by_status"]["FROBNICATED"], 1)
        self.assertEqual(summary["by_status"]["IDLE"], 1)
        active = next(agent for agent in result["agents"] if agent["id"] == "bc-active")
        self.assertEqual(active["repos"][0]["starting_ref"], "main")
        self.assertEqual(active["branches"][0]["pr_url"], "https://github.com/example/demo/pull/7")
        self.assertEqual(active["latest_run"]["status"], "FINISHED")
        self.assertEqual(active["latest_run"]["duration_ms"], 12000)
        self.assertNotIn("result", active["latest_run"])
        weird = next(agent for agent in result["agents"] if agent["id"] == "bc-weird")
        self.assertEqual(weird["status"], "FROBNICATED")
        self.assertTrue(weird["usage_unavailable"])
        ids = [finding["id"] for finding in result["findings"]]
        self.assertIn("cloud_agents.active_current_branch", ids)
        self.assertIn("cloud_agents.active_repo_write", ids)
        self.assertIn("cloud_agents.long_lived_unarchived", ids)
        self.assertIn("cloud_agents.coverage", ids)
        by_id = {finding["id"]: finding for finding in result["findings"]}
        self.assertEqual(by_id["cloud_agents.active_current_branch"]["severity"], "high")
        self.assertEqual(by_id["cloud_agents.active_current_branch"]["evidence_count"], 1)
        self.assertEqual(by_id["cloud_agents.active_repo_write"]["severity"], "medium")
        self.assertEqual(by_id["cloud_agents.active_repo_write"]["evidence_count"], 1)
        self.assertEqual(by_id["cloud_agents.long_lived_unarchived"]["evidence_count"], 2)
        self.assertIn("cost", by_id["cloud_agents.coverage"]["sample_redacted"].lower())
        self.assertIn("GitHub", by_id["cloud_agents.coverage"]["sample_redacted"])

    def test_recent_agent_is_not_long_lived(self):
        client, _scripted = _client(_world())
        result = ca.collect(client, now=NOW)
        sample = next(
            finding["sample_redacted"]
            for finding in result["findings"]
            if finding["id"] == "cloud_agents.long_lived_unarchived"
        )
        self.assertNotIn("Readme agent", sample)
        self.assertIn("Old idle agent", sample)
        self.assertIn("Weird status", sample)
        self.assertNotIn("Done agent", sample)

    def test_include_result_scrubs_key_and_honors_redaction(self):
        marker_key_name = KEY
        routes = {
            "/v1/me": (200, {"apiKeyName": "laptop", "userEmail": KEY}, None),
            "/v1/agents": (
                200,
                {
                    "items": [
                        _summary("bc-active", "ACTIVE", name=marker_key_name, created=RECENT, run_id="run-active")
                    ]
                },
                None,
            ),
            "/v1/agents/bc-active": (
                200,
                _detail(
                    _summary("bc-active", "ACTIVE", name=marker_key_name, created=RECENT, run_id="run-active"),
                    repos=[{"url": "https://github.com/example/demo", "startingRef": "main"}],
                    workOnCurrentBranch=False,
                ),
                None,
            ),
            "/v1/agents/bc-active/runs/run-active": (
                200,
                {
                    "id": "run-active",
                    "status": "FINISHED",
                    "durationMs": 5,
                    "result": "leak " + KEY + " and " + ("AKIA" + ("0" * 16)),
                    "git": {"branches": []},
                },
                None,
            ),
            "/v1/agents/bc-active/usage": (200, {"totalUsage": _tokens(3)}, None),
        }
        previous = os.environ.get("AISCAN_REDACT")
        os.environ.pop("AISCAN_REDACT", None)
        try:
            hidden, _scripted = _client(routes)
            hidden_result = ca.collect(hidden, include_run_result=False, now=NOW)
            hidden_blob = json.dumps(hidden_result)
            self.assertNotIn(KEY, hidden_blob)
            self.assertNotIn("AKIA" + ("0" * 16), hidden_blob)
            self.assertEqual(hidden_result["agents"][0]["name"], "[redacted-key]")

            shown, _scripted = _client(routes)
            shown_result = ca.collect(shown, include_run_result=True, now=NOW)
            shown_blob = json.dumps(shown_result)
            self.assertNotIn(KEY, shown_blob)
            self.assertIn("AKIA" + ("0" * 16), shown_blob)
            self.assertIn("[redacted-key]", shown_result["agents"][0]["latest_run"]["result"])

            os.environ["AISCAN_REDACT"] = "1"
            redacted, _scripted = _client(routes)
            redacted_result = ca.collect(redacted, include_run_result=True, now=NOW)
            redacted_blob = json.dumps(redacted_result)
            self.assertNotIn(KEY, redacted_blob)
            self.assertNotIn("AKIA" + ("0" * 16), redacted_blob)
            self.assertIn("REDACTED:aws_key", redacted_blob)
        finally:
            if previous is None:
                os.environ.pop("AISCAN_REDACT", None)
            else:
                os.environ["AISCAN_REDACT"] = previous

    def test_error_body_does_not_echo_the_key(self):
        routes = {
            "/v1/me": (401, {"message": KEY}, None),
        }
        client, _scripted = _client(routes)
        with self.assertRaises(ca.CursorApiError) as caught:
            ca.collect(client, now=NOW)
        self.assertNotIn(KEY, str(caught.exception))
        self.assertEqual(caught.exception.status, 401)


class TestMain(unittest.TestCase):
    def test_missing_key_exits_cleanly(self):
        with tempfile.TemporaryDirectory() as tmp:
            stderr = io.StringIO()
            with redirect_stderr(stderr):
                code = ca.main(["--evidence-root", tmp], environ={})
            self.assertEqual(code, 0)
            message = stderr.getvalue()
            self.assertIn("CURSOR_API_KEY", message)
            self.assertIn("api.cursor.com", message)
            self.assertIn("aiscan all", message)
            self.assertIn("session token", message)
            path = Path(tmp) / "evidence" / "cloud-agents.json"
            data = json.loads(path.read_text(encoding="utf-8"))
            self.assertFalse(data["platform_detected"])
            self.assertFalse(data["summary"]["key_configured"])
            self.assertEqual(data["agents"], [])
            self.assertNotIn(KEY, json.dumps(data))
            self.assertNotIn("crsr_", json.dumps(data))

    def test_written_evidence_omits_the_key(self):
        routes = _world()
        with tempfile.TemporaryDirectory() as tmp:
            stderr = io.StringIO()

            def factory(api_key: str) -> ca.CursorClient:
                client, _scripted = _client(routes)
                client._api_key = api_key
                return client

            with redirect_stderr(stderr):
                code = ca.main(
                    ["--evidence-root", tmp, "--include-run-result"],
                    environ={"CURSOR_API_KEY": KEY},
                    client_factory=factory,
                )
            self.assertEqual(code, 0, stderr.getvalue())
            data = json.loads((Path(tmp) / "evidence" / "cloud-agents.json").read_text(encoding="utf-8"))
            blob = json.dumps(data)
            self.assertNotIn(KEY, blob)
            self.assertNotIn("person@example.com", blob)
            self.assertTrue(data["platform_detected"])
            self.assertEqual(data["collector"], "cloud-agents")
            self.assertIn("RESULTMARKER", blob)

    def test_auth_failure_does_not_print_the_key(self):
        routes = {"/v1/me": (401, {"message": "bad " + KEY}, None)}
        with tempfile.TemporaryDirectory() as tmp:
            stderr = io.StringIO()

            def factory(api_key: str) -> ca.CursorClient:
                scripted = Scripted(routes, key=api_key)
                return ca.CursorClient(api_key, scripted, min_interval=0, sleep=lambda _s: None)

            with redirect_stderr(stderr):
                code = ca.main(
                    ["--evidence-root", tmp],
                    environ={"CURSOR_API_KEY": KEY},
                    client_factory=factory,
                )
            self.assertEqual(code, 1)
            self.assertNotIn(KEY, stderr.getvalue())
            self.assertFalse((Path(tmp) / "evidence" / "cloud-agents.json").exists())


class TestWiringAndBriefing(unittest.TestCase):
    def test_aiscan_keeps_cloud_agents_out_of_all(self):
        repo = Path(__file__).resolve().parents[3]
        text = (repo / "aiscan.ps1").read_text(encoding="utf-8")
        import re

        match = re.search(r"\$StdlibOrder = @\((.*?)\)", text, re.S)
        self.assertIsNotNone(match)
        assert match is not None
        self.assertNotIn("cloud-agents", match.group(1))
        self.assertIn('"cloud-agents"', text)

    def test_briefing_panel_only_when_evidence_exists(self):
        import importlib.util

        repo = Path(__file__).resolve().parents[3]
        briefing_path = repo / "report" / "build-briefing.py"
        spec = importlib.util.spec_from_file_location("briefing_mod", briefing_path)
        briefing = importlib.util.module_from_spec(spec)
        assert spec.loader is not None
        spec.loader.exec_module(briefing)

        base = {
            "collector": "codex",
            "version": "1.0.0",
            "ran_at": "2026-10-01T00:00:00+00:00",
            "host": "DEMO-ENDPOINT",
            "platform_detected": True,
            "scope_hash": "abcd",
            "summary": {},
            "findings": [],
            "rules": [],
            "raw_pointers": [],
        }
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "evidence").mkdir()
            (root / "evidence" / "codex.json").write_text(json.dumps(base), encoding="utf-8")
            html = briefing.build_html(root, customer="Example", operator="Test")
            self.assertNotIn('id="cloud-agents"', html)
            self.assertNotIn("%%CLOUD_AGENTS", html)

            client, _scripted = _client(_world())
            result = ca.collect(client, now=NOW)
            envelope = ca._scanned_envelope(result)
            envelope["agents"][0]["name"] = "<script>alert(1)</script>"
            envelope["agents"][0]["url"] = "javascript:alert(1)"
            (root / "evidence" / "cloud-agents.json").write_text(
                json.dumps(envelope), encoding="utf-8"
            )
            html = briefing.build_html(root, customer="Example", operator="Test")
            self.assertIn('id="cloud-agents"', html)
            self.assertIn("181", html)
            self.assertIn("FROBNICATED", html)
            self.assertIn("&lt;script&gt;", html)
            self.assertNotIn("<script>alert", html)
            self.assertNotIn('href="javascript:', html)
            self.assertIn("api.cursor.com", html)
            self.assertNotIn(KEY, html)


if __name__ == "__main__":
    unittest.main()
