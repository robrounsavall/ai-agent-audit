"""Unit tests for the GitHub access inventory. No network."""

from __future__ import annotations

import json
import unittest
import urllib.parse
from pathlib import Path

import importlib.util

_mod_path = Path(__file__).resolve().parent.parent / "github_access.py"
_spec = importlib.util.spec_from_file_location("github_access_mod", _mod_path)
ga = importlib.util.module_from_spec(_spec)
assert _spec.loader is not None
_spec.loader.exec_module(ga)

TOKEN = "test-token"


def _url_path(url: str) -> str:
    parsed = urllib.parse.urlparse(url)
    return parsed.path + (("?" + parsed.query) if parsed.query else "")


class Scripted:
    def __init__(self, routes: dict[str, tuple[int, object, dict[str, str] | None]]):
        self.routes = routes
        self.calls: list[str] = []

    def __call__(self, url: str, token: str):
        self.calls.append(url)
        if token != TOKEN:
            raise AssertionError("unexpected token passed to transport")
        path = urllib.parse.urlparse(url).path
        query = urllib.parse.parse_qs(urllib.parse.urlparse(url).query)
        key = path
        if path not in self.routes:
            for candidate, response in self.routes.items():
                if candidate == path:
                    key = candidate
                    break
            else:
                raise AssertionError(f"unexpected URL {url}")
        status, body, headers = self.routes[key]
        if isinstance(body, dict) and body.get("_echo_login"):
            body = [{"login": query.get("login", ["missing"])[0], "credential_type": "personal access token"}]
        raw = json.dumps(body).encode("utf-8")
        return status, headers or {}, raw


class TestResolveToken(unittest.TestCase):
    def test_env_beats_gh(self):
        token = ga.resolve_token(None, {"GH_TOKEN": "from-env"}, lambda: "from-gh")
        self.assertEqual(token, "from-env")

    def test_missing(self):
        self.assertIsNone(ga.resolve_token(None, {}, lambda: None))


class TestCollect(unittest.TestCase):
    def test_owner_apps_and_own_credentials(self):
        routes = {
            "/user": (200, {"login": "robert"}, None),
            "/user/memberships/orgs": (
                200,
                [
                    {"role": "admin", "state": "active", "organization": {"login": "acme"}},
                    {"role": "member", "state": "active", "organization": {"login": "other"}},
                ],
                None,
            ),
            "/orgs/acme/installations": (
                200,
                {
                    "total_count": 1,
                    "installations": [
                        {
                            "id": 9,
                            "app_id": 42,
                            "app_slug": "cursor",
                            "target_type": "Organization",
                            "repository_selection": "selected",
                            "permissions": {"contents": "write", "metadata": "read", "email": None},
                            "html_url": "https://github.com/organizations/acme/settings/installations/9",
                            "account": {"login": "acme", "email": "hidden@example.com"},
                            "access_tokens_url": "https://api.github.com/app/installations/9/access_tokens",
                            "suspended_at": None,
                        }
                    ],
                },
                None,
            ),
            "/orgs/acme/credential-authorizations": (
                200,
                {
                    "_echo_login": True,
                },
                None,
            ),
        }
        # credential route returns a list based on query; Scripted special-cases dict flag
        scripted = Scripted(routes)
        report = ga.collect(ga.GitHubClient(TOKEN, scripted))
        blob = json.dumps(report)
        self.assertNotIn(TOKEN, blob)
        self.assertNotIn("hidden@example.com", blob)
        self.assertNotIn("access_tokens", blob)
        self.assertEqual(report["login"], "robert")
        self.assertEqual([org["login"] for org in report["orgs"]], ["acme", "other"])
        acme, other = report["orgs"]
        self.assertEqual(acme["installations"][0]["app_slug"], "cursor")
        self.assertEqual(acme["installations"][0]["permissions"], {"contents": "write", "metadata": "read"})
        self.assertEqual(acme["installations"][0]["repository_selection"], "selected")
        self.assertIn("not an organization owner", other["installations_error"])
        self.assertEqual(acme["credential_authorizations"][0]["login"], "robert")
        self.assertTrue(any("/orgs/acme/installations" in call for call in scripted.calls))
        self.assertFalse(any("/orgs/other/" in call for call in scripted.calls))
        summary = ga.format_summary(report)
        self.assertIn("cursor  selected  contents:write, metadata:read", summary)
        self.assertIn("settings/installations", summary)
        self.assertNotIn(TOKEN, summary)

    def test_refuses_foreign_pagination(self):
        routes = {
            "/user": (200, {"login": "robert"}, None),
            "/user/memberships/orgs": (
                200,
                [{"role": "admin", "state": "active", "organization": {"login": "acme"}}],
                {"Link": '<https://evil.example/next>; rel="next"'},
            ),
        }
        client = ga.GitHubClient(TOKEN, Scripted(routes))
        with self.assertRaises(ga.GitHubError) as caught:
            ga.collect(client)
        self.assertIn("pagination", str(caught.exception).lower())

    def test_saml_404_is_a_note(self):
        routes = {
            "/user": (200, {"login": "robert"}, None),
            "/user/memberships/orgs": (
                200,
                [{"role": "admin", "state": "active", "organization": {"login": "acme"}}],
                None,
            ),
            "/orgs/acme/installations": (200, {"installations": []}, None),
            "/orgs/acme/credential-authorizations": (404, {"message": "Not Found"}, None),
        }
        report = ga.collect(ga.GitHubClient(TOKEN, Scripted(routes)))
        self.assertIn("no SAML", report["orgs"][0]["credential_authorizations_error"])

    def test_scrub_removes_token(self):
        self.assertNotIn("ghp_" + "a" * 20, ga.scrub("leaked ghp_" + "a" * 20, None))


if __name__ == "__main__":
    unittest.main()
