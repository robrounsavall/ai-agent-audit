"""Fixture tests for the accounts collector.

Sentinel strings stand in for tokens and API keys. They must never appear in
the evidence envelope.
"""

from __future__ import annotations

import json
import os
import shutil
import sqlite3
import tempfile
import unittest
from pathlib import Path

os.environ["USERPROFILE"] = r"C:\Users\Test User"
os.environ["APPDATA"] = r"C:\Users\Test User\AppData\Roaming"
os.environ.pop("AISCAN_REDACT", None)

import bootstrap  # noqa: E402,F401
import accounts  # noqa: E402

FIXTURES = Path(__file__).resolve().parent / "fixtures"

SENTINELS = (
    "SENTINEL_CLAUDE_KEY",
    "SENTINEL_CLAUDE_SETTINGS_KEY",
    "SENTINEL_CREDENTIALS",
    "SENTINEL_CREDENTIALS_REFRESH",
    "SENTINEL_CODEX_API",
    "SENTINEL_CODEX_ACCESS",
    "SENTINEL_CODEX_REFRESH",
    "SENTINEL_GROK_TOKEN",
    "SENTINEL_GROK_ACCESS",
    "SENTINEL_GROK_SETTINGS_TOKEN",
    "SENTINEL_GH_OAUTH",
    "SENTINEL_GH_ENTERPRISE",
    "SENTINEL_GIT_HEADER",
    "SENTINEL_MCP_ENV",
    "SENTINEL_MCP_HEADER",
    "SENTINEL_MCP_ARG",
    "SENTINEL_MCP_URL",
    "SENTINEL_CURSOR_TOKEN",
    "SENTINEL_GROK_BOT_SECRET",
    "SENTINEL_GROK_BOT_STORE",
    "SENTINEL_COPILOT_TOKEN",
    "SENTINEL_COPILOT_JSON_TOKEN",
    "SENTINEL_ENV_XAI",
)

JWT = (
    "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0."
    "eyJlbWFpbCI6ImNvZGV4LXVzZXJAZXhhbXBsZS5jb20iLCJuYW1lIjoiQ29kZXggVXNlciIsImh0dHBzOi8vYXBpLm9wZW5haS5jb20vYXV0aCI6eyJjaGF0Z3B0X3BsYW5fdHlwZSI6InBybyIsImNoYXRncHRfYWNjb3VudF9pZCI6ImFjY3RfZGVtbyIsImNoYXRncHRfdXNlcl9pZCI6InVzZXItZGVtbyJ9LCJodHRwczovL2FwaS5vcGVuYWkuY29tL3Byb2ZpbGUiOnsiZW1haWwiOiJjb2RleC11c2VyQGV4YW1wbGUuY29tIn19."
    "c2ln"
)


def _copy(src: Path, dest: Path) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(src, dest)


def _make_cursor_db(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(path)
    con.execute("CREATE TABLE ItemTable (key TEXT UNIQUE, value BLOB)")
    con.execute("CREATE TABLE cursorDiskKV (key TEXT UNIQUE, value BLOB)")
    rows = {
        "cursorAuth/cachedEmail": '"cursor-user@example.com"',
        "cursorAuth/stripeMembershipType": "pro",
        "cursorAuth/cachedSignUpType": "Google",
        "cursorAuth/accessToken": "SENTINEL_CURSOR_TOKEN",
        "cursorAuth/refreshToken": "SENTINEL_CURSOR_REFRESH",
    }
    for key, value in rows.items():
        con.execute("INSERT INTO ItemTable VALUES (?, ?)", (key, value))
    con.commit()
    con.close()


class Layout:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.home = root / "home"
        self.appdata = root / "appdata"
        self.home.mkdir()
        self.appdata.mkdir()
        self.claude_home = self.home / ".claude"
        self.codex_home = self.home / ".codex"
        self.grok_home = self.home / ".grok"
        self.cursor_db = self.appdata / "Cursor" / "User" / "globalStorage" / "state.vscdb"
        self.copilot = self.appdata / "Code" / "User" / "globalStorage" / "github.copilot"
        self.grok_bot = self.appdata / "Grok Bot"
        self.repo = root / "repos" / "demo"
        (self.repo / ".git").mkdir(parents=True)

    def locs(self, *, repo_roots: list[Path] | None = None) -> accounts.Locations:
        return accounts.Locations(
            home=self.home,
            appdata=self.appdata,
            claude_home=self.claude_home,
            claude_json=self.home / ".claude.json",
            codex_home=self.codex_home,
            codex_auth=self.codex_home / "auth.json",
            codex_config=self.codex_home / "config.toml",
            cursor_db=self.cursor_db,
            cursor_mcp=[self.home / ".cursor" / "mcp.json"],
            grok_home=self.grok_home,
            grok_config=self.grok_home / "config.toml",
            grok_auth=self.grok_home / "auth.json",
            copilot_dirs=[self.copilot],
            grok_bot_root=self.grok_bot,
            gh_hosts=[self.appdata / "GitHub CLI" / "hosts.yml"],
            gitconfigs=[self.home / ".gitconfig"],
            extra_mcp=[],
            repo_roots=repo_roots if repo_roots is not None else [self.repo],
            claude_desktop_config=self.appdata / "Claude" / "claude_desktop_config.json",
        )


def _plant(layout: Layout) -> None:
    _copy(FIXTURES / "claude.json", layout.home / ".claude.json")
    _copy(FIXTURES / "settings.json", layout.claude_home / "settings.json")
    _copy(FIXTURES / "credentials.json", layout.claude_home / ".credentials.json")
    _copy(FIXTURES / "codex-auth.json", layout.codex_home / "auth.json")
    _copy(FIXTURES / "grok-auth.json", layout.grok_home / "auth.json")
    _copy(FIXTURES / "grok-user-settings.json", layout.grok_home / "user-settings.json")
    _copy(FIXTURES / "hosts.yml", layout.appdata / "GitHub CLI" / "hosts.yml")
    _copy(FIXTURES / "gitconfig", layout.home / ".gitconfig")
    _copy(FIXTURES / "mcp.json", layout.repo / ".mcp.json")
    _copy(FIXTURES / "grok-bot-preferences.json", layout.grok_bot / "Preferences")
    _copy(FIXTURES / "grok-bot-sand-secrets.json", layout.grok_bot / "sand-secrets.json")
    _copy(FIXTURES / "copilot-user.json", layout.copilot / "user.json")
    _copy(FIXTURES / "copilot-token", layout.copilot / "copilot-token")
    (layout.grok_bot / "Network").mkdir(parents=True, exist_ok=True)
    (layout.grok_bot / "Network" / "Cookies").write_text("SENTINEL_COOKIE", encoding="utf-8")
    _make_cursor_db(layout.cursor_db)


def _by_tool(env: dict, tool: str) -> list[dict]:
    return [row for row in env["accounts"] if row["tool"] == tool]


class TestAccountsFixtures(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.layout = Layout(Path(self._tmp.name))
        _plant(self.layout)
        self.db_before = self.layout.cursor_db.read_bytes()
        self.db_mtime = self.layout.cursor_db.stat().st_mtime
        os.environ.pop("AISCAN_REDACT", None)

    def _collect(self, env: dict | None = None) -> dict:
        return accounts.collect(
            self.layout.locs(),
            environ={} if env is None else env,
        )

    def test_identifiers_and_no_secrets(self) -> None:
        env = self._collect({"XAI_API_KEY": "SENTINEL_ENV_XAI", "ANTHROPIC_API_KEY": "  "})
        blob = json.dumps(env)
        for sentinel in SENTINELS:
            self.assertNotIn(sentinel, blob, sentinel)
        self.assertNotIn(JWT, blob)
        self.assertNotIn("history-only@example.com", blob)
        self.assertNotIn("do-not-read@example.com", blob)
        self.assertNotIn("should-not-read-secrets@example.com", blob)
        self.assertNotIn("acct_demo", blob)
        self.assertNotIn("user-demo", blob)
        self.assertNotIn("00000000-0000-4000-8000-000000000001", blob)
        self.assertNotIn("Claude User", blob)
        self.assertNotIn("Codex User", blob)
        self.assertNotIn("organizationRole", blob)
        self.assertNotIn("SENTINEL_COOKIE", blob)
        self.assertNotIn("SENTINEL_CURSOR_REFRESH", blob)
        self.assertNotIn(str(self.layout.home), blob)
        self.assertNotIn("Users", blob)

        self.assertEqual(self.layout.cursor_db.read_bytes(), self.db_before)
        self.assertEqual(self.layout.cursor_db.stat().st_mtime, self.db_mtime)

        claude = _by_tool(env, "claude-code")
        oauth = next(row for row in claude if row["auth_method"] == "oauth")
        self.assertEqual(oauth["signed_in"], "yes")
        self.assertEqual(oauth["account"], "claude-user@example.com")
        self.assertEqual(oauth["organization"], "Example Org")
        self.assertEqual(oauth["source"], "~/.claude.json")
        self.assertTrue(any(row["auth_method"] == "api_key" for row in claude))
        settings_row = next(row for row in claude if row["source"].endswith("#env:ANTHROPIC_API_KEY"))
        self.assertEqual(settings_row["auth_method"], "api_key")
        self.assertEqual(settings_row["account"], "")

        codex = next(row for row in _by_tool(env, "codex") if row["auth_method"] == "oauth")
        self.assertEqual(codex["account"], "codex-user@example.com")
        self.assertEqual(codex["plan"], "pro")
        self.assertEqual(codex["signed_in"], "yes")
        self.assertTrue(codex["last_sign_in"].startswith("2026-04-01T12:30:00"))
        self.assertEqual(codex["source"], "~/.codex/auth.json")
        self.assertTrue(any(row["auth_method"] == "api_key" and row["tool"] == "codex" for row in env["accounts"]))

        cursor = _by_tool(env, "cursor")[0]
        self.assertEqual(cursor["account"], "cursor-user@example.com")
        self.assertEqual(cursor["plan"], "pro")
        self.assertEqual(cursor["auth_method"], "oauth")
        self.assertEqual(cursor["signed_in"], "yes")
        self.assertTrue(cursor["source"].startswith("%APPDATA%/"))
        self.assertIn("state.vscdb", cursor["source"])

        grok = next(row for row in _by_tool(env, "grok") if row["auth_method"] == "oauth")
        self.assertEqual(grok["account"], "grok-user@example.com")
        self.assertEqual(grok["plan"], "supergrok")
        self.assertEqual(grok["organization"], "Example Grok Org")
        self.assertEqual(grok["signed_in"], "yes")

        bot = _by_tool(env, "grok-bot")[0]
        self.assertEqual(bot["account"], "grok-bot@example.com")
        self.assertEqual(bot["signed_in"], "yes")

        copilot = _by_tool(env, "copilot")[0]
        self.assertEqual(copilot["account"], "copilot-user@example.com")
        self.assertEqual(copilot["organization"], "example-org")
        self.assertEqual(copilot["plan"], "business")
        self.assertEqual(copilot["auth_method"], "oauth")

        gh = _by_tool(env, "gh")
        self.assertEqual({row["account"] for row in gh}, {"gh-user", "gh-enterprise"})
        self.assertTrue(all(row["auth_method"] == "oauth" for row in gh))
        self.assertIn("github.com", {row["organization"] for row in gh})

        git = _by_tool(env, "git")[0]
        self.assertEqual(git["account"], "git-user@example.com")
        self.assertEqual(git["auth_method"], "git_config")
        self.assertEqual(git["source"], "~/.gitconfig")
        self.assertEqual(git["signed_in"], "yes")

        mcp = _by_tool(env, "mcp:notes")
        self.assertEqual(len(mcp), 1)
        self.assertEqual(mcp[0]["signed_in"], "unknown")
        self.assertIn("env:NOTES_API_KEY", mcp[0]["auth_method"])
        self.assertIn("header:Authorization", mcp[0]["auth_method"])
        self.assertIn("args:authorization", mcp[0]["auth_method"])
        self.assertIn("url_userinfo", mcp[0]["auth_method"])
        self.assertNotIn("mcp:local", {row["tool"] for row in env["accounts"]})

        xai = next(row for row in env["accounts"] if row["source"] == "env:XAI_API_KEY")
        self.assertEqual(xai["tool"], "grok")
        self.assertEqual(xai["auth_method"], "api_key")
        self.assertEqual(xai["account"], "")
        self.assertEqual(xai["signed_in"], "unknown")
        self.assertNotIn("env:ANTHROPIC_API_KEY", {row["source"] for row in env["accounts"]})

        ids = {item["id"] for item in env["findings"]}
        self.assertIn("accounts.identity.multiple", ids)
        mixed = next(item for item in env["findings"] if item["id"] == "accounts.auth.api_key_and_subscription")
        self.assertEqual(mixed["severity"], "medium")
        self.assertGreaterEqual(env["summary"]["distinct_accounts"], 2)
        self.assertNotIn("@", json.dumps(env["summary"]))
        self.assertTrue(env["platform_detected"])
        self.assertEqual(env["rules"], [])
        self.assertEqual(env["raw_pointers"], [])

    def test_redact_masks_emails(self) -> None:
        os.environ["AISCAN_REDACT"] = "1"
        try:
            env = self._collect()
        finally:
            os.environ.pop("AISCAN_REDACT", None)
        blob = json.dumps(env)
        self.assertNotIn("claude-user@example.com", blob)
        self.assertNotIn("cursor-user@example.com", blob)
        self.assertNotIn("codex-user@example.com", blob)
        self.assertIn("<email>", blob)
        for sentinel in SENTINELS:
            self.assertNotIn(sentinel, blob)
        self.assertGreaterEqual(env["summary"]["distinct_accounts"], 2)
        multiple = next(item for item in env["findings"] if item["id"] == "accounts.identity.multiple")
        self.assertNotIn("@", multiple["sample_redacted"])
        self.assertGreaterEqual(multiple["evidence_count"], 2)

    def test_empty_machine_is_not_detected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            layout = Layout(Path(tmp))
            env = accounts.collect(layout.locs(repo_roots=[]), environ={})
        self.assertFalse(env["platform_detected"])
        self.assertEqual(env["findings"], [])
        self.assertEqual(env["summary"]["distinct_accounts"], 0)
        methods = {row["auth_method"] for row in env["accounts"]}
        self.assertIn("not_present", methods)
        blob = json.dumps(env)
        for sentinel in SENTINELS:
            self.assertNotIn(sentinel, blob)

    def test_malformed_auth_does_not_raise(self) -> None:
        self.layout.codex_home.mkdir(parents=True, exist_ok=True)
        (self.layout.codex_home / "auth.json").write_text("{not json", encoding="utf-8")
        env = self._collect()
        codex = _by_tool(env, "codex")[0]
        self.assertEqual(codex["auth_method"], "unreadable")
        self.assertNotIn("SENTINEL_CODEX_ACCESS", json.dumps(env))

    def test_opaque_id_token_reports_session_without_the_token(self) -> None:
        payload = {
            "auth_mode": "chatgpt",
            "tokens": {
                "id_token": "not-a-jwt",
                "access_token": "SENTINEL_CODEX_ACCESS",
            },
        }
        self.layout.codex_home.mkdir(parents=True, exist_ok=True)
        (self.layout.codex_home / "auth.json").write_text(json.dumps(payload), encoding="utf-8")
        env = self._collect()
        codex = next(row for row in _by_tool(env, "codex") if row["auth_method"] == "oauth")
        self.assertEqual(codex["signed_in"], "yes")
        self.assertEqual(codex["account"], "")
        self.assertNotIn("SENTINEL_CODEX_ACCESS", json.dumps(env))

    def test_credentials_file_is_not_opened(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            layout = Layout(Path(tmp))
            layout.claude_home.mkdir()
            secret = layout.claude_home / ".credentials.json"
            secret.write_text('{"accessToken":"SENTINEL_CREDENTIALS"}', encoding="utf-8")
            before = secret.read_bytes()
            env = accounts.collect(layout.locs(repo_roots=[]), environ={})
            self.assertEqual(secret.read_bytes(), before)
        blob = json.dumps(env)
        self.assertNotIn("SENTINEL_CREDENTIALS", blob)
        oauth = next(row for row in _by_tool(env, "claude-code") if row["auth_method"] == "oauth")
        self.assertEqual(oauth["signed_in"], "yes")
        self.assertEqual(oauth["account"], "")
        self.assertTrue(oauth["source"].endswith(".credentials.json"))


class TestAccountsMain(unittest.TestCase):
    def test_main_writes_envelope(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            home = root / "home"
            appdata = home / "AppData" / "Roaming"
            home.mkdir()
            appdata.mkdir(parents=True)
            (home / ".gitconfig").write_text("[user]\nemail = solo@example.com\n", encoding="utf-8")
            env = {
                "USERPROFILE": str(home),
                "HOME": str(home),
                "APPDATA": str(appdata),
                "ANTHROPIC_API_KEY": "",
                "OPENAI_API_KEY": "",
                "XAI_API_KEY": "",
                "CURSOR_API_KEY": "",
                "GH_CONFIG_DIR": "",
                "GIT_CONFIG_GLOBAL": "",
                "CLAUDE_CONFIG_DIR": "",
                "CODEX_HOME": "",
                "GROK_HOME": "",
            }
            code = None
            old = {key: os.environ.get(key) for key in env}
            os.environ.update(env)
            os.environ.pop("AISCAN_REDACT", None)
            try:
                accounts.main(
                    [
                        "--evidence-root",
                        str(root),
                        "--repo-roots",
                        str(root / "no-such-repos"),
                        "--claude-home",
                        str(home / ".claude"),
                        "--codex-home",
                        str(home / ".codex"),
                        "--cursor-projects",
                        str(home / ".cursor" / "projects"),
                        "--cursor-db",
                        str(home / "missing.vscdb"),
                        "--grok-home",
                        str(home / ".grok"),
                    ]
                )
            except SystemExit as exc:
                code = exc.code
            finally:
                for key, value in old.items():
                    if value is None:
                        os.environ.pop(key, None)
                    else:
                        os.environ[key] = value
            self.assertEqual(code, 0)
            written = json.loads((root / "evidence" / "accounts.json").read_text(encoding="utf-8"))
            self.assertEqual(written["collector"], "accounts")
            self.assertTrue(any(row["account"] == "solo@example.com" for row in written["accounts"]))
            self.assertNotIn("SENTINEL", json.dumps(written))


if __name__ == "__main__":
    unittest.main()
