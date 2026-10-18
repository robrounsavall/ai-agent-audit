"""Tests for Cursor 3.2x permission sources (cli config, IDE state, sandbox, hooks)."""

from __future__ import annotations

import json
import os
import sqlite3
import tempfile
import unittest
from contextlib import closing
from unittest.mock import patch
from pathlib import Path

os.environ["USERPROFILE"] = r"C:\Users\Test User"
os.environ["APPDATA"] = r"C:\Users\Test User\AppData\Roaming"

import bootstrap  # noqa: E402,F401
import cursor  # noqa: E402
import cursor_permissions as cperm  # noqa: E402
import paths  # noqa: E402

APP_USER_KEY = cperm.APPLICATION_USER_KEY
SECRET_TOKEN = "ghp_" + "A1b2C3d4E5" * 3
EMAIL = "someone@example.com"


def ids(findings):
    return {f["id"] for f in findings}


def by_id(findings, fid):
    return [f for f in findings if f["id"] == fid]


def write(path: Path, data) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(data if isinstance(data, str) else json.dumps(data), encoding="utf-8")


def make_db(path: Path, item_rows: dict, disk_rows: dict | None = None) -> None:
    con = sqlite3.connect(path)
    con.execute("CREATE TABLE ItemTable (key TEXT UNIQUE, value BLOB)")
    con.execute("CREATE TABLE cursorDiskKV (key TEXT UNIQUE, value BLOB)")
    for k, v in item_rows.items():
        con.execute("INSERT INTO ItemTable VALUES (?, ?)", (k, v if isinstance(v, str) else json.dumps(v)))
    for k, v in (disk_rows or {}).items():
        con.execute("INSERT INTO cursorDiskKV VALUES (?, ?)", (k, v if isinstance(v, str) else json.dumps(v)))
    con.commit()
    con.close()


def composer(**over):
    state = {
        "useYoloMode": False,
        "yoloEnableRunEverything": False,
        "yoloCommandAllowlist": ["git", "python", "curl", "remove-item"],
        "yoloCommandDenylist": [],
        "webFetchDomainAllowlist": [],
        "yoloOutsideWorkspaceDisabled": False,
        "yoloDeleteFileDisabled": True,
        "yoloMcpToolsDisabled": True,
        "defaultMode2": "agent",
        "modes4": [
            {"id": "agent", "name": "Agent", "autoRun": True, "fullAutoRun": True},
            {"id": "triage", "name": "Triage", "autoRun": True, "fullAutoRun": False},
            {"id": "plan", "name": "Plan", "autoRun": False},
        ],
    }
    state.update(over)
    return state


class Base(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name)
        self.home = self.root / "cursor_home"
        self.home.mkdir()
        self.repos = self.root / "repos"
        self.repo = self.repos / "proj"
        (self.repo / ".git").mkdir(parents=True)
        self.db = self.root / "state.vscdb"
        self.projects = self.root / "projects"
        self.projects.mkdir()
        self._env = os.environ.get("CURSOR_CONFIG_DIR")
        os.environ.pop("CURSOR_CONFIG_DIR", None)
        self.addCleanup(self._restore_env)

    def _restore_env(self):
        os.environ.pop("CURSOR_CONFIG_DIR", None)
        if self._env is not None:
            os.environ["CURSOR_CONFIG_DIR"] = self._env

    def run_collect(self, **kw):
        tp = paths.resolve_tool_paths(cli_overrides={
            "cursor_projects": str(self.projects),
            "cursor_db": str(self.db),
        })
        kw.setdefault("cursor_home", self.home)
        kw.setdefault("install_dirs", [])
        return cursor.collect(tp, repo_roots=[self.repos], **kw)


class TestIdeState(Base):
    def test_composer_state_real_shape(self):
        make_db(self.db, {APP_USER_KEY: {"composerState": composer()}})
        env = self.run_collect()
        f = env["findings"]
        self.assertIn("cursor.run_mode.full_auto_mode", ids(f))
        full = by_id(f, "cursor.run_mode.full_auto_mode")[0]
        self.assertEqual(full["severity"], "high")
        self.assertEqual(full["sample_redacted"], "modes: Agent")
        self.assertEqual(full["evidence_count"], 1)
        self.assertEqual(by_id(f, "cursor.allowlist.interpreter")[0]["severity"], "high")
        self.assertEqual(by_id(f, "cursor.allowlist.interpreter")[0]["sample_redacted"], "python")
        self.assertIn("cursor.allowlist.network_tools", ids(f))
        self.assertIn("cursor.allowlist.destructive", ids(f))
        self.assertIn("cursor.autorun.outside_workspace", ids(f))
        self.assertNotIn("cursor.permissions.no_durable_allowlist", ids(f))
        self.assertNotIn("cursor.run_mode.unrestricted", ids(f))
        bash = [r for r in env["rules"] if r["rule_type"] == "bash"]
        self.assertEqual({r["command_or_tool_redacted"] for r in bash},
                         {"git", "python", "curl", "remove-item"})
        self.assertTrue(all(r["decision"] == "allow" for r in bash))
        s = env["summary"]
        self.assertTrue(s["ide_state_read"])
        self.assertEqual(s["ide_run_mode"], "ask")
        self.assertEqual(s["ide_allowlist_count"], 4)
        self.assertEqual(s["ide_full_auto_modes"], ["Agent"])
        self.assertEqual(s["ide_auto_run_modes"], ["Agent", "Triage"])
        self.assertEqual(s["durable_rules"], 4)
        self.assertTrue(s["durable_allowlist_found"])
        self.assertEqual(s["cursor_version"], "")
        self.assertNotIn("sandbox_mode", s)
        self.assertNotIn("approval_policy", s)

    def test_run_everything(self):
        make_db(self.db, {APP_USER_KEY: {"composerState": composer(
            useYoloMode=True, yoloEnableRunEverything=True, yoloCommandAllowlist=["*"],
            yoloCommandDenylist=["rm"])}})
        env = self.run_collect()
        crit = by_id(env["findings"], "cursor.run_mode.unrestricted")
        self.assertEqual(len(crit), 1)
        self.assertEqual(crit[0]["severity"], "critical")
        self.assertEqual(crit[0]["title"], "Cursor IDE Run Mode is Run Everything")
        wc = by_id(env["findings"], "cursor.allowlist.wildcard")
        self.assertEqual(wc[0]["severity"], "critical")
        self.assertEqual(env["summary"]["ide_run_mode"], "run-everything")
        self.assertTrue(any(r["decision"] == "deny" for r in env["rules"]))

    def test_run_mode_finding_suppresses_no_allowlist(self):
        make_db(self.db, {APP_USER_KEY: {"composerState": composer(
            yoloCommandAllowlist=[], modes4=[{"name": "Agent", "autoRun": True, "fullAutoRun": True}])}})
        env = self.run_collect()
        self.assertNotIn("cursor.permissions.no_durable_allowlist", ids(env["findings"]))

    def test_non_json_blob(self):
        make_db(self.db, {APP_USER_KEY: "not json"})
        env = self.run_collect()
        self.assertFalse(env["summary"]["ide_state_read"])
        self.assertEqual(env["summary"]["ide_run_mode"], "unknown")
        self.assertIn("cursor.permissions.no_durable_allowlist", ids(env["findings"]))

    def test_admin_policy(self):
        make_db(self.db, {cperm.ADMIN_SETTINGS_KEY: {
            "autoReview": {"allowInstructions": ["secret text a"], "blockInstructions": ["b", "c"]},
            "localPermissionsFilePath": "C:\\Users\\Test User\\x.json",
            "remotePermissionsFilePaths": [],
            "permissionsFileOverridesAutoRun": True,
            "networkAllowlist": ["a", "b"], "networkDenylist": ["c"],
        }})
        env = self.run_collect()
        s = env["summary"]
        self.assertTrue(s["admin_policy_cached"])
        self.assertEqual(s["admin_auto_review_rules"], 3)
        self.assertEqual(s["admin_network_allowlist"], 2)
        self.assertEqual(s["admin_network_denylist"], 1)
        self.assertTrue(s["admin_permissions_file_set"])
        self.assertTrue(s["admin_permissions_file_overrides_autorun"])
        self.assertNotIn("secret text", json.dumps(env))


class TestCliConfig(Base):
    def test_unrestricted_wildcards_and_project(self):
        write(self.home / "cli-config.json", {
            "approvalMode": "unrestricted",
            "permissions": {
                "allow": ["Shell(*)", "Write(**)", "Mcp(*:*)", "Shell(curl:*)", "Read(src/**)",
                          "WebFetch(example.com)"],
                "deny": ["Shell(rm)"],
            },
            "sandbox": {"mode": "disabled", "networkAccess": "allow_all", "readBoundary": "system"},
        })
        write(self.repo / ".cursor" / "cli.json", {"permissions": {"allow": ["Shell(pwsh)"]}})
        env = self.run_collect()
        f = env["findings"]
        un = by_id(f, "cursor.run_mode.unrestricted")
        self.assertEqual(un[0]["title"], "Cursor Agent CLI approvalMode is unrestricted (Run Everything)")
        wc = {x["title"]: x["severity"] for x in by_id(f, "cursor.allowlist.wildcard")}
        self.assertEqual(len(wc), 3)
        self.assertEqual(sorted(wc.values()), ["critical", "high", "high"])
        self.assertIn("cursor.sandbox.disabled", ids(f))
        self.assertIn("cursor.sandbox.network_allow_all", ids(f))
        self.assertIn("cursor.allowlist.interpreter", ids(f))  # project pwsh
        self.assertIn("cursor.allowlist.network_tools", ids(f))
        deny = [r for r in env["rules"] if r["decision"] == "deny"]
        self.assertEqual(len(deny), 1)
        self.assertEqual(deny[0]["rule_type"], "bash")
        types = {r["rule_type"] for r in env["rules"]}
        self.assertTrue({"bash", "edit", "mcp_tool", "web_fetch", "other"} <= types)
        proj = [r for r in env["rules"] if r.get("settings_source") == "project .cursor/cli.json"]
        self.assertEqual(len(proj), 1)
        self.assertEqual(proj[0]["source_kind"], "project_config")
        s = env["summary"]
        self.assertEqual(s["project_cli_configs"], 1)
        self.assertEqual(s["cli_approval_mode"], "unrestricted")
        self.assertEqual(s["cli_allow_count"], 7)
        self.assertEqual(s["cli_deny_count"], 1)
        self.assertEqual(s["cli_sandbox_mode"], "disabled")
        self.assertEqual(s["cli_read_boundary"], "system")
        self.assertTrue(s["cli_config_present"])
        self.assertTrue(env["platform_detected"])

    def test_real_shape_is_quiet(self):
        write(self.home / "cli-config.json", {
            "approvalMode": "allowlist", "permissions": {"allow": ["Shell(ls)"], "deny": []},
            "sandbox": {"mode": "disabled", "networkAccess": "user_config_with_defaults"},
            "attribution": {"x": 1},
        })
        env = self.run_collect()
        got = ids(env["findings"])
        self.assertNotIn("cursor.permissions.no_durable_allowlist", got)
        self.assertNotIn("cursor.sandbox.network_allow_all", got)
        self.assertNotIn("cursor.run_mode.unrestricted", got)
        self.assertIn("cursor.sandbox.disabled", got)

    def test_auto_review(self):
        write(self.home / "cli-config.json", {"approvalMode": "auto-review"})
        env = self.run_collect()
        self.assertEqual(by_id(env["findings"], "cursor.run_mode.auto_review")[0]["severity"], "low")

    def test_jsonc_and_parse_error(self):
        write(self.home / "cli-config.json",
              '{\n // note\n "approvalMode": "unrestricted", /* c */\n "permissions": {"allow": ["Shell(ls)",],},\n}\n')
        env = self.run_collect()
        self.assertIn("cursor.run_mode.unrestricted", ids(env["findings"]))
        self.assertNotIn("cursor.config.parse_error", ids(env["findings"]))

        write(self.home / "cli-config.json", "{ broken")
        env = self.run_collect()
        pe = by_id(env["findings"], "cursor.config.parse_error")
        self.assertEqual(len(pe), 1)
        self.assertEqual(pe[0]["severity"], "low")
        self.assertIn("cli-config.json", pe[0]["title"])
        self.assertNotIn(str(self.home), json.dumps(env))

    def test_cursor_config_dir_env(self):
        other = self.root / "other_home"
        write(other / "cli-config.json", {"approvalMode": "unrestricted"})
        os.environ["CURSOR_CONFIG_DIR"] = str(other)
        tp = paths.resolve_tool_paths(cli_overrides={
            "cursor_projects": str(self.projects), "cursor_db": str(self.db)})
        env = cursor.collect(tp, repo_roots=[self.repos], install_dirs=[])
        self.assertIn("cursor.run_mode.unrestricted", ids(env["findings"]))


class TestSideFiles(Base):
    def test_permissions_sandbox_hooks(self):
        for base in (self.home, self.repo / ".cursor"):
            write(base / "permissions.json", {"autoRun": {
                "allow_instructions": ["secret allow text"], "block_instructions": ["a", "b"]}})
            write(base / "sandbox.json", {
                "type": "insecure_none",
                "networkPolicy": {"default": "allow"},
                "additionalReadwritePaths": ["~", "C:\\", "src"],
            })
        write(self.home / "hooks.json", {"version": 1, "hooks": {
            "beforeShellExecution": [{"command": "audit.sh --token " + SECRET_TOKEN}]}})
        write(self.repo / ".cursor" / "hooks.json", {"hooks": {
            "stop": [{"hooks": [{"command": "a"}, {"command": "b"}]}]}})
        env = self.run_collect()
        f = env["findings"]
        self.assertEqual(len(by_id(f, "cursor.sandbox.disabled")), 2)
        self.assertTrue(all(x["severity"] == "high" for x in by_id(f, "cursor.sandbox.disabled")))
        self.assertEqual(len(by_id(f, "cursor.sandbox.network_allow_all")), 2)
        bw = by_id(f, "cursor.sandbox.broad_write")
        self.assertEqual(len(bw), 2)
        self.assertEqual(bw[0]["evidence_count"], 2)
        hooks = by_id(f, "cursor.hooks.command")
        self.assertEqual(len(hooks), 2)
        self.assertTrue(all(h["severity"] == "medium" for h in hooks))
        s = env["summary"]
        self.assertEqual(s["permissions_json_files"], 2)
        self.assertEqual(s["auto_review_allow_instructions"], 2)
        self.assertEqual(s["auto_review_block_instructions"], 4)
        self.assertEqual(s["sandbox_json_files"], 2)
        self.assertEqual(s["hooks_json_handlers"], 3)
        dump = json.dumps(env)
        self.assertNotIn("secret allow text", dump)
        self.assertNotIn(SECRET_TOKEN, dump)

    def test_same_project_sandbox_title_merges(self):
        other = self.repos / "proj2"
        (other / ".git").mkdir(parents=True)
        for repo in (self.repo, other):
            write(repo / ".cursor" / "sandbox.json", {"type": "insecure_none"})
        env = self.run_collect()
        rows = by_id(env["findings"], "cursor.sandbox.disabled")
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["evidence_count"], 2)
        self.assertIn("project sandbox.json", rows[0]["title"])

    def test_camelcase_permissions_and_bad_sandbox(self):
        write(self.home / "permissions.json", {"allowInstructions": ["x"], "blockInstructions": []})
        write(self.home / "sandbox.json", "[1,")
        env = self.run_collect()
        self.assertEqual(env["summary"]["auto_review_allow_instructions"], 1)
        pe = by_id(env["findings"], "cursor.config.parse_error")
        self.assertEqual(len(pe), 1)
        self.assertIn("sandbox.json", pe[0]["title"])


class TestMisc(Base):
    def test_no_sources_still_flags(self):
        env = self.run_collect()
        self.assertIn("cursor.permissions.no_durable_allowlist", ids(env["findings"]))
        t = by_id(env["findings"], "cursor.permissions.no_durable_allowlist")[0]
        self.assertEqual(t["severity"], "medium")
        self.assertIn("cli-config.json", t["title"])

    def test_install_version(self):
        sysdir = self.root / "pf" / "Cursor"
        write(sysdir / "resources" / "app" / "product.json", {"version": "3.25.6"})
        userdir = self.root / "local" / "cursor"
        userdir.mkdir(parents=True)
        env = self.run_collect(install_dirs=[userdir, sysdir])
        self.assertEqual(env["summary"]["cursor_version"], "3.25.6")
        self.assertEqual(env["summary"]["cursor_install_scope"], "user")
        env = self.run_collect(install_dirs=[("system", sysdir)])
        self.assertEqual(env["summary"]["cursor_install_scope"], "system")
        self.assertNotIn(str(sysdir), json.dumps(env))

    def test_privacy(self):
        blob = {
            "someUnrelated": {"email": EMAIL, "token": SECRET_TOKEN},
            "composerState": composer(unrelatedKey={"mail": EMAIL, "tok": SECRET_TOKEN}),
        }
        make_db(
            self.db,
            {
                APP_USER_KEY: blob,
                "cursorAuth/accessToken": SECRET_TOKEN,
                "cursorAuth/refreshToken": "refresh-" + SECRET_TOKEN,
                "cursorAuth/cachedEmail": EMAIL,
                "mcpOAuth.secret.x": "oauth-secret-value-123",
                "secret://abc": "secret-uri-value-456",
                "composerData:1234": "permission allowlist chat text about my passwords",
                "agentKv:blob1": "autoRun permission mcp chat content",
            },
            {
                "composerData:9999": "permission allowlist chat text about my passwords",
                "bubbleId:1:2": "allowlist autorun bubble content",
            },
        )
        env = self.run_collect()
        dump = json.dumps(env)
        for needle in (SECRET_TOKEN, EMAIL, "oauth-secret-value", "secret-uri-value",
                       "composerData", "chat text", "agentKv", "bubbleId", "cursorAuth"):
            self.assertNotIn(needle, dump)
        self.assertLessEqual(env["summary"]["vscdb_keys_scanned"], 4)
        self.assertTrue(env["summary"]["ide_state_read"])

    def test_legacy_allowlist_key_still_parsed(self):
        make_db(self.db, {"cursor.terminalAllowlist": {"allowlist": ["npm"]}})
        env = self.run_collect()
        self.assertTrue(any(r["rule"] == "npm" for r in env["rules"]))
        self.assertNotIn("cursor.permissions.no_durable_allowlist", ids(env["findings"]))


class TestReviewRegressions(Base):
    def test_search_summary_has_no_private_payload(self):
        make_db(self.db, {APP_USER_KEY: {"composerState": composer()},
                          cperm.ADMIN_SETTINGS_KEY: {"networkAllowlist": ["a"]}})
        result = cursor.search_vscdb(self.db)
        self.assertEqual(len(result), 4)
        self.assertFalse(any(k.startswith("_") for k in result[3]))
        self.assertNotIn("composerState", json.dumps(result[3]))
        self.assertTrue(self.run_collect()["summary"]["ide_state_read"])

    def test_search_uses_keys_only_and_targeted_values(self):
        make_db(self.db, {
            "cursor.terminalAllowlist": {"allowlist": ["npm"]},
            "composerData:allowlist": "PRIVATE_CHAT",
            "cursorAuth/allowlist": "PRIVATE_AUTH",
            "unrelated": "allowlist PRIVATE_VALUE",
        }, {"allowlist": "PRIVATE_DISK"})
        queries = []
        original = cursor.open_vscdb

        def traced(path):
            con = original(path)
            con.set_trace_callback(queries.append)
            return con

        with patch.object(cursor, "open_vscdb", side_effect=traced):
            cursor.search_vscdb(self.db)
        self.assertIn("SELECT key FROM ItemTable", queries)
        for query in queries:
            if "SELECT" in query.upper() and "value" in query.lower():
                self.assertIn("WHERE", query.upper())
            self.assertNotIn("composerData:allowlist", query)
            self.assertNotIn("cursorAuth/allowlist", query)
            self.assertNotIn("WHERE key='unrelated'", query)
            self.assertNotIn("FROM cursorDiskKV WHERE key='allowlist'", query)

    def test_non_command_rules_do_not_hide_missing_command_allowlist(self):
        write(self.home / "cli-config.json", {"permissions": {
            "allow": ["Read(**)", "Write(src/**)", "WebFetch(*)", "Mcp(*:*)"]}})
        make_db(self.db, {APP_USER_KEY: {"composerState": {
            "webFetchDomainAllowlist": ["example.com"]}}})
        self.assertIn("cursor.permissions.no_durable_allowlist", ids(self.run_collect()["findings"]))

    def test_invalid_top_levels_and_deep_json(self):
        for value in ("null", "[]", "42", "[" * 1200 + "]" * 1200,
                      '{"value":' + "9" * 5000 + '}'):
            with self.subTest(value=value[:20]):
                write(self.home / "cli-config.json", value)
                env = self.run_collect()
                self.assertIn("cursor.config.parse_error", ids(env["findings"]))

    def test_odd_and_oversized_state(self):
        make_db(self.db, {APP_USER_KEY: "[" * 1200 + "]" * 1200})
        self.assertFalse(self.run_collect()["summary"]["ide_state_read"])
        with closing(sqlite3.connect(self.db)) as con, con:
            con.execute("UPDATE ItemTable SET value=?", (' ' * (cperm.configfmt.MAX_CONFIG_BYTES + 1),))
        self.assertFalse(self.run_collect()["summary"]["ide_state_read"])
        with closing(sqlite3.connect(self.db)) as con, con:
            con.execute("UPDATE ItemTable SET value=?", (json.dumps({"composerState": {
                "yoloCommandAllowlist": [None, 42, {}, "git"],
                "yoloCommandDenylist": None, "modes4": [None, 1, {}]}}),))
        self.assertEqual(self.run_collect()["summary"]["ide_allowlist_count"], 1)

    def test_mode_and_cli_summary_redaction(self):
        make_db(self.db, {APP_USER_KEY: {"composerState": composer(modes4=[{
            "name": EMAIL + " " + SECRET_TOKEN, "autoRun": True, "fullAutoRun": True}])}})
        write(self.home / "cli-config.json", {"sandbox": {"mode": SECRET_TOKEN}})
        dump = json.dumps(self.run_collect())
        self.assertNotIn(EMAIL, dump)
        self.assertNotIn(SECRET_TOKEN, dump)


class TestRedactionPolicy(Base):
    """Paths follow -Redact like the rest of aiscan; profile fragments are masked."""

    FRAGMENT = "User\\AppData\\Roaming\\tool.exe"

    def _collect_with(self, redact: str):
        make_db(self.db, {APP_USER_KEY: {"composerState": composer(
            yoloCommandAllowlist=["git", self.FRAGMENT])}})
        with patch.dict(os.environ, {"AISCAN_REDACT": redact}), \
                patch.object(cperm, "USERPROFILE", Path("C:/Users/Test User")):
            return json.dumps(self.run_collect())

    def test_local_run_keeps_allowlist_entry(self):
        blob = self._collect_with("")
        self.assertIn("AppData", blob)

    def test_redacted_run_masks_profile_fragment(self):
        blob = self._collect_with("1")
        self.assertNotIn("User\\\\AppData", blob)
        self.assertNotIn(self.FRAGMENT, blob)
        self.assertIn("<user>", blob)


if __name__ == "__main__":
    unittest.main()
