"""Synthetic permission-file fixtures for the Codex collector."""
import os
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

os.environ["USERPROFILE"] = r"C:\Users\Test User"
import bootstrap  # noqa: E402,F401
import codex
import paths


class PermissionFiles(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.home = self.base / "home"
        self.home.mkdir()
        self.tp = paths.resolve_tool_paths(cli_overrides={"codex_home": str(self.home)})

    def write(self, name, text, root=None):
        path = (root or self.home) / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        return path

    def collect(self, **kwargs):
        return codex.collect(self.tp, repo_roots=kwargs.get("repo_roots", []), managed_dirs=kwargs.get("managed_dirs", []))

    def finding(self, env, fid):
        return next(f for f in env["findings"] if f["id"] == fid)

    def test_default_permissions_and_reviewer(self):
        self.write("config.toml", 'default_permissions = ":danger-full-access"\napprovals_reviewer = "auto_review"\n[windows]\nsandbox="elevated"')
        env = self.collect()
        self.assertEqual(self.finding(env, "codex.permissions.full_access")["severity"], "critical")
        self.assertEqual(self.finding(env, "codex.approval.auto_review")["severity"], "medium")
        self.assertEqual(env["summary"]["windows_sandbox"], "elevated")
        self.write("config.toml", 'default_permissions = ":workspace"')
        env = self.collect()
        self.assertNotIn("codex.permissions.full_access", [f["id"] for f in env["findings"]])
        self.assertEqual(env["summary"]["effective_permissions"], ":workspace")

    def test_custom_profiles(self):
        self.write("config.toml", '''default_permissions="work"
[permissions.work]
extends="parent"
[permissions.work.network]
enabled=true
[permissions.parent.filesystem]
"/"="write"
[permissions.other.network]
enabled=true
''')
        env = self.collect()
        self.assertEqual(self.finding(env, "codex.permissions.custom_full_disk")["severity"], "high")
        self.assertEqual([f["severity"] for f in env["findings"] if f["id"] == "codex.permissions.network_enabled"], ["high", "medium"])
        self.assertEqual(env["summary"]["custom_permission_profiles"], 3)

    def test_latent_profile(self):
        self.write("work.config.toml", 'default_permissions=":danger-full-access"\napproval_policy="never"')
        env = self.collect()
        finding = self.finding(env, "codex.profile.full_access")
        self.assertEqual(finding["severity"], "high")
        self.assertTrue(finding["title"].startswith("Codex profile work: "))
        self.assertNotIn("danger-full-access", finding["sample_redacted"])
        never = self.finding(env, "codex.profile.approval_never")
        self.assertEqual(never["severity"], "high")
        self.assertTrue(never["title"].startswith("Codex profile work: "))
        self.assertNotIn("codex.approval.never", {f["id"] for f in env["findings"]})
        self.assertEqual(env["summary"]["profile_names"], ["work"])

    def test_latent_profile_reviewer_and_sandbox_ids(self):
        self.write("ci.config.toml", 'approvals_reviewer="auto_review"\nsandbox_mode="danger-full-access"')
        ids = {f["id"] for f in self.collect()["findings"]}
        self.assertIn("codex.profile.approval_auto_review", ids)
        self.assertIn("codex.profile.sandbox_full_access", ids)
        for live in ("codex.approval.auto_review", "codex.sandbox.full_access", "codex.approval.never"):
            self.assertNotIn(live, ids)

    def test_rules_safely_parsed(self):
        self.write("rules/default.rules", '''prefix_rule(pattern=["git", "status"], decision="allow")
prefix_rule(
 pattern = ['gh', ['pr', 'issue'], 'view'], # union
 decision = 'allow', justification='review', match=['gh pr view'], not_match=[]
)
prefix_rule(pattern=['python'])
prefix_rule(pattern=['powershell.exe', '-Command'])
prefix_rule(pattern=['git', 'push'], decision='prompt')
prefix_rule(pattern=['rm'], decision='forbidden')
network_rule(host='example.com', protocol='https', decision='allow')
prefix_rule(pattern=__import__("os").system("x"))
# prefix_rule(pattern=['ignored'])
''')
        with patch("os.system", side_effect=AssertionError("must not execute")):
            env = self.collect()
        s = env["summary"]
        self.assertEqual([s[k] for k in ("rules_allow", "rules_prompt", "rules_forbidden", "rules_network", "rules_unparsed")], [4, 1, 1, 1, 1])
        broad = self.finding(env, "codex.rules.interpreter_prefix")
        self.assertEqual(broad["evidence_count"], 2)
        self.assertEqual(self.finding(env, "codex.rules.saved_allow")["evidence_count"], 4)
        self.assertIn("durable_allowlist", self.finding(env, "codex.rules.saved_allow")["tags"])
        rules = env["rules"]
        self.assertTrue(any(r["rule"] == "Bash(gh {pr|issue} view *)" for r in rules))
        self.assertTrue(any(r["rule"] == "PowerShell(powershell.exe -Command *)" and r["rule_type"] == "powershell" for r in rules))
        self.assertEqual({r["decision"] for r in rules}, {"allow", "ask", "deny"})
        self.assertTrue(all(r["settings_source"] == "rules/default.rules" for r in rules))

    def test_fixed_script_is_not_unrestricted(self):
        self.write("rules/default.rules", 'prefix_rule(pattern=["powershell.exe","-Command","Get-ChildItem"])')
        self.assertNotIn("codex.rules.interpreter_prefix", [f["id"] for f in self.collect()["findings"]])

    def test_file_rules_replace_session_prefixes(self):
        self.write("sessions/a.jsonl", json.dumps({"payload": {"type": "message", "content": 'Approved command prefixes: ["git", "status"]'}}) + "\n")
        self.write("rules/default.rules", 'prefix_rule(pattern=["git", "status"])')
        env = self.collect()
        self.assertEqual(len(env["rules"]), 1)
        self.assertEqual(env["rules"][0]["source_kind"], "user_config")

    def test_trusted_projects_and_hooks(self):
        repos = self.base / "repos"
        good = repos / "good"
        bad = repos / "bad"
        self.write("config.toml", '[projects.' + json.dumps(str(good).upper()) + ']\ntrust_level="trusted"')
        hook = json.dumps({"hooks": {"PreToolUse": [{"matcher": "*", "hooks": [{"type": "command", "command": "echo checked"}]}], "Stop": [{"type": "command", "command": "echo done"}]}})
        self.write("hooks.json", hook)
        for project in (good, bad):
            self.write(".codex/hooks.json", hook, project)
            self.write(".codex/config.toml", 'default_permissions=":danger-full-access"\napproval_policy="never"', project)
            self.write(".codex/rules/project.rules", 'prefix_rule(pattern=["git"])', project)
        env = self.collect(repo_roots=[repos, good])
        self.assertEqual(env["summary"]["project_layers_trusted"], 1)
        self.assertEqual(env["summary"]["project_layers_untrusted"], 1)
        self.assertEqual(env["summary"]["hooks_json_handlers"], 4)
        full = [f for f in env["findings"] if f["id"] == "codex.permissions.full_access"]
        self.assertEqual(len(full), 1)
        self.assertTrue(full[0]["title"].startswith("Codex project config: "))
        self.assertEqual(self.finding(env, "codex.approval.never")["severity"], "critical")
        self.assertTrue(any(r.get("settings_source") == "project .codex/rules" for r in env["rules"]))

    def test_managed_settings(self):
        managed = self.base / "managed"
        self.write("requirements.toml", '''allowed_approval_policies=["on-request"]
allowed_sandbox_modes=["read-only"]
allowed_approvals_reviewers=["user"]
default_permissions=":workspace"
[allowed_permission_profiles]
":workspace"=true
":danger-full-access"=false
''', managed)
        self.write("managed_config.toml", 'default_permissions=":danger-full-access"', managed)
        env = self.collect(managed_dirs=[managed])
        s = env["summary"]
        self.assertTrue(s["managed_requirements_present"])
        self.assertTrue(s["managed_config_present"])
        self.assertEqual(s["managed_allowed_permission_profiles"], [":workspace"])
        self.assertEqual(s["managed_allowed_approval_policies"], ["on-request"])
        self.assertEqual(s["managed_allowed_sandbox_modes"], ["read-only"])
        self.assertEqual(s["managed_allowed_approvals_reviewers"], ["user"])
        self.assertEqual(s["managed_default_permissions"], ":workspace")
        self.assertIn("approval never not allowed", self.finding(env, "codex.managed.requirements_present")["sample_redacted"])
        self.assertTrue(self.finding(env, "codex.permissions.full_access")["title"].startswith("Codex managed defaults: "))

    def test_desktop_counts_and_privacy(self):
        self.write("config.toml", 'approvals_reviewer="auto_review"')
        atom = {"agent-mode-by-host-id": {"local": "fullAccess"}, "skip-full-access-confirm": True,
                "heartbeat-thread-permissions-by-id": {"private-thread-id": {"approvalPolicy": "never", "approvalsReviewer": "auto_review", "sandboxPolicy": {"type": "dangerFullAccess", "networkAccess": True, "writableRoots": ["private-workspace-path"]}}},
                "workspace-path": "private-workspace-path", "account": "someone@example.com", "token": "fake-secret-token"}
        self.write(".codex-global-state.json", json.dumps({"electron-persisted-atom-state": atom}))
        env = self.collect()
        s = env["summary"]
        self.assertEqual(self.finding(env, "codex.desktop.full_access_mode")["severity"], "critical")
        self.assertEqual(self.finding(env, "codex.desktop.thread_full_access")["evidence_count"], 1)
        for key in ("desktop_thread_permissions", "desktop_threads_full_access", "desktop_threads_approval_never", "desktop_threads_auto_review", "desktop_threads_network"):
            self.assertEqual(s[key], 1)
        self.assertEqual(self.finding(env, "codex.approval.auto_review")["evidence_count"], 2)
        self.assertEqual(len([f for f in env["findings"] if f["id"] == "codex.approval.auto_review"]), 1)
        self.assertEqual(s["effective_permissions"], "full-access (desktop app)")
        for private in ("private-thread-id", "private-workspace-path", "someone@example.com", "fake-secret-token"):
            self.assertNotIn(private, json.dumps(env))

    def test_desktop_auto_review_only_title(self):
        threads = {"t1": {"approvalsReviewer": "auto_review"}, "t2": {"approvalsReviewer": "auto_review"}, "t3": {}}
        self.write(".codex-global-state.json", json.dumps({"electron-persisted-atom-state": {"heartbeat-thread-permissions-by-id": threads}}))
        env = self.collect()
        finding = self.finding(env, "codex.desktop.thread_auto_review")
        self.assertEqual(finding["title"], "2 Codex Desktop threads use auto_review approvals")
        self.assertNotIn("codex.approval.auto_review", {f["id"] for f in env["findings"]})
        self.assertEqual(finding["evidence_count"], 2)

    def test_desktop_non_full_access_mode_has_no_finding(self):
        state = {"electron-persisted-atom-state": {"agent-mode-by-host-id": {"local": "guardian-approvals"}}}
        self.write(".codex-global-state.json", json.dumps(state))
        env = self.collect()
        self.assertEqual(env["summary"]["desktop_agent_mode"], "guardian-approvals")
        self.assertEqual([f for f in env["findings"] if f["id"].startswith("codex.desktop.")], [])
        self.assertNotEqual(env["summary"]["effective_permissions"], "full-access (desktop app)")

    def test_rules_unusual_line_separators(self):
        self.write("rules/default.rules", '# note \x0c\nprefix_rule(pattern=["git", "log"])\nprefix_rule(pattern=["ls"])\n')
        env = self.collect()
        self.assertEqual(env["summary"]["rules_allow"], 2)
        self.assertEqual(env["summary"]["rules_unparsed"], 0)

    def test_odd_value_types_do_not_crash(self):
        self.write("config.toml", 'default_permissions=5\napproval_policy=7\napps=3\npermissions=1\nprojects=2\nwindows=4')
        self.write("hooks.json", json.dumps({"hooks": {"Stop": "x", "PreToolUse": [1, {"hooks": 5}]}}))
        self.write(".codex-global-state.json", json.dumps({"electron-persisted-atom-state": {"agent-mode-by-host-id": [], "heartbeat-thread-permissions-by-id": {"a": 1}}}))
        env = self.collect()
        self.assertEqual(env["summary"]["default_permissions"], "unset")

    def test_desktop_fallback(self):
        self.write(".codex-global-state.json", json.dumps({"electron-persisted-atom-state": {"permission-selection-by-host-id:local": {"kind": "agent-mode", "agentMode": "danger-full-access"}}}))
        self.assertEqual(self.collect()["summary"]["desktop_agent_mode"], "full-access")

    def test_parse_errors(self):
        self.write("config.toml", 'invalid = [')
        self.write("hooks.json", '{broken')
        self.write(".codex-global-state.json", '{broken')
        env = self.collect()
        errors = [f for f in env["findings"] if f["id"] == "codex.config.parse_error"]
        self.assertEqual(len(errors), 3)
        self.assertTrue(all(f["severity"] == "low" for f in errors))
        self.assertTrue(any("config.toml" in f["title"] for f in errors))

    def test_invalid_utf8_config(self):
        (self.home / "config.toml").write_bytes(b"\xff")
        self.assertEqual(self.finding(self.collect(), "codex.config.parse_error")["severity"], "low")

    def test_profile_older_settings(self):
        self.write("work.config.toml", 'sandbox_mode="danger-full-access"')
        finding = self.finding(self.collect(), "codex.profile.sandbox_full_access")
        self.assertEqual(finding["severity"], "high")
        self.assertTrue(finding["title"].startswith("Codex profile work: "))

    def test_granular_apps_and_legacy(self):
        self.write("config.toml", '''approval_policy={granular={request_permissions=false}}
[apps._default]
approvals_reviewer="auto_review"
''')
        env = self.collect()
        self.finding(env, "codex.approval.never")
        self.finding(env, "codex.approval.auto_review")
        self.write("config.toml", 'approval_policy="untrusted"')
        env = self.collect()
        self.assertEqual(env["summary"]["legacy_approval_policy"], "untrusted")
        self.assertEqual(env["findings"], [])


if __name__ == "__main__":
    unittest.main()
