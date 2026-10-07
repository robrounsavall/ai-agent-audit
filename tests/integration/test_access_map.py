"""Unit tests for the cross-agent access map.

Run from the repo root:
    python -m unittest discover -s tests/integration -p "test_access_map.py" -v
"""

from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "report"))

import access_map  # noqa: E402
from access_map import UNCAPTURED, build_access_map  # noqa: E402
from sections.access_map import render_access_map_nav, render_access_map_section  # noqa: E402

DEMO = ROOT / "samples" / "synthetic-demo" / "evidence"
VALUES = {"yes", "no", "partial", "unknown"}
EVIDENCE_LEVELS = {"none", "low", "moderate", "high"}


def _load_demo() -> dict[str, dict]:
    envelopes = {}
    for path in sorted(DEMO.glob("*.json")):
        envelopes[path.stem] = json.loads(path.read_text(encoding="utf-8"))
    return envelopes


def _grok_bot_fixture() -> dict:
    return {
        "collector": "grok-bot",
        "version": "1.0.0",
        "platform_detected": True,
        "summary": {
            "app_present": True,
            "local_execution": "unknown",
            "local_execution_reason": "not_determinable_offline",
            "sand_secrets_present": True,
            "sand_secrets_bytes": 256,
            "box_secrets_push_state_present": True,
            "box_secrets_push_state_bytes": 128,
            "lockfile_present": True,
            "browser_state_present": True,
            "client_persistence_present": True,
            "findings": 2,
        },
        "findings": [
            {
                "id": "grok_bot.secrets.store_present",
                "severity": "medium",
                "category": "Secrets Exposure",
                "title": "Grok Bot secrets store is present on this endpoint (contents excluded)",
                "evidence_count": 2,
                "tags": ["auth_excluded"],
            }
        ],
        "rules": [],
    }


def _cloud_agents_fixture() -> dict:
    return {
        "collector": "cloud-agents",
        "version": "1.0.0",
        "platform_detected": True,
        "summary": {
            "key_configured": True,
            "api": "https://api.cursor.com",
            "total_agents": 1,
            "agents_active": 1,
            "agents_running": 1,
            "agents_with_prs": 1,
            "total_tokens": 8000,
            "by_status": {"ACTIVE": 1},
            "agent_errors": 0,
            "usage_unavailable": 0,
            "include_run_result": False,
        },
        "findings": [
            {
                "id": "cloud_agents.active_current_branch",
                "severity": "high",
                "category": "Source Code Egress",
                "title": "Active cloud agent can push to the repository's current branch",
                "evidence_count": 1,
                "tags": ["cloud_agent", "repo_write", "current_branch"],
            }
        ],
        "rules": [],
        "agents": [
            {
                "id": "bc-demo-active",
                "name": "Demo README agent",
                "status": "ACTIVE",
                "env_type": "cloud",
                "repos": [{"url": "https://github.com/example/demo-repo", "starting_ref": "main", "pr_url": ""}],
                "work_on_current_branch": True,
                "auto_create_pr": True,
                "branches": [
                    {
                        "repo_url": "github.com/example/demo-repo",
                        "branch": "cursor/demo-readme",
                        "pr_url": "https://github.com/example/demo-repo/pull/14",
                    }
                ],
                "tokens": {"total_tokens": 8000},
            }
        ],
    }


class AccessMapSyntheticTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.envelopes = _load_demo()
        cls.grid = build_access_map(cls.envelopes)

    def test_shape(self) -> None:
        self.assertEqual([row["id"] for row in self.grid["rows"]], [agent[0] for agent in access_map.AGENTS])
        self.assertEqual([column["id"] for column in self.grid["columns"]], [column[0] for column in access_map.COLUMNS])
        for row in self.grid["rows"]:
            for column in self.grid["columns"]:
                cell = self.grid["cells"][row["id"]][column["id"]]
                self.assertIn(cell["value"], VALUES)
                self.assertIn(cell["evidence"], EVIDENCE_LEVELS)
                self.assertTrue(cell["reason"])
                self.assertEqual(cell["anchor"], f"access-evidence-{row['id']}-{column['id']}")
                self.assertTrue(cell["sources"])

    def test_headline_counts_yes_only(self) -> None:
        self.assertEqual(self.grid["counts"], {"shell_yes": 2, "git_yes": 0})
        self.assertEqual(self.grid["headline"], "2 agents can run shell commands; 0 can push to GitHub.")

    def test_claude_synthetic(self) -> None:
        cells = self.grid["cells"]["claude"]
        self.assertEqual(cells["shell"]["value"], "yes")
        self.assertIn("Bash(*)", cells["shell"]["reason"])
        self.assertEqual(cells["files"]["value"], "partial")
        self.assertEqual(cells["network"]["value"], "yes")
        self.assertEqual(cells["network"]["mcp_count"], 1)
        self.assertIn("playwright", cells["network"]["reason"])
        self.assertEqual(cells["secrets"]["value"], "unknown")
        self.assertEqual(cells["git"]["value"], "partial")
        self.assertEqual(cells["remote"]["value"], "unknown")
        self.assertEqual(cells["approval"]["value"], "partial")
        self.assertIn("Dangerous-mode", cells["approval"]["reason"])

    def test_codex_synthetic_sandbox_bypass(self) -> None:
        cells = self.grid["cells"]["codex"]
        self.assertEqual(cells["shell"]["value"], "yes")
        self.assertEqual(cells["approval"]["value"], "yes")
        self.assertIn("Auto-approve", cells["approval"]["reason"])
        self.assertEqual(cells["files"]["value"], "partial")
        self.assertEqual(cells["network"]["value"], "partial")
        self.assertEqual(cells["network"]["mcp_count"], 0)
        self.assertEqual(cells["secrets"]["value"], "unknown")
        self.assertEqual(cells["git"]["value"], "partial")
        self.assertEqual(cells["remote"]["value"], "unknown")

    def test_grok_synthetic(self) -> None:
        cells = self.grid["cells"]["grok"]
        self.assertEqual(cells["approval"]["value"], "yes")
        self.assertIn("always-approve", cells["approval"]["reason"])
        self.assertEqual(cells["network"]["value"], "yes")
        self.assertEqual(cells["network"]["mcp_count"], 1)
        self.assertEqual(cells["shell"]["value"], "unknown")
        self.assertEqual(cells["files"]["value"], "unknown")
        self.assertEqual(cells["secrets"]["value"], "unknown")
        self.assertEqual(cells["git"]["value"], "unknown")
        self.assertEqual(cells["remote"]["value"], "unknown")

    def test_cursor_and_copilot_stay_unknown_without_signals(self) -> None:
        for agent in ("cursor", "copilot"):
            cells = self.grid["cells"][agent]
            for column in ("shell", "files", "secrets", "git", "remote", "approval"):
                self.assertEqual(cells[column]["value"], "unknown", f"{agent}.{column}")
        self.assertEqual(self.grid["cells"]["cursor"]["network"]["value"], "unknown")
        self.assertEqual(self.grid["cells"]["cursor"]["network"]["mcp_count"], 0)
        self.assertIsNone(self.grid["cells"]["copilot"]["network"]["mcp_count"])
        self.assertEqual(self.grid["cells"]["copilot"]["network"]["value"], "unknown")

    def test_optional_collectors_missing_are_unknown(self) -> None:
        self.assertNotIn("grok-bot", self.envelopes)
        self.assertNotIn("cloud-agents", self.envelopes)
        for agent in ("grok-bot", "cloud-agents", "cowork"):
            row = next(item for item in self.grid["rows"] if item["id"] == agent)
            self.assertFalse(row["present"])
            for cell in self.grid["cells"][agent].values():
                self.assertEqual(cell["value"], "unknown")
                self.assertIn("Not collected", cell["reason"])

    def test_secrets_scan_does_not_bleed_into_agents(self) -> None:
        self.assertGreaterEqual(self.envelopes["secrets-scan"]["summary"]["hits"], 1)
        self.assertEqual(self.grid["cells"]["claude"]["secrets"]["value"], "unknown")
        self.assertEqual(self.grid["cells"]["cursor"]["secrets"]["value"], "unknown")


class AccessMapFixtureTests(unittest.TestCase):
    def test_grok_bot_secrets_and_explicit_unknown_shell(self) -> None:
        envelopes = _load_demo()
        fixture = _grok_bot_fixture()
        fixture["rules"] = [
            {
                "platform": "grok-bot",
                "rule_type": "bash",
                "rule": "Bash(*)",
                "decision": "allow",
                "command_or_tool_redacted": "*",
            }
        ]
        envelopes["grok-bot"] = fixture
        grid = build_access_map(envelopes)
        cells = grid["cells"]["grok-bot"]
        self.assertTrue(next(row["present"] for row in grid["rows"] if row["id"] == "grok-bot"))
        self.assertEqual(cells["secrets"]["value"], "yes")
        self.assertIn("sand-secrets.json", cells["secrets"]["reason"])
        self.assertEqual(cells["shell"]["value"], "unknown")
        self.assertIn("not_determinable_offline", cells["shell"]["reason"])
        self.assertEqual(cells["git"]["value"], "unknown")
        self.assertIn("not a git push", cells["git"]["reason"])
        self.assertEqual(cells["remote"]["value"], "unknown")
        self.assertEqual(cells["files"]["value"], "unknown")
        self.assertEqual(cells["approval"]["value"], "unknown")
        self.assertIsNone(cells["network"]["mcp_count"])
        self.assertEqual(cells["network"]["value"], "unknown")

    def test_cloud_agents_remote_and_git(self) -> None:
        envelopes = _load_demo()
        envelopes["cloud-agents"] = _cloud_agents_fixture()
        grid = build_access_map(envelopes)
        cells = grid["cells"]["cloud-agents"]
        self.assertEqual(cells["remote"]["value"], "yes")
        self.assertIn("cloud", cells["remote"]["reason"])
        self.assertEqual(cells["git"]["value"], "yes")
        self.assertEqual(cells["files"]["value"], "yes")
        self.assertEqual(cells["network"]["value"], "partial")
        self.assertIsNone(cells["network"]["mcp_count"])
        self.assertEqual(cells["shell"]["value"], "unknown")
        self.assertEqual(cells["secrets"]["value"], "unknown")
        self.assertEqual(cells["approval"]["value"], "unknown")
        self.assertEqual(grid["headline"], "2 agents can run shell commands; 1 can push to GitHub.")

    def test_empty_cloud_inventory_is_no_not_a_crash(self) -> None:
        grid = build_access_map(
            {
                "cloud-agents": {
                    "collector": "cloud-agents",
                    "platform_detected": True,
                    "summary": {"key_configured": True, "total_agents": 0, "agents_with_prs": 0},
                    "agents": [],
                    "findings": [],
                    "rules": [],
                }
            }
        )
        cells = grid["cells"]["cloud-agents"]
        self.assertEqual(cells["remote"]["value"], "no")
        self.assertEqual(cells["git"]["value"], "no")
        self.assertEqual(cells["files"]["value"], "no")
        self.assertEqual(cells["shell"]["value"], "unknown")
        self.assertEqual(cells["approval"]["value"], "unknown")

    def test_missing_api_key_is_not_collected(self) -> None:
        grid = build_access_map(
            {
                "cloud-agents": {
                    "collector": "cloud-agents",
                    "platform_detected": False,
                    "summary": {"key_configured": False, "total_agents": 0},
                    "agents": [],
                }
            }
        )
        self.assertFalse(next(row["present"] for row in grid["rows"] if row["id"] == "cloud-agents"))
        self.assertIn("CURSOR_API_KEY", grid["cells"]["cloud-agents"]["shell"]["reason"])

    def test_codex_read_only_and_ask(self) -> None:
        grid = build_access_map(
            {
                "codex": {
                    "collector": "codex",
                    "platform_detected": True,
                    "summary": {
                        "sandbox_mode": "read-only",
                        "approval_policy": "on-request",
                        "mcp_servers": 0,
                    },
                    "findings": [],
                    "rules": [],
                }
            }
        )
        cells = grid["cells"]["codex"]
        self.assertEqual(cells["files"]["value"], "no")
        self.assertEqual(cells["shell"]["value"], "partial")
        self.assertEqual(cells["approval"]["value"], "partial")
        self.assertIn("on-request", cells["approval"]["reason"])
        self.assertIn("read-only", cells["approval"]["reason"])
        self.assertEqual(cells["network"]["mcp_count"], 0)
        self.assertEqual(cells["network"]["value"], "unknown")

    def test_grok_shell_tool_and_default_mode(self) -> None:
        grid = build_access_map(
            {
                "grok": {
                    "collector": "grok",
                    "platform_detected": True,
                    "summary": {
                        "permission_mode": "default",
                        "yolo": False,
                        "mcp_servers": 0,
                        "mcp_runtime_servers": 2,
                        "tools_used_distribution": {"run_terminal_command": 3, "read_file": 1},
                    },
                    "findings": [],
                    "rules": [],
                }
            }
        )
        cells = grid["cells"]["grok"]
        self.assertEqual(cells["shell"]["value"], "yes")
        self.assertIn("run_terminal_command", cells["shell"]["reason"])
        self.assertEqual(cells["approval"]["value"], "no")
        self.assertIn("default", cells["approval"]["reason"])
        self.assertEqual(cells["network"]["value"], "yes")
        self.assertEqual(cells["network"]["mcp_count"], 2)
        self.assertIn("runtime", cells["network"]["reason"])

    def test_claude_bypass_and_git_grant(self) -> None:
        grid = build_access_map(
            {
                "claude": {
                    "collector": "claude",
                    "platform_detected": True,
                    "summary": {"allow_rules": 1, "ask_rules": 0, "desktop_mcp_servers": 0},
                    "findings": [
                        {
                            "id": "claude.permission.bypass_mode",
                            "severity": "critical",
                            "category": "Shell Execution",
                            "title": "Claude default permission mode bypasses prompts",
                        }
                    ],
                    "rules": [
                        {
                            "rule_type": "bash",
                            "rule": "Bash(git push:*)",
                            "decision": "allow",
                            "command_or_tool_redacted": "git",
                        }
                    ],
                }
            }
        )
        cells = grid["cells"]["claude"]
        self.assertEqual(cells["approval"]["value"], "yes")
        self.assertEqual(cells["shell"]["value"], "yes")
        self.assertEqual(cells["git"]["value"], "yes")
        self.assertEqual(cells["network"]["mcp_count"], 0)

    def test_cowork_outputs_and_bridge(self) -> None:
        grid = build_access_map(
            {
                "cowork": {
                    "collector": "cowork",
                    "platform_detected": True,
                    "summary": {"output_files": 4, "bridge_synced_sessions": 2, "design_used": True},
                    "findings": [
                        {
                            "id": "cowork.bridge.remote_sync",
                            "category": "Network Egress",
                            "evidence_count": 2,
                        }
                    ],
                    "rules": [],
                }
            }
        )
        cells = grid["cells"]["cowork"]
        self.assertEqual(cells["files"]["value"], "yes")
        self.assertEqual(cells["remote"]["value"], "yes")
        self.assertEqual(cells["network"]["value"], "yes")
        self.assertIsNone(cells["network"]["mcp_count"])
        self.assertEqual(cells["shell"]["value"], "unknown")
        self.assertEqual(cells["approval"]["value"], "unknown")

    def test_copilot_egress_is_partial(self) -> None:
        grid = build_access_map(
            {
                "copilot": {
                    "collector": "copilot",
                    "platform_detected": True,
                    "summary": {
                        "public_code_suggestions": "enabled",
                        "telemetry": "all",
                        "vscode_copilot_enabled": True,
                    },
                    "findings": [],
                    "rules": [],
                }
            }
        )
        cells = grid["cells"]["copilot"]
        self.assertEqual(cells["network"]["value"], "partial")
        self.assertEqual(cells["remote"]["value"], "partial")
        self.assertEqual(cells["shell"]["value"], "unknown")
        self.assertEqual(cells["approval"]["value"], "unknown")

    def test_cursor_other_rule_bash_text_counts_as_shell(self) -> None:
        grid = build_access_map(
            {
                "cursor": {
                    "collector": "cursor",
                    "platform_detected": True,
                    "summary": {"mcp_registered": 0},
                    "findings": [],
                    "rules": [
                        {
                            "rule_type": "other",
                            "rule": "Bash(*)",
                            "decision": "allow",
                            "command_or_tool_redacted": "Bash(*)",
                        }
                    ],
                }
            }
        )
        self.assertEqual(grid["cells"]["cursor"]["shell"]["value"], "yes")
        self.assertIn("Bash(*)", grid["cells"]["cursor"]["shell"]["reason"])

    def test_cursor_auto_accept_is_partial(self) -> None:
        grid = build_access_map(
            {
                "cursor": {
                    "collector": "cursor",
                    "platform_detected": True,
                    "summary": {
                        "mcp_registered": 3,
                        "composer_auto_accept_workspaces": 2,
                        "durable_allowlist_found": False,
                    },
                    "findings": [
                        {
                            "id": "cursor.permissions.no_durable_allowlist",
                            "category": "General Tooling",
                        }
                    ],
                    "rules": [],
                }
            }
        )
        cells = grid["cells"]["cursor"]
        self.assertEqual(cells["network"]["value"], "yes")
        self.assertEqual(cells["network"]["mcp_count"], 3)
        self.assertEqual(cells["approval"]["value"], "partial")
        self.assertEqual(cells["shell"]["value"], "unknown")
        self.assertEqual(cells["remote"]["value"], "unknown")

    def test_uncaptured_cells_stay_unknown_under_noise(self) -> None:
        noisy = {
            "collector": "noise",
            "platform_detected": True,
            "summary": {
                "permission_mode": "always-approve",
                "yolo": True,
                "mcp_servers": 4,
                "sandbox_mode": "danger-full-access",
                "approval_policy": "never",
                "auth_json_exists": True,
                "sand_secrets_present": True,
                "output_files": 9,
                "bridge_synced_sessions": 3,
                "local_execution": "enabled",
            },
            "findings": [
                {"id": "claude.permission.bypass_mode", "category": "Shell Execution"},
                {"id": "codex.sandbox.bypass", "category": "Shell Execution", "sample_redacted": "sandbox=disabled"},
                {"id": "secrets", "category": "Secrets Exposure", "secret_redacted": True},
            ],
            "rules": [
                {
                    "rule_type": "bash",
                    "rule": "Bash(*)",
                    "decision": "allow",
                    "command_or_tool_redacted": "*",
                }
            ],
            "agents": [
                {
                    "env_type": "cloud",
                    "work_on_current_branch": True,
                    "auto_create_pr": True,
                    "repos": [{"url": "https://github.com/example/demo", "pr_url": "https://github.com/example/demo/pull/1"}],
                    "branches": [{"branch": "cursor/x", "pr_url": "https://github.com/example/demo/pull/1"}],
                }
            ],
        }
        envelopes = {collector: dict(noisy, collector=collector) for _agent, _label, collector in access_map.AGENTS}
        grid = build_access_map(envelopes)
        for (agent_id, column_id), reason in UNCAPTURED.items():
            cell = grid["cells"][agent_id][column_id]
            self.assertEqual(cell["value"], "unknown", f"{agent_id}.{column_id}")
            self.assertEqual(cell["reason"], reason)
            self.assertEqual(cell["evidence"], "none")

    def test_empty_input(self) -> None:
        grid = build_access_map({})
        self.assertEqual(len(grid["rows"]), 8)
        self.assertEqual(grid["headline"], "0 agents can run shell commands; 0 can push to GitHub.")
        for row in grid["cells"].values():
            for cell in row.values():
                self.assertEqual(cell["value"], "unknown")


class AccessMapRenderTests(unittest.TestCase):
    def test_section_links_legend_and_escaping(self) -> None:
        envelopes = _load_demo()
        envelopes["claude"] = json.loads(json.dumps(envelopes["claude"]))
        envelopes["claude"]["rules"][0]["command_or_tool_redacted"] = "<b>"
        envelopes["claude"]["rules"][0]["rule"] = "mcp__<b>"
        html = render_access_map_section(envelopes)
        self.assertIn('id="access-map"', html)
        self.assertIn("2 agents can run shell commands; 0 can push to GitHub.", html)
        self.assertIn("access-legend", html)
        self.assertIn("access-cell--yes", html)
        self.assertIn("access-cell--unknown", html)
        self.assertIn("pill critical", html)
        self.assertIn("pill skipped", html)
        self.assertIn("pill medium", html)
        self.assertNotIn("<b>", html)
        self.assertIn("&lt;b&gt;", html)
        grid = build_access_map(envelopes)
        for row in grid["rows"]:
            for column in grid["columns"]:
                anchor = grid["cells"][row["id"]][column["id"]]["anchor"]
                self.assertIn(f"href='#{anchor}'", html)
                self.assertIn(f"id='{anchor}'", html)
        nav = render_access_map_nav(envelopes)
        self.assertEqual(nav, '<a href="#access-map">Access</a>')

    def test_preview_script_writes_html(self) -> None:
        import subprocess
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "preview.html"
            result = subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "scripts" / "preview-access-map.py"),
                    "--evidence-root",
                    str(ROOT / "samples" / "synthetic-demo"),
                    "--out",
                    str(out),
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            text = out.read_text(encoding="utf-8")
            self.assertIn('id="access-map"', text)
            self.assertIn("posture-grid", text)
            self.assertIn("<style>", text)
