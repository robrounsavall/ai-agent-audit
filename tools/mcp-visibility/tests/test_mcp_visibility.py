"""
Tests for the local-first MCP visibility tool.

Run:
    python -m unittest tools/mcp-visibility/tests/test_mcp_visibility.py -v
"""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

TOOLS_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(TOOLS_DIR))

import mcp_visibility as mcp  # noqa: E402


def write_json(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def by_name(inv: dict, name: str) -> list[dict]:
    return [row for row in inv["servers"] if row["server_name"] == name]


class TestMcpVisibilityFixtures(unittest.TestCase):
    def build_inventory(self) -> dict:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        home = root / "home"
        appdata = home / "AppData" / "Roaming"
        repos = home / "cursor-projects"

        bearer = "splunk-live-token-abcdefghijklmnopqrstuvwxyz123456"
        write_json(
            home / ".mcp.json",
            {
                "mcpServers": {
                    "acme-mcp": {"command": "python", "args": ["server.py"]},
                    "splunk-mcp-server": {
                        "command": "npx",
                        "args": [
                            "-y",
                            "mcp-remote",
                            "http://localhost:8001/en-US/splunkd/__raw/services/mcp",
                            "--header",
                            f"Authorization: Bearer {bearer}",
                        ],
                    },
                }
            },
        )
        write_json(home / ".cursor" / "mcp.json", {"mcpServers": {}})
        write_json(
            home / ".claude.json",
            {
                "mcpServers": {
                    "notebooklm-mcp": {"command": "node", "args": ["notebook.js"]}
                },
                "projects": {
                    str(repos / "uigen"): {
                        "mcpServers": {
                            "playwright": {"command": "npx", "args": ["@playwright/mcp"]}
                        },
                        "enabledMcpjsonServers": [],
                        "disabledMcpjsonServers": [],
                    },
                    str(repos / "p-04-learn-app"): {
                        "mcpServers": {},
                        "disabledMcpServers": [
                            "claude.ai Gmail",
                            "claude.ai Google Drive",
                            "notebooklm-mcp",
                        ],
                    },
                },
            },
        )
        write_json(
            home / ".claude" / "settings.local.json",
            {"enabledMcpjsonServers": ["acme-mcp", "notebooklm-mcp"]},
        )
        write_text(
            home / ".codex" / "config.toml",
            """
[mcp_servers.acme-mcp]
command = "python"
args = ["server.py"]
enabled = true

[mcp_servers.splunk-mcp-server]
command = "powershell"
args = ["-File", "splunk-mcp.ps1"]
enabled = true

[mcp_servers.node_repl]
command = "node"
args = ["repl.js"]
""",
        )
        write_json(
            repos / "p-02-content-production-system" / ".cursor" / "mcp.json",
            {
                "mcpServers": {
                    "acme-mcp": {"command": "python", "args": ["different-server.py"]},
                    "notebooklm-mcp": {"command": "node", "args": ["notebook.js"]},
                }
            },
        )
        write_json(
            repos / "acme-app" / ".cursor" / "mcp.json",
            {
                "mcpServers": {
                    "external-docs": {"url": "https://docs.example.com/mcp"}
                }
            },
        )
        write_json(
            repos / "p-99-claude-project" / ".mcp.json",
            {"mcpServers": {"project-claude": {"command": "python", "args": ["mcp.py"]}}},
        )
        write_text(
            home / ".grok" / "config.toml",
            """
[mcp_servers.acme-mcp]
command = "python"
args = ["server.py"]
enabled = true

[mcp_servers.grok-remote]
url = "https://grok-mcp.example.com/mcp"
""",
        )

        return mcp.collect_inventory(
            home=home,
            appdata=appdata,
            repo_roots=[repos],
            include_repo_roots=True,
        )

    def test_collects_expected_server_names(self):
        inv = self.build_inventory()
        names = {row["server_name"] for row in inv["servers"]}
        self.assertTrue(
            {
                "acme-mcp",
                "notebooklm-mcp",
                "splunk-mcp-server",
                "playwright",
                "node_repl",
                "claude.ai Gmail",
                "external-docs",
                "project-claude",
            }.issubset(names)
        )

    def test_claude_references_and_disable_lists(self):
        inv = self.build_inventory()
        gmail = by_name(inv, "claude.ai Gmail")
        self.assertEqual(len(gmail), 1)
        self.assertFalse(gmail[0]["registered"])
        self.assertEqual(gmail[0]["effective_status"], "disabled_reference_only")

        settings_refs = [
            row
            for row in by_name(inv, "acme-mcp")
            if row["platform"] == "claude" and row["source_kind"] == "settings_json"
        ]
        self.assertEqual(len(settings_refs), 1)
        self.assertEqual(settings_refs[0]["effective_status"], "enabled_reference_only")

    def test_codex_enabled_and_unspecified_status(self):
        inv = self.build_inventory()
        codex_acme = [
            row for row in by_name(inv, "acme-mcp") if row["platform"] == "codex"
        ][0]
        self.assertEqual(codex_acme["effective_status"], "enabled")
        self.assertTrue(codex_acme["explicit_enable"])

        node = by_name(inv, "node_repl")[0]
        self.assertEqual(node["platform"], "codex")
        self.assertEqual(node["effective_status"], "enabled_unspecified")

    def test_grok_enabled_and_non_local_endpoint(self):
        inv = self.build_inventory()
        grok_acme = [
            row for row in by_name(inv, "acme-mcp") if row["platform"] == "grok"
        ][0]
        self.assertEqual(grok_acme["effective_status"], "enabled")
        self.assertTrue(grok_acme["explicit_enable"])

        grok_remote = by_name(inv, "grok-remote")[0]
        self.assertEqual(grok_remote["platform"], "grok")
        self.assertEqual(grok_remote["endpoint_locality"], "public_dns")

    def test_cursor_project_entries_and_external_endpoint(self):
        inv = self.build_inventory()
        notebook_cursor = [
            row for row in by_name(inv, "notebooklm-mcp") if row["platform"] == "cursor"
        ]
        self.assertEqual(len(notebook_cursor), 1)
        self.assertEqual(notebook_cursor[0]["effective_status"], "enabled_implicit")

        external = by_name(inv, "external-docs")[0]
        self.assertEqual(external["endpoint_locality"], "public_dns")
        self.assertEqual(external["auth_status"], "oauth_likely")

    def test_bearer_is_masked_and_classified(self):
        inv = self.build_inventory()
        blob = json.dumps(inv, ensure_ascii=False)
        self.assertNotIn("splunk-live-token", blob)
        splunk_shared = [
            row
            for row in by_name(inv, "splunk-mcp-server")
            if row["platform"] == "shared"
        ][0]
        self.assertEqual(splunk_shared["auth_status"], "localhost_with_bearer")
        self.assertIn("Authorization: <redacted>", " ".join(splunk_shared["args"]))
        self.assertTrue(splunk_shared["secret_redacted"])

    def test_duplicate_conflict_detection(self):
        inv = self.build_inventory()
        acme_rows = by_name(inv, "acme-mcp")
        self.assertGreaterEqual(len(acme_rows), 3)
        self.assertTrue(any(row["definition_conflict"] for row in acme_rows))
        self.assertTrue(any(row["duplicate_group"] for row in acme_rows))

    def test_summary_counts(self):
        inv = self.build_inventory()
        summary = inv["summary"]
        self.assertGreaterEqual(summary["servers_total"], 10)
        self.assertGreaterEqual(summary["unique_server_names"], 8)
        self.assertGreaterEqual(summary["duplicate_server_names"], 2)
        self.assertGreaterEqual(summary["conflicting_server_names"], 1)
        self.assertGreaterEqual(summary["secrets_in_config"], 1)
        self.assertGreaterEqual(summary["external_or_nonlocal"], 1)

    def test_summary_report_explains_duplicates(self):
        inv = self.build_inventory()
        report = mcp.render_summary_report(inv)
        self.assertIn("MCP Visibility Summary", report)
        self.assertIn("Server Groups", report)
        self.assertIn("Duplicate Fields Explained", report)
        self.assertIn("Definition drift:", report)
        self.assertIn("definition-drift", report)
        self.assertIn("external-docs", report)


class TestPureHelpers(unittest.TestCase):
    def test_codex_enabled_false(self):
        status, basis, _, explicit_enable, explicit_disable = mcp.derive_codex_status(
            {"enabled": False}
        )
        self.assertEqual(status, "disabled")
        self.assertIn("enabled=false", basis)
        self.assertFalse(explicit_enable)
        self.assertTrue(explicit_disable)

    def test_claude_allowlist_precedence(self):
        status, basis, *_ = mcp.derive_claude_status(
            "server-b",
            {"command": "node"},
            {"enabledMcpjsonServers": {"server-a"}},
        )
        self.assertEqual(status, "disabled_by_allowlist")
        self.assertIn("omits", basis)

    def test_env_secret_keys_do_not_emit_values(self):
        cfg = {
            "command": "node",
            "env": {"API_TOKEN": "abcdefghijklmnopqrstuvwxyz1234567890"},
        }
        status, evidence, keys, secret_redacted = mcp.classify_auth(cfg)
        self.assertEqual(status, "env_configured")
        self.assertIn("API_TOKEN", keys)
        self.assertTrue(secret_redacted)
        self.assertNotIn("abcdefghijklmnopqrstuvwxyz", json.dumps(evidence))

    def test_parse_failure_is_soft(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        path = Path(tmp.name) / ".mcp.json"
        path.write_text("{not json", encoding="utf-8")
        src, records = mcp.parse_mcp_json_source(
            path,
            platform="shared",
            source_kind="global_mcp_json",
            scope="global",
            scope_label="global",
        )
        self.assertTrue(src.exists)
        self.assertFalse(src.parse_ok)
        self.assertEqual(records, [])


if __name__ == "__main__":
    unittest.main()
