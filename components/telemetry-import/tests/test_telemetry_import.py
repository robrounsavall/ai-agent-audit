"""Unit tests for the telemetry-import collector and its report section."""

from __future__ import annotations

import ast
import hashlib
import html
import importlib.util
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

os.environ.setdefault("USERPROFILE", r"C:\Users\Test User")
os.environ.setdefault("APPDATA", r"C:\Users\Test User\AppData\Roaming")
os.environ.pop("AISCAN_REDACT", None)

import bootstrap  # noqa: E402,F401

_MOD_PATH = Path(__file__).resolve().parent.parent / "telemetry-import.py"
_SPEC = importlib.util.spec_from_file_location("telemetry_import_mod", _MOD_PATH)
ti = importlib.util.module_from_spec(_SPEC)
assert _SPEC.loader is not None
sys.modules["telemetry_import_mod"] = ti
_SPEC.loader.exec_module(ti)

_REPO = Path(__file__).resolve().parents[3]
_SAMPLES = _REPO / "samples" / "telemetry-import"
_SECTION_PATH = _REPO / "report" / "sections" / "telemetry.py"
_SECTION_SPEC = importlib.util.spec_from_file_location("telemetry_section", _SECTION_PATH)
section = importlib.util.module_from_spec(_SECTION_SPEC)
assert _SECTION_SPEC.loader is not None
sys.modules["telemetry_section"] = section
_SECTION_SPEC.loader.exec_module(section)

SENTINELS = (
    "SENTINEL_PROMPT_do_not_store",
    "SENTINEL_COMMAND_do_not_store",
    "SENTINEL_SERVER_do_not_store",
    "SENTINEL_NOTES_do_not_store",
    "sentinel.user@example.com",
    "toolu_SENTINEL_USE_ID",
    "https://sentinel.example/do-not-store",
)


def _dump(envelope: dict, raw_root: Path | None = None) -> str:
    chunks = [json.dumps(envelope)]
    if raw_root is not None:
        folder = raw_root / "telemetry-import"
        if folder.exists():
            for path in folder.iterdir():
                chunks.append(path.read_text(encoding="utf-8"))
    return "\n".join(chunks)


class TestNoExport(unittest.TestCase):
    def test_not_detected_envelope_and_exit_code(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            stdout, stderr = io.StringIO(), io.StringIO()
            with redirect_stdout(stdout), redirect_stderr(stderr):
                code = ti.run(["--evidence-root", str(root)])
            self.assertEqual(code, 2)
            self.assertIn("not on disk", stderr.getvalue())
            written = json.loads((root / "evidence" / "telemetry.json").read_text(encoding="utf-8"))
        self.assertEqual(written["collector"], "telemetry")
        self.assertEqual(written["version"], "1.0.0")
        self.assertFalse(written["platform_detected"])
        self.assertEqual(written["summary"]["status"], "not_detected")
        self.assertEqual(written["summary"]["note"], ti.NOTE_NO_EXPORT)
        self.assertLessEqual(len(written["summary"]["note"]), 64)
        ids = [finding["id"] for finding in written["findings"]]
        self.assertIn("telemetry.coverage.approvals_require_otel", ids)
        self.assertIn("tool_decision", written["findings"][0]["title"])

    def test_missing_file_is_not_detected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            stdout, stderr = io.StringIO(), io.StringIO()
            with redirect_stdout(stdout), redirect_stderr(stderr):
                code = ti.run(
                    ["--evidence-root", str(root), "--otel-file", str(root / "missing.json")]
                )
            self.assertEqual(code, 2)
            written = json.loads((root / "evidence" / "telemetry.json").read_text(encoding="utf-8"))
        self.assertFalse(written["platform_detected"])
        self.assertEqual(written["summary"]["inputs_failed"], 1)
        ids = [finding["id"] for finding in written["findings"]]
        self.assertIn("telemetry.import.unreadable", ids)
        self.assertNotIn("missing.json", json.dumps(written["findings"]))

    def test_section_empty_without_evidence(self):
        envelope = ti.collect([])
        self.assertEqual(section.render_approvals_section(envelope), "")
        self.assertEqual(section.render_usage_section(envelope), "")
        self.assertEqual(section.telemetry_nav_links(envelope), "")
        self.assertEqual(section.render_approvals_section(None), "")
        self.assertEqual(section.render_usage_section({}), "")


class TestApprovals(unittest.TestCase):
    def test_otlp_sample_rollup_drops_content(self):
        sample = _SAMPLES / "otel-tool-decisions.json"
        with tempfile.TemporaryDirectory() as tmp:
            raw = Path(tmp) / "raw"
            envelope = ti.collect([sample], raw_root=raw)
            blob = _dump(envelope, raw)
            decisions = raw / "telemetry-import" / "decisions.jsonl"
            self.assertTrue(decisions.exists())
            pointer = envelope["raw_pointers"][0]
            self.assertEqual(pointer["path"], "raw/telemetry-import/decisions.jsonl")
            self.assertEqual(pointer["sha256"], hashlib.sha256(decisions.read_bytes()).hexdigest())
        for sentinel in SENTINELS:
            self.assertNotIn(sentinel, blob)
        self.assertTrue(envelope["platform_detected"])
        summary = envelope["summary"]
        self.assertEqual(summary["approval_events"], 5)
        self.assertEqual(summary["approvals"], 4)
        self.assertEqual(summary["denials"], 1)
        self.assertEqual(summary["config_approvals"], 3)
        self.assertEqual(summary["hook_approvals"], 1)
        self.assertEqual(summary["user_approvals"], 0)
        self.assertEqual(summary["config_approval_percent"], 75)
        self.assertGreater(summary["sensitive_attributes_dropped"], 0)
        self.assertEqual(summary["usage_events"], 0)

        by_source = {row["source"]: row for row in summary["approvals_by_source"]}
        self.assertEqual(by_source["config"]["approvals"], 3)
        self.assertEqual(by_source["config"]["group"], "config rule")
        self.assertEqual(by_source["hook"]["approvals"], 1)
        self.assertEqual(by_source["hook"]["group"], "hook")
        self.assertEqual(by_source["user_reject"]["denials"], 1)
        self.assertEqual(by_source["user_reject"]["group"], "user")

        by_day = {row["day"]: row for row in summary["approvals_by_day"]}
        self.assertEqual(by_day["2026-04-02"]["approvals"], 4)
        self.assertEqual(by_day["2026-04-03"]["denials"], 1)

        tools = {row["tool"]: row for row in summary["approvals_by_tool"]}
        self.assertEqual(tools["Bash"]["auto_approved"], 1)
        self.assertEqual(tools["Bash"]["denials"], 1)
        self.assertEqual(tools["Write"]["unprompted"], 1)
        self.assertEqual(tools["WebFetch"]["unprompted"], 1)
        self.assertIn("mcp:demo_tool", tools)
        self.assertEqual(tools["mcp:demo_tool"]["auto_approved"], 1)
        self.assertEqual(tools["Bash"]["harness"], "claude")

        top = [row["tool"] for row in summary["top_auto_approved"]]
        self.assertEqual(set(top), {"Bash", "Write", "mcp:demo_tool"})

        ids = {finding["id"] for finding in envelope["findings"]}
        self.assertIn("telemetry.approval.blanket_allow_share", ids)
        self.assertIn("telemetry.approval.unprompted_shell", ids)
        self.assertIn("telemetry.approval.unprompted_write", ids)
        self.assertIn("telemetry.approval.unprompted_webfetch", ids)
        self.assertIn("telemetry.approval.unprompted_mcp", ids)
        self.assertIn("telemetry.coverage.approvals_require_otel", ids)
        blanket = next(f for f in envelope["findings"] if f["id"] == "telemetry.approval.blanket_allow_share")
        self.assertEqual(blanket["severity"], "high")
        self.assertIn("75%", blanket["title"])
        self.assertEqual(envelope["rules"], [])
        self.assertEqual(len(envelope["raw_pointers"][0]["sha256"]), 64)

    def test_jsonl_and_decision_synonyms(self):
        envelope = ti.collect([_SAMPLES / "otel-tool-decisions.jsonl"])
        summary = envelope["summary"]
        self.assertEqual(summary["approval_events"], 2)
        self.assertEqual(summary["approvals"], 1)
        self.assertEqual(summary["denials"], 1)
        tools = {row["tool"]: row for row in summary["approvals_by_tool"]}
        self.assertEqual(tools["Write"]["auto_approved"], 1)
        self.assertEqual(tools["WebFetch"]["denials"], 1)
        blob = _dump(envelope)
        self.assertNotIn("SENTINEL_COMMAND_do_not_store", blob)
        self.assertNotIn("SENTINEL_PROMPT_do_not_store", blob)

    def test_splunk_approve_synonym_and_groups(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "rows.jsonl"
            path.write_text(
                "\n".join(
                    [
                        json.dumps(
                            {
                                "event.name": "tool_decision",
                                "tool_name": "Bash",
                                "decision": "approve",
                                "source": "config",
                                "_time": "2026-04-04T00:00:00Z",
                            }
                        ),
                        json.dumps(
                            {
                                "tool": "Write",
                                "decision": "deny",
                                "source": "user-permanent",
                                "timestamp": "2026-04-04T02:00:00Z",
                            }
                        ),
                        json.dumps(
                            {
                                "tool_name": "Bash",
                                "decision": "accept",
                                "source": "echo SENTINEL_COMMAND_do_not_store",
                                "event.timestamp": "2026-04-04T03:00:00Z",
                            }
                        ),
                    ]
                ),
                encoding="utf-8",
            )
            envelope = ti.collect(splunk_files=[path])
        blob = _dump(envelope)
        self.assertNotIn("SENTINEL_COMMAND_do_not_store", blob)
        summary = envelope["summary"]
        self.assertEqual(summary["approvals"], 2)
        self.assertEqual(summary["denials"], 1)
        by_source = {row["source"]: row for row in summary["approvals_by_source"]}
        self.assertEqual(by_source["config"]["approvals"], 1)
        self.assertEqual(by_source["user_permanent"]["denials"], 1)
        self.assertEqual(by_source["unknown"]["approvals"], 1)
        self.assertNotIn("echo", json.dumps(summary["approvals_by_source"]))

    def test_duplicate_tool_use_id_counts_once(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "dup.json"
            path.write_text(
                json.dumps(
                    [
                        {
                            "event.name": "tool_decision",
                            "tool_name": "Read",
                            "decision": "accept",
                            "source": "user_temporary",
                            "tool_use_id": "toolu_same",
                            "event.timestamp": "2026-04-02T00:00:00Z",
                        },
                        {
                            "event.name": "tool_decision",
                            "tool_name": "Read",
                            "decision": "accept",
                            "source": "user_temporary",
                            "tool_use_id": "toolu_same",
                            "event.timestamp": "2026-04-02T00:00:01Z",
                        },
                    ]
                ),
                encoding="utf-8",
            )
            envelope = ti.collect([path])
        self.assertEqual(envelope["summary"]["approval_events"], 1)
        self.assertNotIn("toolu_same", _dump(envelope))

    def test_command_shaped_tool_name_is_not_stored(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "cmd.json"
            path.write_text(
                json.dumps(
                    {
                        "event.name": "tool_decision",
                        "tool_name": "Bash rm -rf SENTINEL_COMMAND_inline",
                        "decision": "accept",
                        "source": "config",
                    }
                ),
                encoding="utf-8",
            )
            envelope = ti.collect([path])
        self.assertNotIn("SENTINEL_COMMAND_inline", _dump(envelope))
        self.assertEqual(envelope["summary"]["approvals_by_tool"][0]["tool"], "redacted")


class TestUsage(unittest.TestCase):
    def test_cursor_csv_cost_is_labeled_and_not_estimated(self):
        envelope = ti.collect(splunk_files=[_SAMPLES / "splunk-cursor-usage.csv"])
        summary = envelope["summary"]
        self.assertEqual(summary["usage_events"], 3)
        self.assertEqual(summary["total_tokens"], 260)
        self.assertEqual(summary["input_tokens"], 170)
        self.assertEqual(summary["output_tokens"], 75)
        self.assertEqual(summary["cache_read_tokens"], 10)
        self.assertEqual(summary["cache_write_tokens"], 5)
        self.assertEqual(summary["cost_cents"], 20)
        self.assertEqual(summary["cost_basis"], "cursor_dashboard")
        self.assertEqual(summary["cost_label"], "from the Cursor dashboard usage export")
        self.assertEqual(summary["usage_rows_with_cost"], 2)
        self.assertEqual(summary["usage_rows_tokens_only"], 1)
        self.assertEqual(summary["approval_events"], 0)
        by_model = {row["model"]: row for row in summary["usage_by_model"]}
        self.assertEqual(by_model["example-small"]["cost_cents"], 12)
        self.assertEqual(by_model["example-small"]["tokens_only_rows"], 1)
        self.assertEqual(by_model["example-large"]["cost_cents"], 8)
        kinds = {row["tool"] for row in summary["usage_by_tool"]}
        self.assertEqual(kinds, {"agent", "chat"})
        self.assertTrue(all(row["harness"] == "cursor" for row in summary["usage_by_tool"]))

    def test_generic_rows_are_tokens_only(self):
        envelope = ti.collect(splunk_files=[_SAMPLES / "generic-tokens.csv"])
        summary = envelope["summary"]
        blob = _dump(envelope)
        self.assertNotIn("9.99", blob)
        self.assertNotIn("1.50", blob)
        self.assertNotIn("cost_usd", blob)
        self.assertNotIn("cost_cents", summary)
        self.assertEqual(summary["cost_basis"], "tokens_only")
        self.assertEqual(summary["cost_label"], "tokens only")
        self.assertEqual(summary["usage_events"], 2)
        self.assertEqual(summary["total_tokens"], 120)
        self.assertEqual(summary["input_tokens"], 90)
        self.assertEqual(summary["output_tokens"], 30)
        harnesses = {row["harness"] for row in summary["usage_by_tool"]}
        self.assertEqual(harnesses, {"codex", "grok"})

    def test_splunk_json_mixes_approval_and_cursor_cost(self):
        envelope = ti.collect(splunk_files=[_SAMPLES / "splunk-results.json"])
        summary = envelope["summary"]
        self.assertEqual(summary["approvals"], 1)
        self.assertEqual(summary["approvals_by_tool"][0]["tool"], "Bash")
        self.assertEqual(summary["usage_events"], 1)
        self.assertEqual(summary["cost_cents"], 3)
        self.assertEqual(summary["total_tokens"], 12)
        self.assertEqual(summary["cost_label"], "from the Cursor dashboard usage export")
        self.assertNotIn("SENTINEL_COMMAND_do_not_store", _dump(envelope))

    def test_combined_exports_do_not_price_generic_tokens(self):
        envelope = ti.collect(
            [_SAMPLES / "otel-tool-decisions.json"],
            [_SAMPLES / "splunk-cursor-usage.csv", _SAMPLES / "generic-tokens.csv"],
        )
        summary = envelope["summary"]
        self.assertEqual(summary["approval_events"], 5)
        self.assertEqual(summary["usage_events"], 5)
        self.assertEqual(summary["total_tokens"], 380)
        self.assertEqual(summary["cost_cents"], 20)
        self.assertEqual(summary["inputs_read"], 3)
        blob = _dump(envelope)
        self.assertNotIn("9.99", blob)
        self.assertNotIn("SENTINEL_PROMPT_do_not_store", blob)


class TestRedaction(unittest.TestCase):
    def setUp(self):
        self._saved = os.environ.get("AISCAN_REDACT")
        os.environ.pop("AISCAN_REDACT", None)

    def tearDown(self):
        if self._saved is None:
            os.environ.pop("AISCAN_REDACT", None)
        else:
            os.environ["AISCAN_REDACT"] = self._saved

    def test_redact_flag_masks_secret_and_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "rows.json"
            path.write_text(
                json.dumps(
                    [
                        {
                            "event.name": "tool_decision",
                            "tool_name": "AKIAIOSFODNN7EXAMPLE",
                            "decision": "accept",
                            "source": "config",
                        },
                        {
                            "harness": "codex",
                            "model": "/home/secretuser/project",
                            "tokens": 10,
                        },
                    ]
                ),
                encoding="utf-8",
            )
            os.environ["AISCAN_REDACT"] = "1"
            envelope = ti.collect(splunk_files=[path])
        blob = _dump(envelope)
        self.assertNotIn("secretuser", blob)
        self.assertNotIn("AKIAIOSFODNN7EXAMPLE", blob)
        self.assertIn("REDACTED:aws_key", blob)
        self.assertIn("<path#", blob)

    def test_without_flag_labels_stay_readable(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "rows.json"
            path.write_text(
                json.dumps(
                    {
                        "event.name": "tool_decision",
                        "tool_name": "Bash",
                        "decision": "accept",
                        "source": "user_temporary",
                    }
                ),
                encoding="utf-8",
            )
            envelope = ti.collect([path])
        tools = [row["tool"] for row in envelope["summary"]["approvals_by_tool"]]
        self.assertIn("Bash", tools)
        self.assertNotIn("REDACTED", _dump(envelope))


class TestCliAndStdlib(unittest.TestCase):
    def test_script_exits_2_without_pythonpath(self):
        script = _MOD_PATH
        with tempfile.TemporaryDirectory() as tmp:
            env = os.environ.copy()
            env.pop("PYTHONPATH", None)
            proc = subprocess.run(
                [sys.executable, str(script), "--evidence-root", tmp],
                capture_output=True,
                text=True,
                env=env,
                check=False,
            )
        self.assertEqual(proc.returncode, 2, proc.stderr)
        self.assertIn("not on disk", proc.stderr)

    def test_dry_run_writes_nothing_and_omits_prompts(self):
        with tempfile.TemporaryDirectory() as tmp:
            stdout, stderr = io.StringIO(), io.StringIO()
            with redirect_stdout(stdout), redirect_stderr(stderr):
                code = ti.run(
                    [
                        "--evidence-root",
                        tmp,
                        "--otel-file",
                        str(_SAMPLES / "otel-tool-decisions.json"),
                        "--dry-run",
                    ]
                )
            self.assertEqual(code, 0)
            self.assertFalse((Path(tmp) / "evidence" / "telemetry.json").exists())
            text = stdout.getvalue()
        self.assertIn('"collector": "telemetry"', text)
        for sentinel in SENTINELS:
            self.assertNotIn(sentinel, text)

    def test_successful_import_exits_0(self):
        with tempfile.TemporaryDirectory() as tmp:
            stdout, stderr = io.StringIO(), io.StringIO()
            with redirect_stdout(stdout), redirect_stderr(stderr):
                code = ti.run(
                    [
                        "--evidence-root",
                        tmp,
                        "--splunk-export",
                        str(_SAMPLES / "splunk-cursor-usage.csv"),
                        "--otel-file",
                        str(_SAMPLES / "otel-tool-decisions.jsonl"),
                    ]
                )
            self.assertEqual(code, 0, stderr.getvalue())
            written = json.loads((Path(tmp) / "evidence" / "telemetry.json").read_text(encoding="utf-8"))
        self.assertTrue(written["platform_detected"])
        self.assertEqual(written["summary"]["approval_events"], 2)
        self.assertEqual(written["summary"]["usage_events"], 3)
        for key, value in written["summary"].items():
            if isinstance(value, str):
                self.assertLessEqual(len(value), 64, key)

    def test_stdlib_only(self):
        tree = ast.parse(_MOD_PATH.read_text(encoding="utf-8"))
        modules: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                modules.update(alias.name.split(".")[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                modules.add(node.module.split(".")[0])
        allowed = {
            "__future__",
            "argparse",
            "csv",
            "hashlib",
            "io",
            "json",
            "re",
            "sys",
            "collections",
            "dataclasses",
            "datetime",
            "pathlib",
            "typing",
            "common",
        }
        self.assertLessEqual(modules, allowed)


class TestReportSection(unittest.TestCase):
    def test_approvals_section_uses_briefing_escaper(self):
        envelope = ti.collect([_SAMPLES / "otel-tool-decisions.json"])
        envelope["summary"]["approvals_by_tool"][0]["tool"] = "A<B>"
        rendered = section.render_approvals_section(envelope)
        self.assertEqual(getattr(section._ESC, "__module__", ""), "aiscan_build_briefing")
        self.assertEqual(section._esc('A<B>"'), html.escape('A<B>"'))
        self.assertIn('id="telemetry-approvals"', rendered)
        self.assertIn('class="section"', rendered)
        self.assertIn('class="perm-summary"', rendered)
        self.assertIn('class="table-wrap"', rendered)
        self.assertIn('class="surface-note"', rendered)
        self.assertIn("class='mode-chip'", rendered)
        self.assertIn("A&lt;B&gt;", rendered)
        self.assertNotIn("<B>", rendered)
        self.assertIn("config rule", rendered)
        self.assertIn("source=config", rendered)
        self.assertEqual(section.approvals_nav_link(envelope), '<a href="#telemetry-approvals">Approvals</a>')
        self.assertEqual(section.usage_nav_link(envelope), "")

    def test_usage_section_labels_cursor_cost(self):
        envelope = ti.collect(
            splunk_files=[
                _SAMPLES / "splunk-cursor-usage.csv",
                _SAMPLES / "generic-tokens.csv",
            ]
        )
        html = section.render_usage_section(envelope)
        self.assertIn('id="telemetry-usage"', html)
        self.assertIn("section--alt", html)
        self.assertIn("from the Cursor dashboard usage export", html)
        self.assertIn("$0.20", html)
        self.assertIn("tokens only", html)
        self.assertNotIn("9.99", html)
        self.assertIn('<a href="#telemetry-usage">Usage</a>', section.telemetry_nav_links(envelope))
        self.assertEqual(section.render_approvals_section(envelope), "")

    def test_tokens_only_section_has_no_dollar_figure(self):
        envelope = ti.collect(splunk_files=[_SAMPLES / "generic-tokens.csv"])
        html = section.render_usage_section(envelope)
        self.assertIn("Tokens only", html)
        self.assertNotIn("$", html)
        self.assertNotIn("from the Cursor dashboard usage export", html)
        self.assertIn("gpt-example", html)
        self.assertIn("codex", html)


if __name__ == "__main__":
    unittest.main()
