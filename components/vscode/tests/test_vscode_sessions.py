"""
Tests for vscode.py chat-session metadata parsing and the chat-history
Copilot request parser. Asserts no prompt text or identity leaks into
session metadata.

Run:
    python -m unittest discover -s phase1-audit/tests -v
"""

from __future__ import annotations

import importlib.util
import json
import os
import sys
import unittest
from pathlib import Path

os.environ["USERPROFILE"] = "C:\\Users\\Test User"
import bootstrap  # noqa: E402,F401

import vscode  # noqa: E402

_spec = importlib.util.spec_from_file_location(
    "chat_history", Path(__file__).resolve().parents[2] / "chat-history" / "chat-history.py"
)
chat_history = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_spec and chat_history)

SECRET_PROMPT = "please rotate AKIA" + "C" * 16
ACCOUNT = "testuser-gh"

KIND0 = json.dumps({
    "kind": 0,
    "v": {
        "version": 3,
        "sessionId": "s-1",
        "requests": [],
        "inputState": {
            "mode": {"id": "agent", "kind": "agent"},
            "selectedModel": {
                "identifier": "copilot/auto",
                "metadata": {
                    "family": "gpt-5-mini",
                    "auth": {"accountLabel": ACCOUNT},
                },
            },
            "permissionLevel": "all",
        },
    },
})

KIND2 = json.dumps({
    "kind": 2,
    "k": ["requests"],
    "v": [
        {
            "requestId": "r-1",
            "timestamp": 1784471177514,
            "modelId": "copilot/auto",
            "message": {"text": SECRET_PROMPT, "parts": []},
            "response": [{"kind": "markdownContent", "value": "use a vault instead"}],
            "agent": {"modes": ["agent"]},
            "promptTokens": 120,
            "completionTokens": 30,
            "result": {"metadata": {"resolvedModel": "mai-code-1-flash"}},
        }
    ],
})


class TestParseSessionLines(unittest.TestCase):
    def test_counts_modes_models_levels(self):
        meta = vscode.parse_session_lines([KIND0, KIND2])
        self.assertEqual(meta["requests"], 1)
        self.assertIn("agent", meta["modes"])
        self.assertIn("gpt-5-mini", meta["models"])
        self.assertIn("mai-code-1-flash", meta["models"])
        self.assertIn("all", meta["permission_levels"])

    def test_no_prompt_text_or_identity_in_metadata(self):
        meta = vscode.parse_session_lines([KIND0, KIND2])
        blob = json.dumps({k: sorted(v) if isinstance(v, set) else v for k, v in meta.items()})
        self.assertNotIn("AKIA", blob)
        self.assertNotIn(ACCOUNT, blob)
        self.assertNotIn("rotate", blob)

    def test_malformed_lines_skipped(self):
        meta = vscode.parse_session_lines(["not json", "", "{}", KIND2])
        self.assertEqual(meta["requests"], 1)


class TestParseCopilotRequests(unittest.TestCase):
    def test_user_and_assistant_entries(self):
        reqs = json.loads(KIND2)["v"]
        entries = chat_history.parse_copilot_requests(reqs)
        roles = [(role, text) for _ts, role, text in entries]
        self.assertEqual(roles[0][0], "user")
        self.assertIn("AKIA", roles[0][1])  # raw export keeps text; secrets-scan runs downstream
        self.assertEqual(roles[1][0], "assistant")
        self.assertIn("vault", roles[1][1])

    def test_missing_timestamp_skipped(self):
        entries = chat_history.parse_copilot_requests([{"message": {"text": "hi"}}])
        self.assertEqual(entries, [])

    def test_unknown_response_parts_placeholder_only_with_details(self):
        req = {
            "timestamp": 1784471177514,
            "response": [{"kind": "toolInvocation", "payload": {"x": 1}}],
        }
        self.assertEqual(chat_history.parse_copilot_requests([req]), [])
        entries = chat_history.parse_copilot_requests([req], include_tool_details=True)
        self.assertEqual(entries[0][2], "[toolInvocation omitted]")


if __name__ == "__main__":
    unittest.main()
