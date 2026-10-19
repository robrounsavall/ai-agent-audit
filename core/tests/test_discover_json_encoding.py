"""discover --json must stay ASCII so Windows PowerShell 5.1 can read it.

5.1 decodes a native process's stdout with the OEM code page. A raw
non-ASCII path would be corrupted before ConvertFrom-Json. \\u escapes
survive that and decode back to the original path.
"""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

DISCOVER = Path(__file__).resolve().parents[1] / "discover.py"


class TestDiscoverJsonEncoding(unittest.TestCase):
    def test_non_ascii_path_is_escaped_and_roundtrips(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cafe = root / "caf\u00e9"
            cafe.mkdir()
            proc = subprocess.run(
                [
                    sys.executable,
                    str(DISCOVER),
                    "--json",
                    "--claude-home",
                    str(cafe),
                    "--codex-home",
                    str(root / "codex"),
                    "--cursor-projects",
                    str(root / "cursor-projects"),
                    "--cursor-db",
                    str(root / "state.vscdb"),
                    "--grok-home",
                    str(root / "grok"),
                ],
                capture_output=True,
                check=False,
            )
        self.assertEqual(proc.returncode, 0, proc.stderr.decode("utf-8", "replace"))
        # The bytes on the pipe are ASCII, whatever the console code page is.
        text = proc.stdout.decode("ascii")
        self.assertIn("\\u00e9", text)
        data = json.loads(text)
        joined = " ".join(data["cli_args"])
        self.assertIn("caf\u00e9", joined)
        self.assertIn("caf\u00e9", data["native_dirs"]["claude_projects"])


if __name__ == "__main__":
    unittest.main()
