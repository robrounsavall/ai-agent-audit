"""aiscan.ps1 preflight, closing note, and UTF-8 evidence reads.

The version probe and the closing note are exercised by running the real
script under pwsh with a stand-in for python. PowerShell 7 already reads
UTF-8 by default, so the evidence test also locks the -Encoding UTF8 flag
that Windows PowerShell 5.1 needs.
"""

from __future__ import annotations

import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
AISCAN = REPO / "aiscan.ps1"
PWSH = shutil.which("pwsh")

OLD_WARNING = (
    "(unredacted by default: real secrets / paths / transcript metadata - delete when done)"
)
REDACT_NOTE = (
    "Redaction was on for this run: evidence and the briefing written now are redacted. "
    "raw\\ is NOT redacted, keep it local. "
    "Files left from earlier runs in this folder are not re-redacted."
)


def _run(driver: str) -> tuple[int, str]:
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "driver.ps1"
        # BOM so Windows PowerShell 5.1 would not misread the driver as ANSI.
        path.write_bytes(b"\xef\xbb\xbf" + driver.encode("utf-8"))
        proc = subprocess.run(
            ["pwsh", "-NoProfile", "-File", str(path)],
            capture_output=True,
            check=False,
        )
    text = proc.stdout.decode("utf-8", "replace") + proc.stderr.decode("utf-8", "replace")
    return proc.returncode, text


def _call(prelude: str, aiscan_args: str) -> str:
    # Single-quoted path. The repo path has no single quotes.
    # pwsh 7 returns from a nested script's exit and stores the code in
    # $LASTEXITCODE. Windows PowerShell 5.1 exits the process instead, so
    # this line never runs there. Either way the process code matches.
    return f"""
$ErrorActionPreference = 'Continue'
$OutputEncoding = New-Object System.Text.UTF8Encoding $false
[Console]::OutputEncoding = $OutputEncoding
{prelude}
& '{AISCAN}' {aiscan_args}
exit $LASTEXITCODE
"""


@unittest.skipUnless(PWSH, "pwsh is required to run aiscan.ps1")
class TestAiscanPreflight(unittest.TestCase):
    def test_python_310_is_too_old(self):
        code, out = _run(_call("function python { '3.10.11' }", "discover"))
        self.assertEqual(code, 1, out)
        self.assertIn("Python 3.10.11 is too old", out)
        self.assertNotIn("cannot be retrieved", out)

    def test_garbage_version_is_rejected(self):
        code, out = _run(_call("function python { 'Python 3.12.3' }", "discover"))
        self.assertEqual(code, 1, out)
        self.assertIn("did not report a usable version", out)

    def test_nonzero_exit_is_rejected(self):
        prelude = """
function python {
    $global:LASTEXITCODE = 1
    '3.12.3'
}
"""
        code, out = _run(_call(prelude, "discover"))
        self.assertEqual(code, 1, out)
        self.assertIn("did not report a usable version", out)
        self.assertNotIn("cannot be retrieved", out)

    def test_missing_python_is_rejected(self):
        with tempfile.TemporaryDirectory() as empty:
            prelude = f"$env:PATH = '{empty}'"
            code, out = _run(_call(prelude, "discover"))
        self.assertEqual(code, 1, out)
        self.assertIn("was not found on PATH", out)

    def test_stale_lastexitcode_is_not_blamed_on_a_good_version(self):
        # A function named python leaves LASTEXITCODE alone. A stale 5 must
        # not fail a probe that printed 3.12.3, and reading it must not throw.
        prelude = """
$global:LASTEXITCODE = 5
function python { '3.12.3' }
"""
        code, out = _run(_call(prelude, "discover"))
        self.assertEqual(code, 0, out)
        self.assertNotIn("did not report a usable version", out)
        self.assertNotIn("cannot be retrieved", out)
        self.assertNotIn("too old", out)


@unittest.skipUnless(PWSH, "pwsh is required to run aiscan.ps1")
class TestAiscanClosingNote(unittest.TestCase):
    def _failing_collector(self, out_dir: Path, redact: bool) -> tuple[int, str]:
        prelude = """
function python {
    if ($args -contains '-c') { '3.12.3'; return }
    $global:LASTEXITCODE = 1
}
"""
        flag = "-Redact" if redact else ""
        return _run(_call(prelude, f"claude -OutDir '{out_dir}' {flag}"))

    def test_without_redact_keeps_the_old_warning(self):
        with tempfile.TemporaryDirectory() as tmp:
            code, out = self._failing_collector(Path(tmp), redact=False)
        self.assertNotEqual(code, 0)
        self.assertIn(OLD_WARNING, out)
        self.assertNotIn("Redaction was on for this run", out)

    def test_with_redact_does_not_claim_older_files_were_redacted(self):
        with tempfile.TemporaryDirectory() as tmp:
            code, out = self._failing_collector(Path(tmp), redact=True)
        self.assertNotEqual(code, 0)
        self.assertIn(REDACT_NOTE, out)
        self.assertNotIn(OLD_WARNING, out)


@unittest.skipUnless(PWSH, "pwsh is required to run aiscan.ps1")
class TestEvidenceUtf8(unittest.TestCase):
    def test_script_reads_evidence_as_utf8(self):
        text = AISCAN.read_text(encoding="utf-8")
        # The table and 'all' read through Read-EvidenceEnvelope, which calls
        # Read-EvidenceText. -Json is the other call site.
        self.assertEqual(text.count("Read-EvidenceText -Path"), 2)
        self.assertIn("Get-Content -LiteralPath $Path -Encoding UTF8 -Raw", text)

    def _writer(self) -> str:
        # Writes a BOM-less UTF-8 envelope whose title contains U+00E9.
        return r"""
function python {
    if ($args -contains '-c') { '3.12.3'; return }
    $joined = $args -join ' '
    if ($joined -like '*discover.py*') {
        '{"cli_args":[],"native_dirs":{}}'
        return
    }
    if ($joined -like '*tool_version.py*') { 'dev'; $global:LASTEXITCODE = 0; return }
    if ($joined -like '*run_status.py*') { '0'; $global:LASTEXITCODE = 0; return }
    $root = $null
    for ($i = 0; $i -lt $args.Count; $i++) {
        if ($args[$i] -eq '--evidence-root') { $root = $args[$i + 1] }
    }
    if (-not $root) { $global:LASTEXITCODE = 1; return }
    $name = [System.IO.Path]::GetFileNameWithoutExtension([string]$args[0])
    $ev = Join-Path $root 'evidence'
    New-Item -ItemType Directory -Force -Path $ev | Out-Null
    $e = [char]0x00E9
    $json = '{"collector":"' + $name + '","version":"0","platform_detected":true,"ran_at":"t","host":"h","scope_hash":"abcdef123456","summary":{},"findings":[{"severity":"low","title":"caf' + $e + '","category":"test","id":"t.1","evidence_count":1}],"rules":[],"raw_pointers":[]}'
    $utf8 = New-Object System.Text.UTF8Encoding $false
    [System.IO.File]::WriteAllText((Join-Path $ev ($name + '.json')), $json, $utf8)
    $global:LASTEXITCODE = 0
}
"""

    def test_non_ascii_title_survives_the_table_and_json_dump(self):
        writer = self._writer()
        with tempfile.TemporaryDirectory() as tmp:
            code, out = _run(_call(writer, f"claude -OutDir '{tmp}'"))
        self.assertEqual(code, 0, out)
        self.assertIn("caf\u00e9", out)
        self.assertNotIn("parse error", out)

        with tempfile.TemporaryDirectory() as tmp:
            code, out = _run(_call(writer, f"claude -Json -OutDir '{tmp}'"))
        self.assertEqual(code, 0, out)
        self.assertIn("caf\u00e9", out)

    def test_all_mode_does_not_mark_utf8_evidence_as_a_parse_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            code, out = _run(_call(self._writer(), f"all -OutDir '{tmp}'"))
        self.assertEqual(code, 0, out)
        self.assertNotIn("parse error", out)


if __name__ == "__main__":
    unittest.main()
