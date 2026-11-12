"""Default scan folder locations and dated-name allocation."""

from __future__ import annotations

import io
import os
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime
from pathlib import Path
from unittest import mock

import scan_paths


class DefaultRootTests(unittest.TestCase):
    def test_env_overrides_the_home_default(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "custom"
            with mock.patch.dict(os.environ, {"AISCAN_SCANS_ROOT": str(root)}, clear=False):
                self.assertEqual(scan_paths.default_scans_root(), root)

    def test_blank_env_falls_back_to_userprofile(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp) / "home"
            env = {"USERPROFILE": str(home), "AISCAN_SCANS_ROOT": "  "}
            with mock.patch.dict(os.environ, env, clear=False):
                os.environ["AISCAN_SCANS_ROOT"] = "  "
                self.assertEqual(
                    scan_paths.default_scans_root(),
                    home / "aiscan" / "scans",
                )

    def test_print_root_prints_only_the_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "scans"
            out = io.StringIO()
            err = io.StringIO()
            with mock.patch.dict(os.environ, {"AISCAN_SCANS_ROOT": str(root)}, clear=False):
                with redirect_stdout(out), redirect_stderr(err):
                    code = scan_paths.main(["--print-root"])
            self.assertEqual(code, 0)
            self.assertEqual(out.getvalue().strip(), str(root))
            self.assertEqual(err.getvalue(), "")



class StampTests(unittest.TestCase):
    def test_parses_minute_second_suffix_and_legacy(self):
        self.assertEqual(
            scan_paths.parse_folder_stamp("2026-11-12_1515"),
            datetime(2026, 11, 12, 15, 15),
        )
        self.assertEqual(
            scan_paths.parse_folder_stamp("2026-11-12_151530"),
            datetime(2026, 11, 12, 15, 15, 30),
        )
        self.assertEqual(
            scan_paths.parse_folder_stamp("2026-11-12_151530-2"),
            datetime(2026, 11, 12, 15, 15, 30),
        )
        self.assertEqual(
            scan_paths.parse_folder_stamp("20261112-151530"),
            datetime(2026, 11, 12, 15, 15, 30),
        )
        self.assertIsNone(scan_paths.parse_folder_stamp("manual"))
        self.assertIsNone(scan_paths.parse_folder_stamp("latest"))
        self.assertIsNone(scan_paths.parse_folder_stamp("aiscan-20261112-151530-abcd1234"))


class AllocateTests(unittest.TestCase):
    def test_first_run_uses_the_minute_and_writes_latest(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            when = datetime(2026, 11, 12, 15, 15, 7)
            path = scan_paths.allocate_scan_dir(root, when=when)
            self.assertEqual(path.name, "2026-11-12_1515")
            self.assertTrue(path.is_dir())
            self.assertEqual(
                (root / "latest.txt").read_text(encoding="utf-8"),
                "2026-11-12_1515\n",
            )
            self.assertEqual(scan_paths.read_latest(root), path)

    def test_same_minute_adds_seconds_then_a_suffix(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            when = datetime(2026, 11, 12, 15, 15, 7)
            first = scan_paths.allocate_scan_dir(root, when=when)
            second = scan_paths.allocate_scan_dir(root, when=when)
            third = scan_paths.allocate_scan_dir(root, when=when)
            self.assertEqual(first.name, "2026-11-12_1515")
            self.assertEqual(second.name, "2026-11-12_151507")
            self.assertEqual(third.name, "2026-11-12_151507-2")
            self.assertEqual(scan_paths.read_latest(root).name, "2026-11-12_151507-2")
            self.assertEqual(len({first, second, third}), 3)

    def test_alloc_cli_creates_under_the_env_root(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "scans"
            out = io.StringIO()
            err = io.StringIO()
            with mock.patch.dict(os.environ, {"AISCAN_SCANS_ROOT": str(root)}, clear=False):
                with redirect_stdout(out), redirect_stderr(err):
                    code = scan_paths.main(["--alloc"])
            self.assertEqual(code, 0)
            self.assertEqual(err.getvalue(), "")
            path = Path(out.getvalue().strip())
            self.assertTrue(path.is_dir())
            self.assertEqual(path.parent, root)
            self.assertIsNotNone(scan_paths.parse_folder_stamp(path.name))
            self.assertEqual(scan_paths.read_latest(root), path)

    def test_latest_ignores_path_separators_and_missing_folders(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "latest.txt").write_text("..\\escape\n", encoding="utf-8")
            self.assertIsNone(scan_paths.read_latest(root))
            (root / "latest.txt").write_text("no-such-folder\n", encoding="utf-8")
            self.assertIsNone(scan_paths.read_latest(root))


class LegacyRootTests(unittest.TestCase):
    def test_legacy_root_is_listed_only_when_it_holds_scans(self):
        with tempfile.TemporaryDirectory() as tmp:
            local = Path(tmp) / "local"
            results = local / "aiscan-results"
            results.mkdir(parents=True)
            with mock.patch.dict(os.environ, {"LOCALAPPDATA": str(local)}, clear=False):
                self.assertEqual(scan_paths.legacy_scan_roots(), [])
                scan = results / "20261018-090000"
                (scan / "evidence").mkdir(parents=True)
                roots = scan_paths.legacy_scan_roots()
                self.assertEqual(roots, [results])

    def test_iter_scan_children_skips_the_latest_pointer_dir(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            real = root / "2026-11-12_1515"
            (real / "evidence").mkdir(parents=True)
            pointer = root / "latest"
            (pointer / "evidence").mkdir(parents=True)
            names = [p.name for p in scan_paths.iter_scan_children(root)]
            self.assertEqual(names, ["2026-11-12_1515"])


if __name__ == "__main__":
    unittest.main()
