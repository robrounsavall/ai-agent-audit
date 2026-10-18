"""Exit code for one aiscan.ps1 run.

``aiscan.ps1`` records one row per collector as ``exit,has,parsed`` (1 or 0)
and calls this file:

    python core/run_status.py 0,1,1 2,1,1 --briefing 0

Exit 2 with a readable evidence file is "platform not detected", which is a
normal result. Any other non-zero collector exit, or an evidence file that
does not parse, is a collector failure. The process then exits:

- 2 when any collector failed
- 3 when collectors were fine and only the briefing failed
- 0 otherwise
"""

from __future__ import annotations

import sys


def collector_failed(exit_code: int, has_evidence: bool, parsed: bool) -> bool:
    """True when this collector should fail the scan.

    A parse failure counts even if the process exit was 0. Exit 2 plus a
    parsed envelope does not: collectors use that for "not detected".
    """
    if has_evidence and not parsed:
        return True
    if exit_code == 2 and has_evidence and parsed:
        return False
    return exit_code != 0


def scan_exit_code(*, collector_failed: bool, briefing_failed: bool) -> int:
    if collector_failed:
        return 2
    if briefing_failed:
        return 3
    return 0


def _parse_row(text: str) -> tuple[int, bool, bool]:
    parts = text.split(",")
    if len(parts) != 3 or parts[1] not in ("0", "1") or parts[2] not in ("0", "1"):
        raise ValueError(text)
    return int(parts[0]), parts[1] == "1", parts[2] == "1"


def rows_failed(rows: list[tuple[int, bool, bool]]) -> bool:
    return any(collector_failed(code, has, parsed) for code, has, parsed in rows)


def main(argv: list[str] | None = None) -> int:
    if argv is None:
        argv = sys.argv[1:]
    briefing_failed = False
    rows: list[tuple[int, bool, bool]] = []
    index = 0
    while index < len(argv):
        arg = argv[index]
        if arg == "--briefing":
            if index + 1 >= len(argv) or argv[index + 1] not in ("0", "1"):
                print("usage: run_status.py [exit,has,parsed ...] --briefing 0|1", file=sys.stderr)
                return 2
            briefing_failed = argv[index + 1] == "1"
            index += 2
            continue
        try:
            rows.append(_parse_row(arg))
        except ValueError:
            print(f"bad collector row: {arg}", file=sys.stderr)
            return 2
        index += 1
    code = scan_exit_code(
        collector_failed=rows_failed(rows),
        briefing_failed=briefing_failed,
    )
    print(code)
    return 0


if __name__ == "__main__":
    sys.exit(main())
