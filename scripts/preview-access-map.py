#!/usr/bin/env python3
"""Write a self-contained HTML page that contains only the access-map section.

Usage:
    python scripts/preview-access-map.py --evidence-root samples/synthetic-demo --out preview.html
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "report"))

from sections.access_map import render_access_map_nav, render_access_map_section  # noqa: E402


def load_envelopes(evidence_root: Path) -> dict[str, dict]:
    evidence_dir = evidence_root / "evidence"
    if not evidence_dir.is_dir():
        raise FileNotFoundError(f"Evidence directory not found: {evidence_dir}")
    envelopes: dict[str, dict] = {}
    for path in sorted(evidence_dir.glob("*.json")):
        envelopes[path.stem] = json.loads(path.read_text(encoding="utf-8"))
    if not envelopes:
        raise FileNotFoundError(f"No evidence JSON files in {evidence_dir}")
    return envelopes


def render_page(envelopes: dict[str, dict]) -> str:
    css_path = ROOT / "report" / "templates" / "briefing.css"
    css = css_path.read_text(encoding="utf-8")
    nav = render_access_map_nav(envelopes)
    section = render_access_map_section(envelopes)
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover" />
  <title>Access map preview</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=IBM+Plex+Mono:wght@400;500&display=swap" rel="stylesheet">
  <style>
{css}
  </style>
</head>
<body>
<nav class="nav">
  <div class="nav-inner">
    <a href="#access-map" class="brand">
      <span class="brand-mark"></span>
      <span>aiscan</span>
    </a>
    <div class="nav-links">
      {nav}
    </div>
    <span class="nav-cta"><span class="dot"></span><span>access map preview</span></span>
  </div>
</nav>
{section}
</body>
</html>
"""


def main() -> None:
    parser = argparse.ArgumentParser(description="Preview the access-map section as a standalone HTML page.")
    parser.add_argument("--evidence-root", required=True, help="Directory that contains evidence/*.json")
    parser.add_argument("--out", required=True, help="HTML file to write")
    args = parser.parse_args()
    evidence_root = Path(args.evidence_root)
    envelopes = load_envelopes(evidence_root)
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(render_page(envelopes), encoding="utf-8")
    print(f"Wrote {out}")


if __name__ == "__main__":
    main()
