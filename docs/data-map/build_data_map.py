#!/usr/bin/env python3
"""Build docs/aiscan-data-map.html from docs/data-map/data_map_content.py.

Usage:
    python docs/data-map/build_data_map.py            # write the HTML
    python docs/data-map/build_data_map.py --verify   # also check every citation anchor
    python docs/data-map/build_data_map.py --check    # fail if the committed HTML is stale

The output is one offline file: inline CSS, inline SVG, inline JS, no fonts,
images or requests. Citation links point at an immutable commit and only open
when clicked.
"""

from __future__ import annotations

import argparse
import html
import re
import subprocess
import sys
from collections import defaultdict
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
OUT = ROOT / "docs" / "aiscan-data-map.html"

sys.path.insert(0, str(HERE))
import data_map_content as A  # noqa: E402


# --------------------------------------------------------------------------- #
# Citations
# --------------------------------------------------------------------------- #
def iter_cites(obj):
    if isinstance(obj, tuple) and obj and obj[0] in ("src", "doc"):
        yield obj
        return
    if isinstance(obj, dict):
        for value in obj.values():
            yield from iter_cites(value)
    elif isinstance(obj, (list, tuple)):
        for value in obj:
            yield from iter_cites(value)


RENDERED: list[tuple] = []


def all_content():
    return [A.HARNESSES, A.CROSS_CUTTING, A.INVENTORY, A.PIPELINE, A.OUTPUT_TREE,
            A.ENVELOPE_CITES, A.REDACTION, A.GUARANTEES, A.PLATFORM_NOTES, RENDERED]


def _pinned_lines(path: str) -> list[str] | None:
    """Lines of path at BASE_SHA. Links cite that commit, so later edits must not move the check."""
    shown = subprocess.run(
        ["git", "show", f"{A.BASE_SHA}:{path}"],
        cwd=ROOT,
        check=False,
        capture_output=True,
    )
    if shown.returncode != 0:
        return None
    return shown.stdout.decode("utf-8").splitlines()


def verify() -> list[str]:
    problems = []
    seen = set()
    blobs: dict[str, list[str] | None] = {}
    for cite in iter_cites(all_content()):
        if cite in seen:
            continue
        seen.add(cite)
        if cite[0] == "doc":
            if cite[1] not in A.DOCS:
                problems.append(f"unknown doc key {cite[1]}")
            continue
        _, path, start, end, anchor = cite
        if path not in blobs:
            blobs[path] = _pinned_lines(path)
        lines = blobs[path]
        if lines is None:
            problems.append(f"{path}: missing at {A.BASE_SHA}")
            continue
        if not (1 <= start <= end <= len(lines)):
            problems.append(f"{path}:{start}-{end}: out of range (file has {len(lines)} lines at {A.BASE_SHA[:12]})")
            continue
        if not anchor:
            problems.append(f"{path}:{start}-{end}: empty anchor")
            continue
        window = "\n".join(lines[start - 1:end])
        if anchor not in window:
            problems.append(f"{path}:{start}-{end}: anchor {anchor!r} not found at {A.BASE_SHA[:12]}")
    return problems


def src_url(path: str, start: int | None = None, end: int | None = None) -> str:
    url = f"{A.REPO_URL}/blob/{A.BASE_SHA}/{path}"
    if start:
        url += f"#L{start}" + (f"-L{end}" if end and end != start else "")
    return url


def esc(text) -> str:
    return html.escape(str(text), quote=True)


_CODE_RE = re.compile(r"`([^`]+)`")


def md(text: str) -> str:
    """Escape, then render `code` spans. Nothing else is interpreted."""
    return _CODE_RE.sub(lambda m: f"<code>{m.group(1)}</code>", esc(text))


def cite_html(cite) -> str:
    RENDERED.append(cite)
    if cite[0] == "doc":
        doc = A.DOCS[cite[1]]
        return (f'<a class="cite cite-doc" href="{esc(doc["url"])}" target="_blank" rel="noopener noreferrer" '
                f'title="Public documentation, read {esc(doc["accessed"])}. Opens in a new tab.">'
                f'<span class="cite-kind">docs</span>{esc(doc["short"])}</a>')
    _, path, start, end, _anchor = cite
    name = path.rsplit("/", 1)[-1]
    lines = f"{start}" if start == end else f"{start}–{end}"
    return (f'<a class="cite" href="{esc(src_url(path, start, end))}" target="_blank" rel="noopener noreferrer" '
            f'title="{esc(path)} lines {lines} at {A.BASE_SHA[:12]}. Opens GitHub in a new tab.">'
            f'{esc(name)}<span class="cite-lines">:{lines}</span></a>')


def cites_html(cites) -> str:
    if not cites:
        return ""
    return '<span class="cites">' + "".join(cite_html(c) for c in cites) + "</span>"


def mode_badge(mode: str) -> str:
    label, desc = A.MODES[mode]
    return f'<span class="mode mode-{mode}" title="{esc(desc)}">{esc(label)}</span>'


# --------------------------------------------------------------------------- #
# SVG: local / remote boundary
# --------------------------------------------------------------------------- #
CLOUDS = [
    ("Anthropic", "Claude Code / Cowork"),
    ("OpenAI", "Codex, Codex Cloud"),
    ("Cursor backend", "IDE, Cloud Agents, Grok Bot"),
    ("GitHub", "Copilot, session sync, repos"),
    ("xAI", "Grok Build · not verified"),
]
STORES = [
    ("claude-code", "Claude Code", r"%USERPROFILE%\.claude"),
    ("claude-desktop", "Claude desktop", r"%APPDATA%\Claude"),
    ("cursor", "Cursor", r"%APPDATA%\Cursor, .cursor"),
    ("codex", "Codex", r"%USERPROFILE%\.codex"),
    ("vscode", "VS Code + Copilot", r"%APPDATA%\Code"),
    ("grok-build", "Grok Build", r"%USERPROFILE%\.grok"),
    ("grok-bot", "Grok Bot", r"%APPDATA%\Grok Bot"),
    (None, "Repositories", r"<repo> under the profile"),
]


def _text(x, y, s, cls="", anchor="start", extra=""):
    return f'<text x="{x}" y="{y}" class="{cls}" text-anchor="{anchor}"{extra}>{esc(s)}</text>'


def boundary_svg(narrow: bool) -> str:
    if narrow:
        W, cloud_cols, ch, store_cols, sh, gap, oh = 360, 1, 54, 1, 56, 8, 60
    else:
        W, cloud_cols, ch, store_cols, sh, gap, oh = 1040, 5, 62, 4, 64, 10, 66
    pad = 14
    inner = W - 2 * pad
    out = []
    y = pad

    # Remote band
    cloud_rows = -(-len(CLOUDS) // cloud_cols)
    band_h = 40 + cloud_rows * (ch + gap)
    out.append(f'<rect x="{pad}" y="{y}" width="{inner}" height="{band_h}" rx="14" class="zone-remote"/>')
    out.append(_text(pad + 14, y + 26, "REMOTE  ·  vendor clouds", "zone-label zone-label-remote"))
    cw = (inner - 28 - gap * (cloud_cols - 1)) / cloud_cols
    stubs = []
    for i, (name, sub) in enumerate(CLOUDS):
        r, c = divmod(i, cloud_cols)
        x = pad + 14 + c * (cw + gap)
        yy = y + 40 + r * (ch + gap)
        out.append(f'<rect x="{x:.1f}" y="{yy}" width="{cw:.1f}" height="{ch}" rx="10" class="node-remote"/>')
        if narrow:
            out.append(_text(x + 12, yy + 23, name, "node-title"))
            out.append(_text(x + 12, yy + 43, sub, "node-sub"))
        else:
            out.append(_text(x + cw / 2, yy + 26, name, "node-title", "middle"))
            out.append(_text(x + cw / 2, yy + 47, sub, "node-sub", "middle"))
        if r == cloud_rows - 1:
            stubs.append((x + (cw / 2 if not narrow else 28), yy + ch))
    y += band_h

    # Boundary, with dotted stubs where harness traffic to each vendor crosses it
    y += 22
    for sx, sy in stubs:
        out.append(f'<line x1="{sx:.1f}" y1="{sy + 2}" x2="{sx:.1f}" y2="{y + 30}" class="flow-vendor"/>')
    out.append(f'<line x1="{pad}" y1="{y}" x2="{W - pad}" y2="{y}" class="boundary"/>')
    lbl = "machine boundary — the offline scan stops here" if not narrow else "machine boundary"
    pw = 380 if not narrow else 160
    out.append(f'<rect x="{W / 2 - pw / 2}" y="{y - 13}" width="{pw}" height="26" rx="13" class="boundary-pill"/>')
    out.append(_text(W / 2, y + 5, lbl, "boundary-text", "middle"))
    y += 24

    # Local zone
    store_rows = -(-len(STORES) // store_cols)
    local_top = y
    stores_h = 40 + store_rows * (sh + gap)
    aiscan_h = 92
    n_out = 3
    out_rows = 3 if narrow else 1
    out_h = 40 + out_rows * (oh + gap)
    local_h = stores_h + 34 + aiscan_h + 34 + out_h + 8
    out.append(f'<rect x="{pad}" y="{local_top}" width="{inner}" height="{local_h}" rx="14" class="zone-local"/>')
    out.append(_text(pad + 14, local_top + 26, "LOCAL  ·  this Windows machine", "zone-label zone-label-local"))
    sw = (inner - 28 - gap * (store_cols - 1)) / store_cols
    for i, (hid, name, path) in enumerate(STORES):
        r, c = divmod(i, store_cols)
        x = pad + 14 + c * (sw + gap)
        yy = local_top + 40 + r * (sh + gap)
        body = (f'<rect x="{x:.1f}" y="{yy}" width="{sw:.1f}" height="{sh}" rx="10" class="node-store"/>'
                + _text(x + 12, yy + (24 if narrow else 26), name, "node-title")
                + _text(x + 12, yy + (44 if narrow else 48), path, "node-path"))
        if hid:
            out.append(f'<a href="#harness={hid}" class="svg-link" aria-label="{esc(name)}: show in the Harnesses section">{body}</a>')
        else:
            out.append(body)
    y = local_top + stores_h

    # aiscan bar
    y += 28
    ax = pad + 14
    aw = inner - 28
    n = int(narrow)
    out.append(f'<line x1="{W / 2}" y1="{y - 30}" x2="{W / 2}" y2="{y - 2}" class="flow-read" marker-end="url(#arrow-read-{n})"/>')
    out.append(f'<rect x="{ax}" y="{y}" width="{aw}" height="{aiscan_h}" rx="12" class="node-aiscan"/>')
    if narrow:
        lines = [("aiscan all", "node-title node-title-lg"), ("12 read-only collectors · offline", "node-sub"),
                 ("never vendor histories", "node-sub node-sub-strong")]
    else:
        lines = [("aiscan all  ·  12 read-only collectors", "node-title node-title-lg"),
                 ("no network calls · SQLite opened read-only · secret validation off", "node-sub"),
                 ("reads local files only — never vendor histories", "node-sub node-sub-strong")]
    for j, (t, cls) in enumerate(lines):
        out.append(_text(ax + aw / 2, y + 32 + j * 23, t, cls, "middle"))
    aiscan_y = y
    y += aiscan_h

    # Output folder
    y += 34
    out.append(f'<line x1="{W / 2}" y1="{y - 34}" x2="{W / 2}" y2="{y + 34}" class="flow-write" marker-end="url(#arrow-write-{n})"/>')
    if narrow:
        outputs = [("evidence\\", "envelopes · review before sharing", "node-evidence"),
                   ("raw\\", "transcripts, CSVs · LOCAL ONLY", "node-raw"),
                   ("briefing\\briefing.html", "with -Briefing · one file", "node-evidence")]
    else:
        outputs = [("evidence\\", "structured envelopes · review before sharing", "node-evidence"),
                   ("raw\\", "transcripts & scanner CSVs · LOCAL ONLY", "node-raw"),
                   ("briefing\\briefing.html", "with -Briefing · self-contained", "node-evidence")]
    ocols = 1 if narrow else n_out
    ow = (inner - 28 - gap * (ocols - 1)) / ocols
    out.append(_text(pad + 14, y + 26, "<scan-root>\\", "zone-label zone-label-out"))
    for i, (name, sub, cls) in enumerate(outputs):
        r, c = divmod(i, ocols)
        x = pad + 14 + c * (ow + gap)
        yy = y + 40 + r * (oh + gap)
        out.append(f'<rect x="{x:.1f}" y="{yy}" width="{ow:.1f}" height="{oh}" rx="10" class="{cls}"/>')
        out.append(_text(x + 12, yy + (25 if narrow else 28), name, "node-title node-mono"))
        out.append(_text(x + 12, yy + (46 if narrow else 50), sub, "node-sub"))
    y = local_top + local_h

    # Opt-in network path along the right edge
    ox = W - pad - 5
    top_target = pad + band_h - 2
    out.append(f'<path d="M {ax + aw} {aiscan_y + 46} H {ox} V {top_target}" class="flow-optin" marker-end="url(#arrow-optin-{n})"/>')
    if narrow:
        out.append(_text(ox - 8, aiscan_y - 10, "opt-in: GET api.cursor.com", "optin-text", "end"))
    else:
        out.append(_text(ox - 10, local_top + stores_h + 20, "opt-in only: cloud-agents → GET api.cursor.com", "optin-text", "end"))

    # Legend
    y += 24
    legend = [("flow-read", "reads (read-only)"), ("flow-write", "writes scan output"),
              ("flow-optin", "opt-in network"), ("flow-vendor", "vendor traffic, not observed")]
    per_row = 1 if narrow else 4
    for i, (cls, text) in enumerate(legend):
        r, c = divmod(i, per_row)
        x = pad + c * (inner / per_row)
        yy = y + r * 24
        out.append(f'<line x1="{x + 4}" y1="{yy}" x2="{x + 34}" y2="{yy}" class="{cls}"/>')
        out.append(_text(x + 42, yy + 5, text, "legend-text"))
    y += 24 * (-(-len(legend) // per_row)) - 6

    defs = (
        "<defs>"
        f'<marker id="arrow-read-{n}" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" class="mk-read"/></marker>'
        f'<marker id="arrow-write-{n}" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" class="mk-write"/></marker>'
        f'<marker id="arrow-optin-{n}" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" class="mk-optin"/></marker>'
        "</defs>"
    )
    title = "Local and remote boundary"
    desc = ("Vendor clouds sit above the machine boundary. Harness data stores on this machine are read by aiscan's "
            "twelve offline collectors, which write evidence, raw and briefing folders locally. The only network path "
            "is the opt-in cloud-agents command, which sends GET requests to api.cursor.com.")
    variant = "narrow" if narrow else "wide"
    return (f'<svg class="diagram diagram-{variant}" viewBox="0 0 {W} {y:.0f}" role="img" '
            f'aria-labelledby="bd-t-{variant} bd-d-{variant}" xmlns="http://www.w3.org/2000/svg">'
            f'<title id="bd-t-{variant}">{title}</title><desc id="bd-d-{variant}">{esc(desc)}</desc>'
            + defs + "".join(out) + "</svg>")


# --------------------------------------------------------------------------- #
# SVG: pipeline
# --------------------------------------------------------------------------- #
SVG_SHORT = {
    "launch": "aiscan.ps1",
    "resolve": "core/paths.py",
    "collect": "components/*",
    "normalize": "core/common.py",
    "store": "evidence/ · raw/",
    "derive": "derived views",
    "brief": "build-briefing.py",
}

SHORTHAND = [
    ("setup", ("launch", "resolve")),
    ("collectors", ("collect",)),
    ("normalized evidence", ("normalize", "store")),
    ("analysis", ("derive",)),
    ("briefing", ("brief",)),
]


def pipeline_svg(narrow: bool) -> str:
    steps = A.PIPELINE
    out = []
    if not narrow:
        W, sw, gap, top = 1040, 138, 9, 16
        total = len(steps) * sw + (len(steps) - 1) * gap
        x0 = (W - total) / 2
        pos = {}
        for i, s in enumerate(steps):
            x = x0 + i * (sw + gap)
            pos[s["id"]] = (x, x + sw)
            out.append(
                f'<a href="#step-{s["id"]}" class="svg-link step-link" data-step="{s["id"]}" aria-label="Step {i + 1}: {esc(s["label"])}">'
                f'<rect x="{x:.1f}" y="{top}" width="{sw}" height="86" rx="12" class="step-node"/>'
                + _text(x + 14, top + 26, f"{i + 1:02d}", "step-num")
                + _text(x + 14, top + 52, s["label"], "node-title")
                + _text(x + 14, top + 72, SVG_SHORT[s["id"]], "node-sub node-mono")
                + "</a>")
            if i:
                out.append(f'<line x1="{x - gap + 2:.1f}" y1="{top + 43}" x2="{x - 2:.1f}" y2="{top + 43}" class="flow-read"/>')
        by = top + 112
        out.append(_text(x0, by - 4, "The usual summary, mapped to these stages:", "legend-text"))
        for label, ids in SHORTHAND:
            a = pos[ids[0]][0]
            b = pos[ids[-1]][1]
            muted = " band-muted" if label == "setup" else ""
            out.append(f'<rect x="{a:.1f}" y="{by + 6}" width="{b - a:.1f}" height="34" rx="17" class="band{muted}"/>')
            out.append(_text((a + b) / 2, by + 28, label, "band-text" + (" band-text-muted" if muted else ""), "middle"))
        H = by + 52
    else:
        W, sh, gap, top = 360, 56, 8, 12
        bandw = 104
        x = 16 + bandw + 10
        w = W - x - 16
        pos = {}
        for i, s in enumerate(steps):
            y = top + i * (sh + gap)
            pos[s["id"]] = (y, y + sh)
            out.append(
                f'<a href="#step-{s["id"]}" class="svg-link step-link" data-step="{s["id"]}" aria-label="Step {i + 1}: {esc(s["label"])}">'
                f'<rect x="{x}" y="{y}" width="{w}" height="{sh}" rx="10" class="step-node"/>'
                + _text(x + 12, y + 25, f"{i + 1:02d}  {s['label']}", "node-title")
                + _text(x + 12, y + 45, SVG_SHORT[s["id"]], "node-sub node-mono")
                + "</a>")
        for label, ids in SHORTHAND:
            a = pos[ids[0]][0]
            b = pos[ids[-1]][1]
            muted = label == "setup"
            out.append(f'<rect x="16" y="{a}" width="{bandw}" height="{b - a}" rx="12" class="band{" band-muted" if muted else ""}"/>')
            words = label.split(" ")
            for j, wd in enumerate(words):
                out.append(_text(16 + bandw / 2, (a + b) / 2 + 5 + (j - (len(words) - 1) / 2) * 18, wd,
                                 "band-text" + (" band-text-muted" if muted else ""), "middle"))
        H = top + len(steps) * (sh + gap)
    variant = "narrow" if narrow else "wide"
    desc = ("Seven stages: launch, resolve paths, collect, normalize, store, derive, brief. The shorthand collectors, "
            "normalized evidence, analysis and briefing maps onto collect; normalize and store; derive; and brief.")
    return (f'<svg class="diagram diagram-{variant}" viewBox="0 0 {W} {H:.0f}" role="img" '
            f'aria-labelledby="pl-t-{variant} pl-d-{variant}" xmlns="http://www.w3.org/2000/svg">'
            f'<title id="pl-t-{variant}">aiscan pipeline</title><desc id="pl-d-{variant}">{esc(desc)}</desc>'
            + "".join(out) + "</svg>")


# --------------------------------------------------------------------------- #
# Sections
# --------------------------------------------------------------------------- #
CAT_LABEL = dict(A.CATEGORIES)


def harness_panel(h: dict) -> str:
    optin = h.get("optin")
    badges = "".join(f'<span class="chip chip-collector">{esc(c)}</span>' for c in h["collectors"])
    status = ('<span class="status status-optin">Opt-in · network</span>' if optin
              else '<span class="status status-all">Covered by aiscan all</span>')
    rows = []
    for r in h["rows"]:
        reads = []
        for collector, mode, text, cites in r["reads"]:
            who = "" if collector == "none" else f'<span class="who">{esc(collector)}</span>'
            reads.append(f'<li>{mode_badge(mode)}{who}<span class="read-text">{md(text)}</span>{cites_html(cites)}</li>')
        modes = " ".join(sorted({m for _, m, _, _ in r["reads"]}))
        rows.append(
            f'<tr class="store-row" data-cat="{r["cat"]}" data-modes="{modes}">'
            f'<td data-label="Category"><span class="cat cat-{r["cat"]}">{esc(CAT_LABEL[r["cat"]])}</span></td>'
            f'<td data-label="Location"><code class="path">{esc(r["loc"])}</code></td>'
            f'<td data-label="What the harness keeps">{md(r["keeps"])}{cites_html(r.get("keeps_cites", []))}</td>'
            f'<td data-label="What aiscan does"><ul class="reads">{"".join(reads)}</ul></td>'
            "</tr>")
    cannot = "".join(f"<li>{md(t)}{cites_html(c)}</li>" for t, c in h["cannot"])
    return f"""
<article class="h-panel" id="h-{h['id']}" data-harness="{h['id']}" data-total="{len(h['rows'])}" aria-labelledby="h-{h['id']}-title">
  <header class="h-head">
    <div>
      <p class="eyebrow">{esc(h['vendor'])}</p>
      <h3 id="h-{h['id']}-title">{esc(h['name'])}</h3>
    </div>
    <div class="h-badges">{status}{badges}</div>
  </header>
  <p class="h-summary">{md(h['summary'])}</p>
  <p class="h-match"><span class="match-count" data-role="match-count">{len(h['rows'])} / {len(h['rows'])} rows match</span></p>
  <div class="table-wrap">
  <table class="store-table">
    <caption class="sr-only">{esc(h['name'])}: storage locations, what the harness keeps there, and what aiscan does</caption>
    <thead><tr><th scope="col">Category</th><th scope="col">Location (example)</th><th scope="col">What the harness keeps</th><th scope="col">What aiscan does</th></tr></thead>
    <tbody>{''.join(rows)}</tbody>
  </table>
  </div>
  <p class="no-rows" hidden>No rows in this harness match the current filters.</p>
  <aside class="cannot" aria-label="What aiscan cannot see for {esc(h['name'])}">
    <h4>aiscan cannot see</h4>
    <ul>{cannot}</ul>
  </aside>
</article>"""


def harness_section() -> str:
    total_rows = sum(len(h["rows"]) for h in A.HARNESSES)
    buttons = ['<button type="button" class="seg" data-harness="all" aria-pressed="true">All harnesses '
               f'<span class="seg-count" data-role="seg-count" aria-hidden="true">{total_rows}</span>'
               f'<span class="sr-only" data-role="seg-sr">, {total_rows} matching rows</span></button>']
    for h in A.HARNESSES:
        rows = len(h["rows"])
        buttons.append(
            f'<button type="button" class="seg" data-harness="{h["id"]}" aria-pressed="false" tabindex="-1" '
            f'title="{esc(h["name"])}">{esc(h["short"])}'
            f'<span class="seg-count" data-role="seg-count" aria-hidden="true">{rows}</span>'
            f'<span class="sr-only" data-role="seg-sr">, {rows} matching rows</span></button>'
        )
    cats = "".join(
        f'<label class="check"><input type="checkbox" name="cat" value="{k}" checked><span class="cat cat-{k}">{esc(v)}</span></label>'
        for k, v in A.CATEGORIES)
    modes = "".join(
        f'<li>{mode_badge(k)}<span>{esc(v[1])}</span></li>' for k, v in A.MODES.items())
    return f"""
<section id="harnesses" class="section" aria-labelledby="harnesses-title">
  <p class="kicker">03 · Harnesses</p>
  <h2 id="harnesses-title">Every supported harness: what it keeps, what aiscan does with it, and what aiscan cannot see</h2>
  <p class="lede">Rows come from collector source at the pinned commit. "What the harness keeps" is general storage; the
  right-hand column is what aiscan does with it. Remote rows describe vendor storage only where public docs confirm it.</p>
  <div class="controls needs-js" role="region" aria-label="Harness filters" id="harness-controls">
    <div class="control-block">
      <p class="control-label" id="harness-label">Harness</p>
      <div class="segmented" role="toolbar" aria-labelledby="harness-label" data-roving>{''.join(buttons)}</div>
    </div>
    <div class="control-row">
      <fieldset class="control-block">
        <legend class="control-label">Data category</legend>
        <div class="checks">{cats}</div>
      </fieldset>
      <div class="control-block search-block">
        <label class="control-label" for="harness-q">Filter rows by path or word</label>
        <input id="harness-q" type="search" placeholder="e.g. state.vscdb, sessions, MCP" autocomplete="off" spellcheck="false">
      </div>
    </div>
    <p class="count" id="harness-count" aria-live="polite">Showing {total_rows} of {total_rows} rows across {len(A.HARNESSES)} harnesses with matches.</p>
    <p class="count count-empty" id="harness-empty" aria-live="polite" hidden>No rows match the current filters. Clear the search or re-enable categories.</p>
  </div>
  <a class="to-filters" href="#harness-controls" hidden>↑ Filters</a>
  <details class="legend-box" open>
    <summary>Read-mode legend</summary>
    <ul class="mode-legend">{modes}</ul>
  </details>
  <div class="h-panels">{''.join(harness_panel(h) for h in A.HARNESSES)}</div>
</section>"""


def pipeline_section() -> str:
    tabs, panels = [], []
    for i, s in enumerate(A.PIPELINE):
        sel = "true" if i == 0 else "false"
        tabs.append(f'<button type="button" role="tab" id="tab-{s["id"]}" aria-controls="step-{s["id"]}" aria-selected="{sel}" '
                    f'tabindex="{0 if i == 0 else -1}" class="step-tab"><span class="step-tab-num">{i + 1:02d}</span>{esc(s["label"])}</button>')
        panels.append(f"""
<div class="step-panel" role="tabpanel" id="step-{s['id']}" aria-labelledby="tab-{s['id']}" tabindex="0">
  <h3><span class="step-tab-num">{i + 1:02d}</span> {esc(s['label'])} <code>{esc(s['short'])}</code></h3>
  <p>{md(s['what'])}</p>
  <dl class="kv">
    <dt>Inputs</dt><dd>{md(s['inputs'])}</dd>
    <dt>Outputs</dt><dd>{md(s['outputs'])}</dd>
    <dt>Reading the source</dt><dd>{md(s['adapt'])}</dd>
    <dt>Sources</dt><dd>{cites_html(s['cites'])}</dd>
  </dl>
</div>""")
    return f"""
<section id="architecture" class="section" aria-labelledby="arch-title">
  <p class="kicker">02 · Architecture</p>
  <h2 id="arch-title">How a scan runs, stage by stage</h2>
  <p class="lede">The usual summary is “collectors → normalized evidence → analysis → briefing”. That is close, with one correction: most analysis happens <em>inside</em> each collector. Collectors read
  files and assign severity themselves. Later steps never go back to the machine; they only read envelopes.</p>
  <figure class="figure">
    {pipeline_svg(False)}{pipeline_svg(True)}
    <figcaption>Select a stage, or use the tabs below with the arrow keys.</figcaption>
  </figure>
  <div class="stepper">
    <div role="tablist" aria-label="Pipeline stages" class="step-tabs">{''.join(tabs)}</div>
    {''.join(panels)}
    <div class="step-nav needs-js"><button type="button" class="btn" data-step-move="-1">← Previous stage</button><button type="button" class="btn" data-step-move="1">Next stage →</button></div>
  </div>
</section>"""


def boundary_section() -> str:
    return f"""
<section id="boundary" class="section" aria-labelledby="boundary-title">
  <p class="kicker">01 · Boundary</p>
  <h2 id="boundary-title">Local versus remote: the offline scan only sees this side of the line</h2>
  <p class="lede">Every harness also talks to its vendor. Those prompts, cloud sessions and server-side histories live above the
  boundary, and no collector in <code>aiscan all</code> reaches them. Select a store to jump to its harness entry.</p>
  <figure class="figure figure-boundary">
    {boundary_svg(False)}{boundary_svg(True)}
    <figcaption>Network use is limited to opt-in commands. <code>aiscan all</code> runs no collector that calls the network;
    <code>git-posture</code> could call <code>gh api</code> only with <code>--allow-gh</code>, which aiscan.ps1 does not pass.
    {cites_html([C_('aiscan.ps1', 8, 10, 'network'), C_('aiscan.ps1', 395, 397, '"git-posture"')])}</figcaption>
  </figure>
  <div class="grid-3">
    <div class="card card-local"><h3>Local, read by aiscan</h3><p>Config files, permission lists, MCP registries, session JSONL,
      SQLite state, app-data folders and git repositories on this machine. Some are parsed, some only stat'ed.</p></div>
    <div class="card card-remote"><h3>Remote, not read</h3><p>Vendor-side conversation storage, cloud sessions and tasks,
      synced histories, admin policy held in the cloud. A local scan cannot prove what is or is not stored there.</p></div>
    <div class="card card-optin"><h3>Remote, opt-in only</h3><p><code>aiscan cloud-agents</code> lists Cursor Cloud Agents through
      the official API with your key. <code>tools/github-access</code> is a separate script with its own token.</p></div>
  </div>
</section>"""


def C_(path, s, e, a):
    return A.C(path, s, e, a)


def cross_section() -> str:
    cards = []
    label = A.COLLECTOR_STATUS
    for c in A.CROSS_CUTTING:
        cards.append(f"""
<article class="card card-collector">
  <header><h3><code>{esc(c['name'])}</code></h3><span class="status status-{c['status']}">{esc(label[c['status']])}</span></header>
  <dl class="kv kv-tight">
    <dt>Reads</dt><dd>{md(c['what'])}</dd>
    <dt>Writes</dt><dd>{md(c['out'])}</dd>
    <dt>Safety</dt><dd>{md(c['safety'])}</dd>
  </dl>
  <p class="card-cites">{cites_html(c['cites'])}</p>
</article>""")
    inv_rows = []
    for name, ver, vc, status, inputs, net, raw in A.INVENTORY:
        inv_rows.append(
            f'<tr><th scope="row"><code>{esc(name)}</code></th><td>{esc(ver)} {cite_html(vc)}</td>'
            f'<td><span class="status status-{status}">{esc(label[status])}</span></td><td>{esc(inputs)}</td>'
            f'<td>{esc(net)}</td><td>{"<code>" + esc(raw) + "</code>" if raw != "—" else "—"}</td></tr>')
    notes = "".join(f"<li><strong>{esc(t)}.</strong> {md(d)}{cites_html(c)}</li>" for t, d, c in A.PLATFORM_NOTES)
    return f"""
<section id="collectors" class="section" aria-labelledby="coll-title">
  <p class="kicker">04 · Collectors</p>
  <h2 id="coll-title">Inventory: what runs, what is opt-in, what stands outside the pipeline</h2>
  <p class="lede">Twelve collectors run in <code>aiscan all</code>, in this order: claude, cowork, cursor, codex, vscode,
  chat-history, git-posture, secrets-scan, grok, grok-bot, pii-scan, accounts. {cites_html([C_('aiscan.ps1', 332, 335, '$StdlibOrder')])}
  The source has no "experimental" label; the groups below are the ones the code itself uses.</p>
  <div class="table-wrap">
  <table class="inv-table">
    <caption class="sr-only">Collector inventory</caption>
    <thead><tr><th scope="col">Collector</th><th scope="col">Version</th><th scope="col">Status</th><th scope="col">Inputs</th><th scope="col">Network</th><th scope="col">raw/ output</th></tr></thead>
    <tbody>{''.join(inv_rows)}
      <tr><th scope="row"><code>tools/mcp-visibility</code></th><td>—</td><td><span class="status status-tool">{esc(label['tool'])}</span></td><td>MCP configs</td><td>none</td><td>stdout</td></tr>
      <tr><th scope="row"><code>tools/github-access</code></th><td>—</td><td><span class="status status-tool">{esc(label['tool'])}</span></td><td>your GitHub token</td><td>GET api.github.com</td><td>stdout</td></tr>
    </tbody>
  </table>
  </div>
  <h3 class="sub">Cross-cutting collectors and tools</h3>
  <div class="grid-cards">{''.join(cards)}</div>
  <h3 class="sub">Optional, platform-dependent and unknown coverage</h3>
  <ul class="notes">{notes}
    <li><strong>Unknown by design.</strong> Grok Bot <code>local_execution</code> is always <code>unknown</code>; the access map keeps
    {sum(1 for _ in _uncaptured())} agent/capability pairs unknown because no envelope field could move them. See the coverage matrix below.</li>
  </ul>
</section>"""


def _uncaptured():
    src = (ROOT / "report" / "access_map.py").read_text(encoding="utf-8")
    block = src.split("UNCAPTURED: dict[tuple[str, str], str] = {", 1)[1].split("\n}\n", 1)[0]
    pairs = re.findall(r'\("([a-z-]+)", "([a-z]+)"\): \(\s*((?:"[^"]*"\s*)+)\)', block)
    for agent, col, text in pairs:
        yield agent, col, " ".join(re.findall(r'"([^"]*)"', text)).replace("  ", " ")


def coverage_section() -> str:
    src = (ROOT / "report" / "access_map.py").read_text(encoding="utf-8")
    agents = re.findall(r'\("([a-z-]+)", "([^"]+)", "[a-z-]+"\),', src.split("AGENTS:", 1)[1].split(")\n\nCOLUMNS", 1)[0])
    cols = re.findall(r'\("([a-z]+)", "([^"]+)", "([^"]+)"\),', src.split("COLUMNS:", 1)[1].split(")\n\n", 1)[0])
    unc = {(a, c): t for a, c, t in _uncaptured()}
    head = "".join(f'<th scope="col" title="{esc(full)}">{esc(short)}</th>' for _, full, short in cols)
    body = []
    for aid, aname in agents:
        cells = []
        for cid, full, short in cols:
            reason = unc.get((aid, cid))
            if reason:
                cells.append(f'<td class="cov-cell cov-unc"><button type="button" class="cov-btn" data-reason="{esc(reason)}" '
                             f'data-where="{esc(aname)} · {esc(full)}" aria-label="{esc(aname)}, {esc(full)}: never captured. {esc(reason)}">'
                             f'<span aria-hidden="true">unknown</span></button></td>')
            else:
                cells.append(f'<td class="cov-cell cov-ev"><span class="sr-only">{esc(aname)}, {esc(full)}: </span>from evidence</td>')
        body.append(f'<tr><th scope="row">{esc(aname)}</th>{"".join(cells)}</tr>')
    return f"""
<section id="coverage" class="section" aria-labelledby="cov-title">
  <p class="kicker">07 · Coverage</p>
  <h2 id="cov-title">Coverage matrix: which questions the evidence can never answer</h2>
  <p class="lede">The briefing's access map is computed from envelopes only. For the hatched pairs, no field in that collector's
  envelope can move the answer off <em>unknown</em>, so the map says unknown even when nearby fields look alarming.
  "From evidence" means the cell <em>can</em> be filled by a real scan; it is not a claim about any machine.
  {cites_html([C_('report/access_map.py', 42, 44, 'UNCAPTURED'), C_('report/access_map.py', 21, 40, 'COLUMNS')])}</p>
  <p class="scroll-hint needs-js" id="cov-scroll-hint" hidden>Swipe sideways to view more capability columns →</p>
  <div class="table-wrap cov-wrap" tabindex="0" role="region" aria-label="Coverage matrix, scroll sideways for more columns">
  <table class="cov-table">
    <caption class="sr-only">Access-map coverage by agent and capability</caption>
    <thead><tr><th scope="col">Agent</th>{head}</tr></thead>
    <tbody>{''.join(body)}</tbody>
  </table>
  </div>
  <div class="cov-reason needs-js" id="cov-reason" aria-live="polite"><p class="muted">Select an <em>unknown</em> cell to read the reason from source.</p></div>
</section>"""


def evidence_section() -> str:
    tree = []
    for name, kind, note, cite in A.OUTPUT_TREE:
        indent = len(name) - len(name.lstrip(" "))
        tree.append(f'<li class="tree-{kind}" style="--depth:{indent // 2}"><code>{esc(name.strip())}</code>'
                    f'<span class="tree-tag tag-{kind}">{ {"dir": "folder", "safe": "safe summary", "review": "review before sharing", "local": "local only"}[kind] }</span>'
                    f'<span class="tree-note">{md(note)}</span>{cites_html([cite] if cite else [])}</li>')
    fields = "".join(
        f'<tr><th scope="row"><code>{esc(f)}</code></th><td><span class="take take-{t.split()[0]}">{esc(t)}</span></td><td>{md(d)}</td></tr>'
        for f, t, d in A.ENVELOPE_FIELDS)
    sample = esc("""{
  "collector": "claude",
  "version": "1.4.0",
  "aiscan_version": "0.2.0",
  "ran_at": "2026-01-01T09:00:00+00:00",
  "host": "EXAMPLE-HOST",
  "platform_detected": true,
  "scope_hash": "<sha256 of scanned paths>",
  "summary": { "allow_rules": 3, "permission_mode": "default" },
  "findings": [{
    "id": "claude.permission.bash_curl_wide",
    "severity": "high",
    "category": "Shell Execution",
    "title": "Claude has unrestricted curl approval",
    "evidence_count": 1,
    "sample_redacted": "Bash(curl:*)",
    "secret_redacted": false,
    "tags": ["network_egress"]
  }],
  "rules": [{
    "platform": "claude", "scope": "project",
    "scope_label_redacted": "project#a1b2",
    "rule_type": "bash", "rule": "Bash(curl:*)",
    "decision": "allow", "source_kind": "project_config"
  }],
  "raw_pointers": []
}""")
    return f"""
<section id="evidence" class="section" aria-labelledby="ev-title">
  <p class="kicker">05 · Normalized evidence</p>
  <h2 id="ev-title">What a scan writes, and which parts may ever leave the machine</h2>
  <p class="lede">Every collector emits the same envelope through <code>core/common.py</code>. The <code>_redacted</code> suffix is a
  field name, not a promise: values are masked only when the scan ran with <code>-Redact</code>.
  {cites_html(A.ENVELOPE_CITES)}</p>
  <div class="grid-2">
    <div>
      <h3 class="sub">Scan folder</h3>
      <ul class="tree">{''.join(tree)}</ul>
      <p class="muted small"><code>discovery.json</code> is written only by <code>core/discover.py --write-discovery</code>, not by
      aiscan.ps1. The opt-in telemetry import adds <code>raw\\telemetry-import\\</code>.</p>
    </div>
    <div>
      <h3 class="sub">Envelope (synthetic example)</h3>
      <pre class="code" tabindex="0" aria-label="Synthetic evidence envelope example"><code>{sample}</code></pre>
    </div>
  </div>
  <div class="table-wrap">
  <table class="field-table">
    <caption>Envelope fields and the schema's take-home marks</caption>
    <thead><tr><th scope="col">Field</th><th scope="col">Take-home</th><th scope="col">Meaning</th></tr></thead>
    <tbody>{fields}</tbody>
  </table>
  </div>
</section>"""


def safety_section() -> str:
    rows = "".join(
        f'<tr><th scope="row">{esc(item)}</th><td>{md(d)}</td><td>{md(r)}</td><td>{cites_html(c)}</td></tr>'
        for item, d, r, c in A.REDACTION)
    guarantees = "".join(f'<li><h3>{esc(t)}</h3><p>{md(d)}</p>{cites_html(c)}</li>' for t, d, c in A.GUARANTEES)
    return f"""
<section id="safety" class="section" aria-labelledby="safety-title">
  <p class="kicker">06 · Safety &amp; redaction</p>
  <h2 id="safety-title">Unredacted by default. <code>-Redact</code> masks evidence and the briefing, never <code>raw\\</code>.</h2>
  <p class="lede">aiscan assumes it runs on the operator's own machine, where masking would hide the thing being inspected. Treat any
  default scan folder as sensitive. {cites_html([C_('core/common.py', 251, 259, 'def redaction_disabled('), C_('aiscan.ps1', 253, 256, 'AISCAN_REDACT')])}</p>
  <div class="callout callout-warn" role="note">
    <strong>Before sharing anything:</strong> rerun with <code>-Redact</code>, drop <code>raw\\</code>, <code>raw_pointers</code> and
    <code>raw_evidence_ref</code>, and still review the output. Workspace names inside command strings and the short hostname can survive redaction.
    {cites_html([C_('SCHEMA.md', 196, 203, 'Known residue')])}
  </div>
  <div class="table-wrap">
  <table class="red-table">
    <caption class="sr-only">Redaction behavior with and without -Redact</caption>
    <thead><tr><th scope="col">Output</th><th scope="col">Default run</th><th scope="col">With -Redact</th><th scope="col">Source</th></tr></thead>
    <tbody>{rows}</tbody>
  </table>
  </div>
  <h3 class="sub">Read-only and no-egress guarantees in code</h3>
  <ul class="guarantees">{guarantees}</ul>
</section>"""


def manifest_section() -> str:
    by_file = defaultdict(set)
    for cite in iter_cites(all_content()):
        if cite[0] == "src":
            by_file[cite[1]].add((cite[2], cite[3]))
    rows = []
    for path in sorted(by_file):
        ranges = sorted(by_file[path])
        links = ", ".join(
            f'<a href="{esc(src_url(path, s, e))}" target="_blank" rel="noopener noreferrer">{s if s == e else f"{s}–{e}"}</a>'
            for s, e in ranges)
        rows.append(f'<tr><th scope="row"><a href="{esc(src_url(path))}" target="_blank" rel="noopener noreferrer"><code>{esc(path)}</code></a></th>'
                    f'<td class="ranges">{links}</td></tr>')
    docs = "".join(
        f'<tr><th scope="row"><a href="{esc(d["url"])}" target="_blank" rel="noopener noreferrer">{esc(d["title"])}</a></th>'
        f'<td>{esc(d["accessed"])}</td><td>{esc(d["used_for"])}</td></tr>'
        for d in A.DOCS.values())
    lim = "".join(f"<li>{md(t)}</li>" for t in A.LIMITATIONS)
    n_ranges = sum(len(v) for v in by_file.values())
    return f"""
<section id="sources" class="section" aria-labelledby="src-title">
  <p class="kicker">08 · Source manifest</p>
  <h2 id="src-title">Sources</h2>
  <p class="lede">Repository facts are pinned to commit <code class="sha">{A.BASE_SHA}</code> of
  <a href="{esc(A.REPO_URL)}" target="_blank" rel="noopener noreferrer">robrounsavall/ai-agent-audit</a> (aiscan {A.AISCAN_VERSION}).
  {n_ranges} line ranges across {len(by_file)} files; each range carries an anchor string that
  the build script&#x27;s <code>--verify</code> mode checks against the code.</p>
  <div class="table-wrap">
  <table class="src-table">
    <caption class="sr-only">Repository files and cited line ranges</caption>
    <thead><tr><th scope="col">File at {A.BASE_SHA[:12]}</th><th scope="col">Cited lines</th></tr></thead>
    <tbody>{''.join(rows)}</tbody>
  </table>
  </div>
  <h3 class="sub">Public documentation</h3>
  <div class="table-wrap">
  <table class="src-table">
    <caption class="sr-only">Public vendor documentation</caption>
    <thead><tr><th scope="col">Page</th><th scope="col">Read on</th><th scope="col">Used for</th></tr></thead>
    <tbody>{docs}</tbody>
  </table>
  </div>
</section>
<section id="limitations" class="section" aria-labelledby="lim-title">
  <p class="kicker">09 · Limitations</p>
  <h2 id="lim-title">Limits of this page</h2>
  <ul class="notes">{lim}</ul>
</section>"""


def hero() -> str:
    facts = [
        ("Offline by default", "<code>aiscan all</code> runs twelve read-only collectors and makes no network calls.",
         [C_("aiscan.ps1", 8, 10, "network")]),
        ("Local scans cannot see remote histories",
         "Vendor-side transcripts, cloud sessions and synced history sit outside the machine. Inside aiscan.ps1, only the opt-in cloud-agents command calls a vendor API.",
         [C_("aiscan.ps1", 8, 11, "cloud-agents"),
          C_("aiscan.ps1", 328, 330, "Opt-in collectors stay out of $StdlibOrder"),
          C_("components/cloud-agents/cloud-agents.py", 131, 132, "GET only, and only https://api.cursor.com paths this inventory needs.")]),
        ("Unredacted by default", "Evidence and the briefing keep real paths, names and secret-shaped samples unless you pass <code>-Redact</code>.",
         [C_("core/common.py", 251, 259, "def redaction_disabled(")]),
        ("Two layers", "<code>evidence\\</code> holds structured envelopes. <code>raw\\</code> holds transcript text and scanner CSVs and is never redacted.",
         [C_("SCHEMA.md", 166, 169, "Chat transcript text NEVER appears in evidence/"),
          C_("aiscan.ps1", 685, 688, "raw\\ is NOT redacted")]),
        ("Coverage is uneven", "Claude, Codex and Cursor configs are parsed in depth. Grok Bot is presence-only, and local execution there is reported as unknown.",
         [C_("components/grok-bot/grok-bot.py", 97, 98, "not_determinable_offline")]),
    ]
    items = "".join(f"<li><p class=\"fact-title\">{t}</p><p>{d}</p>{cites_html(c)}</li>" for t, d, c in facts)
    return f"""
<header class="hero" id="top">
  <p class="kicker">Reference · aiscan {A.AISCAN_VERSION} · source commit <code class="sha" title="{A.BASE_SHA}">{A.BASE_SHA[:12]}</code></p>
  <h1>aiscan Data Map</h1>
  <p class="hero-lede">Where AI coding harnesses keep data on a Windows machine, what aiscan reads, and what it cannot see.</p>
  <ul class="facts">{items}</ul>
  <p class="hero-meta">Researched {A.RESEARCHED_ON} from repository source and public vendor docs. All paths are generic placeholders such as
  <code>%USERPROFILE%</code>, <code>%APPDATA%</code> and <code>&lt;repo&gt;</code>. No machine was scanned to make this page.</p>
</header>"""


NAV = [("boundary", "Local vs remote"), ("architecture", "Architecture"), ("harnesses", "Harnesses"),
       ("collectors", "Collectors"), ("evidence", "Evidence"), ("safety", "Safety & redaction"),
       ("coverage", "Coverage matrix"), ("sources", "Sources"), ("limitations", "Limitations")]


def page() -> str:
    nav = "".join(f'<li><a href="#{i}">{esc(t)}</a></li>' for i, t in NAV)
    csp = ("default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; "
           "img-src data:; font-src 'none'; connect-src 'none'; base-uri 'none'; form-action 'none'")
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="{csp}">
<meta name="referrer" content="no-referrer">
<meta name="color-scheme" content="light dark">
<meta name="description" content="Where AI coding harnesses store data, what aiscan reads, and what it cannot see.">
<title>aiscan Data Map · harness storage and scanner coverage</title>
<style>{CSS}</style>
</head>
<body>
<a class="skip" href="#main">Skip to content</a>
<div class="layout">
  <nav class="toc" aria-label="Sections">
    <a class="brand" href="#top"><span class="brand-mark" aria-hidden="true"></span>aiscan Data Map</a>
    <details class="toc-menu" open><summary>Sections</summary><ol>{nav}</ol></details>
    <p class="toc-meta">Commit <code>{A.BASE_SHA[:7]}</code><br>Offline file · no requests</p>
  </nav>
  <main id="main">
    {hero()}
    {boundary_section()}
    {pipeline_section()}
    {harness_section()}
    {cross_section()}
    {evidence_section()}
    {safety_section()}
    {coverage_section()}
    {manifest_section()}
    <footer class="foot"><p>Generated by <code>docs/data-map/build_data_map.py</code> from <code>docs/data-map/data_map_content.py</code>.
    Not affiliated with Anthropic, OpenAI, Cursor, xAI, Microsoft or GitHub. <a href="#top">Back to top</a></p></footer>
  </main>
</div>
<script>{JS}</script>
</body>
</html>
"""


CSS = r"""
:root{
  --paper:#f6f5f1; --surface:#ffffff; --surface-2:#fbfaf7; --ink:#15181f; --ink-2:#424957; --muted:#5f6675; --line:#dcd8cd; --line-2:#ebe8df;
  --local:#0b6b61; --local-bg:#e2f1ed; --local-line:#7cc2b6;
  --remote:#9a4300; --remote-bg:#fbebdc; --remote-line:#e0a774;
  --aiscan:#3534a6; --aiscan-bg:#e9e8fb; --aiscan-line:#9896e6;
  --raw:#86266a; --raw-bg:#f8e5f1;
  --warn:#9e1430; --warn-bg:#fce6ea;
  --focus:#1b5fd1;
  --sans:"Segoe UI Variable Text","Segoe UI",system-ui,-apple-system,"Helvetica Neue",Arial,sans-serif;
  --display:"Segoe UI Variable Display","Segoe UI",system-ui,-apple-system,"Helvetica Neue",Arial,sans-serif;
  --mono:"Cascadia Mono","Cascadia Code",ui-monospace,"SF Mono",Menlo,Consolas,"Liberation Mono",monospace;
  --radius:14px;
}
@media (prefers-color-scheme: dark){
  :root{
    --paper:#111318; --surface:#181b22; --surface-2:#1d2129; --ink:#eceef2; --ink-2:#c3c8d2; --muted:#9aa1ae; --line:#2f3440; --line-2:#262a34;
    --local:#5fd0bf; --local-bg:#12302c; --local-line:#2f7d72;
    --remote:#f2a766; --remote-bg:#3a2414; --remote-line:#8f5a2c;
    --aiscan:#a9a7ff; --aiscan-bg:#23224a; --aiscan-line:#5d5bc4;
    --raw:#f08acd; --raw-bg:#3a1830;
    --warn:#ff8da0; --warn-bg:#3d1720; --focus:#7fb0ff;
  }
}
*{box-sizing:border-box}
html{-webkit-text-size-adjust:100%}
body{margin:0; background:var(--paper); color:var(--ink); font:16px/1.6 var(--sans); font-kerning:normal; text-rendering:optimizeLegibility}
a{color:var(--aiscan); text-underline-offset:2px}
code,pre{font-family:var(--mono); font-size:.88em}
code{background:var(--line-2); padding:.08em .35em; border-radius:5px; overflow-wrap:anywhere}
:focus-visible{outline:3px solid var(--focus); outline-offset:2px; border-radius:6px}
.sr-only{position:absolute!important; width:1px; height:1px; overflow:hidden; clip:rect(0 0 0 0); white-space:nowrap}
.skip{position:absolute; left:-999px; top:8px; background:var(--ink); color:var(--paper); padding:8px 14px; border-radius:8px; z-index:10}
.skip:focus{left:8px}
.layout{display:grid; grid-template-columns:250px minmax(0,1fr); max-width:1420px; margin:0 auto}
.toc{position:sticky; top:0; align-self:start; height:100vh; padding:28px 18px 20px 24px; border-right:1px solid var(--line); display:flex; flex-direction:column; gap:18px}
.brand{font:700 1rem/1.2 var(--display); color:var(--ink); text-decoration:none; display:flex; align-items:center; gap:10px; letter-spacing:-.01em}
.brand-mark{width:22px; height:22px; border-radius:6px; background:linear-gradient(135deg,var(--local) 0 50%,var(--remote) 50% 100%)}
.toc-menu summary{font-size:.8125rem; text-transform:uppercase; letter-spacing:.06em; color:var(--muted); cursor:pointer; list-style:none; font-weight:650}
.toc-menu summary::-webkit-details-marker{display:none}
.toc ol{list-style:none; margin:10px 0 0; padding:0; counter-reset:s}
.toc li{counter-increment:s}
.toc li a{display:flex; gap:10px; padding:6px 10px; margin-left:-10px; border-radius:8px; color:var(--ink-2); text-decoration:none; font-size:.9375rem}
.toc li a::before{content:counter(s,decimal-leading-zero); font:600 .8125rem/1.9 var(--mono); color:var(--muted)}
.toc li a:hover,.toc li a[aria-current="true"]{background:var(--surface); color:var(--ink)}
.toc li a[aria-current="true"]{box-shadow:inset 3px 0 0 var(--aiscan)}
.toc-meta{margin-top:auto; font-size:.8125rem; color:var(--muted); line-height:1.5}
main{padding:0 clamp(18px,4vw,64px) 80px; min-width:0}
.hero{padding:64px 0 36px; border-bottom:1px solid var(--line)}
.kicker{font:650 .8125rem/1.4 var(--sans); text-transform:uppercase; letter-spacing:.06em; color:var(--muted); margin:0 0 12px}
.kicker code{text-transform:none; letter-spacing:0}
h1{font:780 clamp(2.4rem,5.4vw,4.1rem)/1.02 var(--display); letter-spacing:-.035em; margin:0 0 16px}
.hero-lede{font-size:clamp(1.125rem,2vw,1.375rem); line-height:1.45; color:var(--ink-2); max-width:44ch; margin:0 0 34px}
.facts{list-style:none; padding:0; margin:0 0 26px; display:grid; grid-template-columns:repeat(6,minmax(0,1fr)); gap:14px}
.facts li{grid-column:span 2} .facts li:nth-child(n+4){grid-column:span 3}
@media (max-width:900px){ .facts{grid-template-columns:minmax(0,1fr)} .facts li,.facts li:nth-child(n+4){grid-column:auto} }
.facts li{background:var(--surface); border:1px solid var(--line); border-radius:var(--radius); padding:16px 18px}
.fact-title{font:700 1rem/1.3 var(--display); margin:0 0 6px; letter-spacing:-.01em}
.facts p{margin:0 0 8px; color:var(--ink-2); font-size:.9375rem; line-height:1.5}
.hero-meta{font-size:.875rem; color:var(--muted); max-width:80ch; margin:0}
.section{padding:56px 0 18px; border-bottom:1px solid var(--line); scroll-margin-top:12px}
h2{font:740 clamp(1.55rem,3vw,2.15rem)/1.15 var(--display); letter-spacing:-.025em; margin:0 0 14px; max-width:30ch}
h3{font-family:var(--display); letter-spacing:-.01em}
.sub{font-size:1.125rem; margin:34px 0 12px}
.lede{font-size:1rem; color:var(--ink-2); max-width:76ch; margin:0 0 24px}
.muted{color:var(--muted)} .small{font-size:.875rem}
.figure{margin:0 0 24px; background:var(--surface); border:1px solid var(--line); border-radius:var(--radius); padding:clamp(10px,2vw,22px)}
.figure figcaption{font-size:.875rem; color:var(--muted); margin-top:10px; max-width:90ch}
.diagram{width:100%; height:auto; display:block}
.diagram-narrow{display:none}
@media (max-width:760px){ .diagram-wide{display:none} .diagram-narrow{display:block} }
.diagram text{font-family:var(--sans); fill:var(--ink)}
.zone-remote{fill:var(--remote-bg); stroke:var(--remote-line); stroke-width:1.5}
.zone-local{fill:var(--local-bg); stroke:var(--local-line); stroke-width:1.5}
.zone-label{font-size:13px; font-weight:750; letter-spacing:.06em}
.zone-label-remote{fill:var(--remote)!important} .zone-label-local{fill:var(--local)!important} .zone-label-out{fill:var(--aiscan)!important; font-family:var(--mono)!important; letter-spacing:0}
.node-remote{fill:var(--surface); stroke:var(--remote-line); stroke-dasharray:5 4; stroke-width:1.4}
.node-store{fill:var(--surface); stroke:var(--local-line); stroke-width:1.4}
.node-aiscan{fill:var(--aiscan-bg); stroke:var(--aiscan-line); stroke-width:1.6}
.node-evidence{fill:var(--surface); stroke:var(--aiscan-line); stroke-width:1.4}
.node-raw{fill:var(--raw-bg); stroke:var(--raw); stroke-width:1.4}
.node-title{font-size:15px; font-weight:680}
.node-title-lg{font-size:17px}
.node-sub{font-size:12.5px; fill:var(--ink-2)!important}
.node-sub-strong{font-weight:650; fill:var(--aiscan)!important}
.node-path,.node-mono{font-family:var(--mono)!important; font-size:12px}
.node-path{fill:var(--ink-2)!important}
.boundary{stroke:var(--ink); stroke-width:2.2; stroke-dasharray:10 7}
.boundary-pill{fill:var(--ink)}
.boundary-text{font-size:12.5px; font-weight:700; fill:var(--paper)!important; letter-spacing:.02em}
.flow-read{stroke:var(--local); stroke-width:2.4; fill:none}
.flow-write{stroke:var(--aiscan); stroke-width:2.4; fill:none}
.flow-optin{stroke:var(--remote); stroke-width:2.2; fill:none; stroke-dasharray:6 5}
.flow-vendor{stroke:var(--muted); stroke-width:1.6; stroke-dasharray:2 5; fill:none}
.mk-read{fill:var(--local)} .mk-write{fill:var(--aiscan)} .mk-optin{fill:var(--remote)}
.optin-text{font-size:12.5px; font-weight:650; fill:var(--remote)!important}
.legend-text{font-size:12.5px; fill:var(--ink-2)!important}
.svg-link rect{transition:stroke-width .12s}
.svg-link:hover rect,.svg-link:focus rect{stroke-width:3; stroke:var(--aiscan)}
.svg-link:focus{outline:none}
.svg-link:focus-visible rect{stroke:var(--focus); stroke-width:3.5}
.step-node{fill:var(--surface-2); stroke:var(--line); stroke-width:1.4}
.step-link.is-active .step-node{fill:var(--aiscan-bg); stroke:var(--aiscan); stroke-width:2.4}
.step-num{font:700 12px var(--mono); fill:var(--muted)!important}
.band{fill:var(--local-bg); stroke:var(--local-line)}
.band-text{font-size:13.5px; font-weight:700; fill:var(--local)!important}
.band-text-muted{fill:var(--muted)!important; font-weight:600}
.band-muted{fill:var(--line-2); stroke:var(--line)}
.grid-3{display:grid; grid-template-columns:repeat(auto-fit,minmax(240px,1fr)); gap:14px; margin-bottom:24px}
.grid-2{display:grid; grid-template-columns:repeat(auto-fit,minmax(320px,1fr)); gap:24px; margin-bottom:24px}
.card{background:var(--surface); border:1px solid var(--line); border-radius:var(--radius); padding:16px 18px}
.card h3{margin:0 0 6px; font-size:1rem}
.card p{margin:0; color:var(--ink-2); font-size:.9375rem}
.card-local{border-top:4px solid var(--local)} .card-remote{border-top:4px solid var(--muted)} .card-optin{border-top:4px solid var(--remote)}
.stepper{background:var(--surface); border:1px solid var(--line); border-radius:var(--radius); overflow:hidden; margin-bottom:24px}
.step-tabs{display:flex; overflow-x:auto; border-bottom:1px solid var(--line); background:var(--surface-2); scrollbar-width:thin}
.step-tab{flex:1 0 auto; border:0; background:none; font:600 .9375rem var(--sans); color:var(--ink-2); padding:13px 16px; cursor:pointer; border-bottom:3px solid transparent; display:flex; gap:8px; align-items:baseline; white-space:nowrap}
.step-tab[aria-selected="true"]{color:var(--ink); border-bottom-color:var(--aiscan); background:var(--surface)}
.step-tab-num{font:700 .8125rem var(--mono); color:var(--muted)}
.step-panel{padding:20px clamp(16px,3vw,28px) 8px}
.js .step-panel:not(.is-active){display:none}
.step-panel h3{margin:0 0 10px; font-size:1.375rem; display:flex; flex-wrap:wrap; gap:10px; align-items:baseline}
.step-panel h3 code{font-size:.8125rem}
.step-panel > p{max-width:78ch; margin:0 0 14px}
.step-nav{display:flex; justify-content:space-between; gap:10px; padding:4px clamp(16px,3vw,28px) 18px}
.btn{font:600 .875rem var(--sans); color:var(--ink); background:var(--surface-2); border:1px solid var(--line); border-radius:999px; padding:8px 16px; cursor:pointer}
.btn:hover{border-color:var(--aiscan)}
.kv{display:grid; grid-template-columns:150px minmax(0,1fr); gap:8px 18px; margin:0 0 14px; font-size:.9375rem}
.kv dt{font-weight:650; color:var(--muted); font-size:.8125rem; text-transform:uppercase; letter-spacing:.06em; padding-top:3px}
.kv dd{margin:0}
.kv-tight{grid-template-columns:70px minmax(0,1fr); font-size:.875rem}
.controls{position:sticky; top:0; z-index:3; background:var(--paper); padding:12px 0 10px; border-bottom:1px solid var(--line); margin-bottom:14px}
.needs-js{display:none} .js .needs-js{display:block} .js .step-nav.needs-js{display:flex}
.control-label{font:650 .8125rem var(--sans); text-transform:uppercase; letter-spacing:.06em; color:var(--muted); margin:0 0 6px; padding:0}
.control-block{border:0; margin:0; padding:0; min-width:0}
.control-row{display:flex; flex-wrap:wrap; gap:12px 28px; margin-top:12px; align-items:flex-end}
.segmented{display:flex; flex-wrap:wrap; gap:6px}
.seg{font:600 .875rem var(--sans); border:1px solid var(--line); background:var(--surface); color:var(--ink-2); border-radius:999px; padding:6px 13px; cursor:pointer; display:inline-flex; align-items:center; gap:7px}
.seg[aria-pressed="true"]{background:var(--ink); color:var(--paper); border-color:var(--ink)}
.seg-count{font:700 .8125rem var(--mono); background:var(--line-2); color:var(--ink-2); border-radius:999px; padding:1px 7px; line-height:1.2}
.seg[aria-pressed="true"] .seg-count{background:color-mix(in srgb,var(--paper) 20%,transparent); color:var(--paper)}
.checks{display:flex; flex-wrap:wrap; gap:6px 12px}
.check{display:inline-flex; align-items:center; gap:6px; cursor:pointer; font-size:.875rem}
.check input{width:17px; height:17px; accent-color:var(--aiscan); margin:0}
.search-block{flex:1 1 240px}
input[type=search]{width:100%; font:.9375rem var(--sans); padding:8px 12px; border:1px solid var(--line); border-radius:10px; background:var(--surface); color:var(--ink)}
.count{font-size:.875rem; color:var(--muted); margin:10px 0 0}
.legend-box{margin:0 0 18px; font-size:.9375rem}
.legend-box summary{cursor:pointer; font-weight:650; color:var(--ink-2)}
.mode-legend{list-style:none; padding:0; margin:10px 0 0; display:grid; grid-template-columns:repeat(auto-fit,minmax(300px,1fr)); gap:8px 20px}
.mode-legend li{display:flex; gap:10px; align-items:baseline; color:var(--ink-2)}
.mode-legend .mode{flex:0 0 auto}
.h-panel{background:var(--surface); border:1px solid var(--line); border-radius:var(--radius); padding:20px clamp(14px,2.5vw,26px); margin-bottom:20px; scroll-margin-top:170px}
.h-panel.is-hidden,.store-row.is-hidden{display:none}
.h-head{display:flex; flex-wrap:wrap; justify-content:space-between; gap:10px 20px; align-items:flex-end; margin-bottom:8px}
.h-head h3{margin:0; font-size:1.375rem; letter-spacing:-.02em}
.eyebrow{margin:0; font-size:.8125rem; color:var(--muted); text-transform:uppercase; letter-spacing:.06em; font-weight:650}
.h-badges{display:flex; flex-wrap:wrap; gap:6px; align-items:center}
.h-summary{max-width:84ch; color:var(--ink-2); margin:0 0 14px}
.h-match{margin:0 0 10px}
.match-count{font:650 .8125rem var(--mono); color:var(--muted)}
.chip{font:600 .8125rem var(--mono); padding:2px 8px; border-radius:6px; background:var(--aiscan-bg); color:var(--aiscan)}
.status{font:650 .8125rem var(--sans); padding:3px 9px; border-radius:999px; white-space:nowrap; letter-spacing:.02em}
.status-all{background:var(--local-bg); color:var(--local)}
.status-optin{background:var(--remote-bg); color:var(--remote)}
.status-tool{background:var(--line-2); color:var(--ink-2)}
.status-derived{background:var(--aiscan-bg); color:var(--aiscan)}
.table-wrap{overflow-x:auto; margin:0 0 16px}
table{border-collapse:collapse; width:100%; font-size:.9375rem}
th,td{text-align:left; vertical-align:top; padding:10px 12px; border-bottom:1px solid var(--line-2)}
thead th{font:650 .8125rem var(--sans); text-transform:uppercase; letter-spacing:.06em; color:var(--muted); border-bottom:1px solid var(--line); white-space:nowrap}
caption{text-align:left; font-weight:650; padding:0 0 8px}
.store-table td:nth-child(1){width:120px} .store-table td:nth-child(2){width:26%} .store-table td:nth-child(3){width:24%}
code.path{background:none; padding:0; font-size:.875rem; color:var(--ink); word-break:break-word}
.cat{font:650 .8125rem var(--sans); padding:2px 8px; border-radius:999px; white-space:nowrap; border:1px solid var(--line)}
.cat-auth{color:#7a3e00; background:#fff2dc; border-color:#f0d2a4}
.cat-config{color:var(--aiscan); background:var(--aiscan-bg); border-color:var(--aiscan-line)}
.cat-sessions{color:var(--raw); background:var(--raw-bg); border-color:#e6b4d5}
.cat-cache{color:var(--local); background:var(--local-bg); border-color:var(--local-line)}
.cat-remote{color:var(--remote); background:var(--remote-bg); border-color:var(--remote-line)}
@media (prefers-color-scheme: dark){ .cat-auth{color:#ffd59a; background:#3a2a12; border-color:#6e5223} .cat-sessions{border-color:#6c2f58} }
.reads{list-style:none; margin:0; padding:0; display:grid; gap:8px}
.reads li{line-height:1.5}
.who{font:650 .8125rem var(--mono); margin:0 6px 0 4px}
.mode{display:inline-block; font:650 .8125rem var(--sans); padding:1px 7px; border-radius:5px; white-space:nowrap; vertical-align:1px; border:1.5px solid transparent}
.mode-parsed{background:var(--aiscan); color:#fff}
.mode-allowlist{border-color:var(--aiscan); color:var(--aiscan)}
.mode-metadata{border-color:var(--local); color:var(--local)}
.mode-stat{background:var(--line-2); color:var(--ink-2); border-color:var(--line)}
.mode-export{background:var(--raw); color:#fff}
.mode-notread{border:1.5px dashed var(--muted); color:var(--muted); text-decoration:line-through}
.mode-network{background:var(--remote); color:#fff}
@media (prefers-color-scheme: dark){ .mode-parsed,.mode-export,.mode-network{color:#111318} }
.cites{display:inline-flex; flex-wrap:wrap; gap:4px; margin-left:6px; vertical-align:1px}
.cite{font:600 .8125rem var(--mono); text-decoration:none; color:var(--ink-2); background:var(--surface-2); border:1px solid var(--line); border-radius:5px; padding:0 6px; white-space:nowrap}
.cite:hover{border-color:var(--aiscan); color:var(--aiscan)}
.cite-lines{color:var(--muted)}
.cite-doc{color:var(--remote); border-color:var(--remote-line); font-family:var(--sans)}
.cite-kind{font:700 .8125rem var(--sans); text-transform:uppercase; letter-spacing:.06em; margin-right:5px}
.cannot{margin-top:6px; border-left:4px solid var(--muted); background:var(--surface-2); border-radius:0 10px 10px 0; padding:10px 16px}
.cannot h4{margin:0 0 6px; font-size:.8125rem; text-transform:uppercase; letter-spacing:.06em; color:var(--muted)}
.cannot ul{margin:0; padding-left:18px}
.cannot li{margin:4px 0; font-size:.9375rem}
.no-rows{font-style:italic; color:var(--muted)}
.count-empty{color:var(--warn); font-weight:650}
.inv-table th[scope=row],.inv-table td:nth-child(2),.inv-table td:nth-child(3){white-space:nowrap}
.grid-cards{display:grid; grid-template-columns:repeat(auto-fit,minmax(300px,1fr)); gap:14px}
.card-collector header{display:flex; justify-content:space-between; gap:10px; align-items:center; margin-bottom:8px}
.card-collector h3{margin:0} .card-collector h3 code{font-size:.9375rem; background:none; padding:0}
.card-cites{margin:6px 0 0}
.notes{padding-left:20px; max-width:90ch} .notes li{margin:8px 0}
.tree{list-style:none; padding:0; margin:0; font-size:.875rem}
.tree li{padding:7px 0 7px calc(var(--depth) * 20px); border-bottom:1px dashed var(--line-2); display:flex; flex-wrap:wrap; gap:4px 10px; align-items:baseline}
.tree code{background:none; padding:0; font-weight:650}
.tree-note{color:var(--ink-2)}
.tree-tag{font:650 .8125rem var(--sans); text-transform:uppercase; letter-spacing:.06em; padding:1px 7px; border-radius:999px}
.tag-dir{background:var(--line-2); color:var(--muted)} .tag-safe{background:var(--local-bg); color:var(--local)}
.tag-review{background:var(--aiscan-bg); color:var(--aiscan)} .tag-local{background:var(--raw-bg); color:var(--raw)}
.code{background:#14171e; color:#e6e8ee; border-radius:12px; padding:16px 18px; overflow:auto; font-size:.875rem; line-height:1.55; margin:0; max-height:520px}
.code code{background:none; padding:0; color:inherit}
.take{font:650 .8125rem var(--sans); padding:2px 8px; border-radius:999px; white-space:nowrap}
.take-yes{background:var(--local-bg); color:var(--local)} .take-after{background:var(--aiscan-bg); color:var(--aiscan)} .take-never{background:var(--warn-bg); color:var(--warn)}
.callout{border-radius:12px; padding:14px 18px; margin:0 0 20px; max-width:100ch}
.callout-warn{background:var(--warn-bg); border:1px solid color-mix(in srgb,var(--warn) 40%,transparent); color:var(--ink)}
.callout-warn strong{color:var(--warn)}
.red-table th[scope=row]{width:20%}
.guarantees{list-style:none; padding:0; display:grid; grid-template-columns:repeat(auto-fit,minmax(280px,1fr)); gap:12px}
.guarantees li{background:var(--surface); border:1px solid var(--line); border-radius:12px; padding:14px 16px}
.guarantees h3{margin:0 0 4px; font-size:1rem} .guarantees p{margin:0 0 6px; color:var(--ink-2); font-size:.9375rem}
.cov-wrap{position:relative}
.cov-wrap::after{content:""; position:sticky; right:0; top:0; float:right; width:56px; height:100%; pointer-events:none; opacity:0; background:linear-gradient(to right, rgba(0,0,0,0), color-mix(in srgb,var(--paper) 55%, var(--remote-bg)) 70%); box-shadow:inset -1px 0 0 color-mix(in srgb,var(--remote) 28%, transparent)}
.cov-wrap.is-scrollable::after{opacity:1}
.cov-wrap.at-end::after{opacity:0}
.scroll-hint{margin:-2px 0 10px; font-size:.875rem; color:var(--remote); font-weight:700; letter-spacing:.02em}
.cov-table{min-width:760px; table-layout:fixed}
.cov-table th[scope=row]{width:170px; font-weight:650; position:sticky; left:0; z-index:2; background:var(--surface)}
.cov-table thead th:first-child{position:sticky; left:0; z-index:3; background:var(--surface)}
.cov-table thead th{white-space:normal}
.cov-cell{text-align:center; padding:6px}
.cov-ev{color:var(--local); font-size:.8125rem; font-weight:600}
.cov-unc{background:repeating-linear-gradient(135deg,var(--line-2) 0 6px,transparent 6px 12px)}
.cov-btn{width:100%; font:650 .8125rem var(--sans); color:var(--ink); background:var(--surface); border:1px dashed var(--muted); border-radius:8px; padding:6px 4px; cursor:pointer}
.cov-btn[aria-pressed="true"]{border:2px solid var(--aiscan); color:var(--aiscan)}
.cov-reason{background:var(--surface); border:1px solid var(--line); border-radius:12px; padding:12px 16px; margin-bottom:24px; min-height:58px}
.cov-reason p{margin:0}
.src-table td.ranges{font:.8125rem var(--mono); line-height:1.8}
.src-table th[scope=row]{font-weight:500; width:44%}
.sha{font-size:.82em; word-break:break-all}
.foot{padding:28px 0; color:var(--muted); font-size:.875rem}
@media (max-width:1060px){
  .layout{grid-template-columns:1fr}
  .toc{position:static; height:auto; border-right:0; border-bottom:1px solid var(--line); padding:14px clamp(18px,4vw,64px); display:grid; grid-template-columns:1fr auto; align-items:center; gap:8px 20px}
  .toc-menu{grid-column:1/-1; order:3} .toc-menu ol{columns:2; column-gap:20px}
  .toc-menu summary{display:inline-block; padding:6px 12px; border:1px solid var(--line); border-radius:999px; background:var(--surface)}
  .toc-meta{margin:0; text-align:right}
  .controls{position:static}
  .h-panel{scroll-margin-top:12px}
}
@media (max-width:760px){
  body{font-size:16px}
  .hero{padding-top:34px}
  .kv{grid-template-columns:1fr; gap:2px}
  .kv dd{margin-bottom:10px}
  .toc-menu ol{columns:1}
  .figure{padding:8px}
  .controls{position:static}
  .step-tabs{flex-wrap:wrap; overflow:visible}
  .step-tab{flex:1 1 40%; padding:10px 12px}
  .kicker .sha{white-space:nowrap}
  .store-table thead{display:none}
  .store-table,.store-table tbody,.store-table tr,.store-table td{display:block; width:auto!important}
  .store-table tr{border:1px solid var(--line); border-radius:12px; padding:6px 12px; margin-bottom:10px; background:var(--surface-2)}
  .store-table td{border:0; padding:6px 0}
  .store-table td::before{content:attr(data-label); display:block; font:650 .8125rem var(--sans); text-transform:uppercase; letter-spacing:.06em; color:var(--muted); margin-bottom:2px}
  .red-table thead{display:none}
  .red-table,.red-table tbody,.red-table tr,.red-table th,.red-table td{display:block; width:auto!important}
  .red-table tr{border-bottom:1px solid var(--line); padding:8px 0}
  .red-table th,.red-table td{border:0; padding:3px 0}
  .red-table td:nth-of-type(1)::before{content:"Default: "; font-weight:650; color:var(--muted)}
  .red-table td:nth-of-type(2)::before{content:"With -Redact: "; font-weight:650; color:var(--muted)}
  .src-table th[scope=row]{width:auto}
  .grid-2{grid-template-columns:minmax(0,1fr)}
}
@media print{
  :root{--paper:#fff; --surface:#fff; --surface-2:#fff}
  body{font-size:10.5pt; background:#fff; color:#000}
  .layout{display:block}
  .toc,.controls,.needs-js,.skip,.step-tabs,.legend-box summary{display:none!important}
  .js .step-panel:not(.is-active){display:block}
  .step-panel{border-top:1px solid #ccc; break-inside:avoid}
  .h-panel.is-hidden,.store-row.is-hidden{display:revert}
  .no-rows{display:none!important}
  .diagram-narrow{display:none!important} .diagram-wide{display:block!important}
  main{padding:0}
  .section{padding:18pt 0 6pt; break-before:auto}
  #boundary,#harnesses,#sources{break-before:page}
  #boundary > .kicker,#boundary > h2,#boundary > .lede{break-after:avoid-page}
  #boundary .figure-boundary{margin-top:8pt}
  .h-panel,.figure,.card,.guarantees li,.facts li{break-inside:avoid; box-shadow:none}
  tr{break-inside:avoid}
  .table-wrap{overflow:visible}
  .code{max-height:none; background:#f4f4f4; color:#000; border:1px solid #ccc}
  a{color:#000}
  .cite{border-color:#999}
  .legend-box{display:block} .legend-box:not([open]) > *:not(summary){display:block}
  .hero{padding-top:0}
  h1{font-size:28pt}
}

/* ---- Data Map polish layer ---- */
@media screen{
  h1{font-size:clamp(2.2rem,4.6vw,3.4rem)}
  .kicker,.control-label,thead th,.eyebrow,.kv dt,.cannot h4,.toc-menu summary{font-weight:650; letter-spacing:.06em}
  .store-table{table-layout:fixed}
  .store-table th:nth-child(1),.store-table td:nth-child(1){width:150px}
  .store-table th:nth-child(2),.store-table td:nth-child(2){width:24%}
  .store-table th:nth-child(3),.store-table td:nth-child(3){width:22%}
  .store-table th:nth-child(4),.store-table td:nth-child(4){width:auto}
  .store-table .cat{white-space:normal; display:inline-block; line-height:1.35; border-radius:6px; padding:2px 8px}
  .reads{gap:0}
  .reads li{padding:8px 0}
  .reads li:first-child{padding-top:0}
  .reads li + li{border-top:1px dashed var(--line)}
  .reads .read-text{display:block; margin-top:4px}
  .reads .cites{display:flex; margin:6px 0 0}
  .cite{font-size:.75rem; padding:1px 7px}
  .mode-notread{text-decoration:none}
  .legend-box{background:var(--surface); border:1px solid var(--line); border-radius:12px; padding:10px 16px}
  .legend-box[open] summary{margin-bottom:4px}
  .to-filters{position:fixed; right:14px; bottom:14px; z-index:20; font:650 .875rem var(--sans); color:var(--paper); background:var(--ink); border-radius:999px; padding:10px 16px; text-decoration:none; box-shadow:0 4px 16px rgba(0,0,0,.25)}
  .to-filters[hidden]{display:none}
}
@media screen and (max-width:760px){
  .store-table td:nth-child(1)::before{display:none}
  .store-table td:nth-child(1){padding-top:8px}
  .store-table td::before{letter-spacing:.06em; font-size:.75rem}
  .h-panel{padding:16px 14px}
  .legend-box{padding:8px 12px}
  .mode-legend{grid-template-columns:1fr}
}
@media print{ .to-filters{display:none!important} }
"""


JS = r"""
(function(){
  var doc = document.documentElement;
  doc.classList.add('js');
  function $(s, r){ return (r || document).querySelector(s); }
  function $$(s, r){ return Array.prototype.slice.call((r || document).querySelectorAll(s)); }

  // Roving focus for any toolbar of buttons.
  $$('[data-roving]').forEach(function(bar){
    bar.addEventListener('keydown', function(e){
      var items = $$('button', bar), i = items.indexOf(document.activeElement);
      if (i < 0) return;
      var n = null;
      if (e.key === 'ArrowRight' || e.key === 'ArrowDown') n = (i + 1) % items.length;
      else if (e.key === 'ArrowLeft' || e.key === 'ArrowUp') n = (i - 1 + items.length) % items.length;
      else if (e.key === 'Home') n = 0;
      else if (e.key === 'End') n = items.length - 1;
      if (n === null) return;
      e.preventDefault();
      items[i].tabIndex = -1; items[n].tabIndex = 0; items[n].focus();
    });
  });

  // Harness filters.
  var state = { harness: 'all', cats: {}, q: '' };
  $$('input[name=cat]').forEach(function(c){ state.cats[c.value] = c.checked; });
  var segs = $$('.seg');
  var panels = $$('.h-panel');
  var countEl = $('#harness-count');
  var emptyEl = $('#harness-empty');
  function rowWord(n){ return n === 1 ? 'row' : 'rows'; }
  function harnessWord(n){ return n === 1 ? 'harness' : 'harnesses'; }
  function apply(){
    var shown = 0, total = 0, harnessShown = 0;
    var q = state.q.trim().toLowerCase();
    panels.forEach(function(p){
      var inHarness = state.harness === 'all' || p.getAttribute('data-harness') === state.harness;
      var visibleRows = 0, panelMatches = 0, panelTotal = 0;
      $$('.store-row', p).forEach(function(r){
        panelTotal++;
        total++;
        var base = state.cats[r.getAttribute('data-cat')] && (!q || r.textContent.toLowerCase().indexOf(q) !== -1);
        if (base) panelMatches++;
        var ok = inHarness && base;
        r.classList.toggle('is-hidden', !ok);
        if (ok) { visibleRows++; shown++; }
      });
      var panelVisible = state.harness === 'all' ? panelMatches > 0 : inHarness;
      p.classList.toggle('is-hidden', !panelVisible);
      if (panelVisible) harnessShown++;
      var empty = $('.no-rows', p);
      if (empty) empty.hidden = !(panelVisible && panelMatches === 0);
      var table = $('.table-wrap', p);
      if (table) table.style.display = (panelVisible && panelMatches === 0) ? 'none' : '';
      var match = $('[data-role="match-count"]', p);
      if (match) match.textContent = panelMatches + ' / ' + panelTotal + ' rows match';
      var hid = p.getAttribute('data-harness');
      var segCount = $('.seg[data-harness="' + hid + '"] [data-role="seg-count"]');
      var segSr = $('.seg[data-harness="' + hid + '"] [data-role="seg-sr"]');
      if (segCount) segCount.textContent = String(panelMatches);
      if (segSr) segSr.textContent = ', ' + panelMatches + ' matching ' + rowWord(panelMatches);
    });
    var allCount = $('.seg[data-harness="all"] [data-role="seg-count"]');
    var allSr = $('.seg[data-harness="all"] [data-role="seg-sr"]');
    if (allCount) allCount.textContent = String(shown);
    if (allSr) allSr.textContent = ', ' + shown + ' matching ' + rowWord(shown);
    if (countEl) {
      var suffix = state.harness === 'all' ? (' ' + harnessWord(harnessShown) + ' with matches.') : (' ' + harnessWord(harnessShown) + '.');
      countEl.textContent = 'Showing ' + shown + ' of ' + total + ' rows across ' + harnessShown + suffix;
    }
    if (emptyEl) emptyEl.hidden = shown !== 0;
    segs.forEach(function(b){
      var on = b.getAttribute('data-harness') === state.harness;
      b.setAttribute('aria-pressed', on ? 'true' : 'false');
      b.tabIndex = on ? 0 : -1;
    });
  }
  function selectHarness(id, scroll){
    if (!segs.some(function(b){ return b.getAttribute('data-harness') === id; })) id = 'all';
    state.harness = id;
    apply();
    if (scroll){
      var target = id === 'all' ? $('#harnesses') : $('#h-' + id);
      if (target) target.scrollIntoView({ block: 'start' });
    }
  }
  segs.forEach(function(b){
    b.addEventListener('click', function(){
      var id = b.getAttribute('data-harness');
      selectHarness(id, false);
      if (history.replaceState) history.replaceState(null, '', id === 'all' ? '#harnesses' : '#harness=' + id);
    });
  });
  $$('input[name=cat]').forEach(function(c){
    c.addEventListener('change', function(){ state.cats[c.value] = c.checked; apply(); });
  });
  var q = $('#harness-q');
  if (q) q.addEventListener('input', function(){ state.q = q.value; apply(); });
  function fromHash(scroll){
    var m = /^#harness=([a-z0-9-]+)$/.exec(location.hash);
    if (m) selectHarness(m[1], scroll);
  }
  window.addEventListener('hashchange', function(){ fromHash(true); });

  // Pipeline tabs.
  var tabs = $$('.step-tab');
  var stepLinks = $$('.step-link');
  function selectStep(i, focus){
    tabs.forEach(function(t, j){
      var on = i === j;
      t.setAttribute('aria-selected', on ? 'true' : 'false');
      t.tabIndex = on ? 0 : -1;
      var panel = document.getElementById(t.getAttribute('aria-controls'));
      if (panel) panel.classList.toggle('is-active', on);
      if (on && focus) t.focus();
    });
    var id = tabs[i] && tabs[i].getAttribute('aria-controls').replace('step-', '');
    stepLinks.forEach(function(a){ a.classList.toggle('is-active', a.getAttribute('data-step') === id); });
  }
  function currentStep(){ for (var i = 0; i < tabs.length; i++) if (tabs[i].getAttribute('aria-selected') === 'true') return i; return 0; }
  tabs.forEach(function(t, i){
    t.addEventListener('click', function(){ selectStep(i, false); });
    t.addEventListener('keydown', function(e){
      var n = null;
      if (e.key === 'ArrowRight') n = (i + 1) % tabs.length;
      else if (e.key === 'ArrowLeft') n = (i - 1 + tabs.length) % tabs.length;
      else if (e.key === 'Home') n = 0;
      else if (e.key === 'End') n = tabs.length - 1;
      if (n === null) return;
      e.preventDefault(); selectStep(n, true);
    });
  });
  stepLinks.forEach(function(a){
    a.addEventListener('click', function(e){
      e.preventDefault();
      var id = a.getAttribute('data-step');
      for (var i = 0; i < tabs.length; i++) if (tabs[i].getAttribute('aria-controls') === 'step-' + id) { selectStep(i, true); break; }
    });
  });
  $$('[data-step-move]').forEach(function(b){
    b.addEventListener('click', function(){
      var n = currentStep() + parseInt(b.getAttribute('data-step-move'), 10);
      if (n >= 0 && n < tabs.length) selectStep(n, false);
    });
  });
  selectStep(0, false);

  // Coverage matrix reasons.
  var reason = $('#cov-reason');
  $$('.cov-btn').forEach(function(b){
    b.setAttribute('aria-pressed', 'false');
    b.addEventListener('click', function(){
      $$('.cov-btn').forEach(function(o){ o.setAttribute('aria-pressed', o === b ? 'true' : 'false'); });
      reason.innerHTML = '';
      var h = document.createElement('p'); var s = document.createElement('strong');
      s.textContent = b.getAttribute('data-where'); h.appendChild(s);
      var p = document.createElement('p'); p.textContent = b.getAttribute('data-reason');
      reason.appendChild(h); reason.appendChild(p);
    });
  });
  // Coverage table horizontal-scroll affordance.
  (function(){
    var wrap = $('.cov-wrap');
    var hint = $('#cov-scroll-hint');
    if (!wrap || !hint) return;
    function update(){
      var max = wrap.scrollWidth - wrap.clientWidth;
      var scrollable = max > 4;
      var atEnd = !scrollable || wrap.scrollLeft >= max - 2;
      wrap.classList.toggle('is-scrollable', scrollable);
      wrap.classList.toggle('at-end', atEnd);
      hint.hidden = !scrollable;
      if (scrollable) hint.textContent = atEnd ? 'Swipe left to review earlier columns ←' : 'Swipe sideways to view more capability columns →';
    }
    wrap.addEventListener('scroll', update, { passive: true });
    window.addEventListener('resize', update);
    update();
  })();

  // Section highlight in the table of contents.
  var navLinks = $$('.toc li a');
  if ('IntersectionObserver' in window){
    var io = new IntersectionObserver(function(entries){
      entries.forEach(function(en){
        if (!en.isIntersecting) return;
        navLinks.forEach(function(a){ a.setAttribute('aria-current', a.getAttribute('href') === '#' + en.target.id ? 'true' : 'false'); });
      });
    }, { rootMargin: '-20% 0px -70% 0px' });
    $$('main .section').forEach(function(s){ io.observe(s); });
  }

  var tocMenu = document.querySelector('.toc-menu');
  if (tocMenu && window.matchMedia('(max-width: 1060px)').matches) {
    tocMenu.open = false;
    $$('.toc-menu a').forEach(function(a){ a.addEventListener('click', function(){ tocMenu.open = false; }); });
  }

  // Print everything regardless of filters.
  var saved = null;
  window.addEventListener('beforeprint', function(){
    saved = $$('details').map(function(d){ return d.open; });
    $$('details').forEach(function(d){ d.open = true; });
  });
  window.addEventListener('afterprint', function(){
    if (saved) $$('details').forEach(function(d, i){ d.open = saved[i]; });
  });

  // Narrow screens: the filter bar is not sticky, so offer a way back to it.
  (function(){
    var btn = $('.to-filters'), ctr = $('#harness-controls'), sec = $('#harnesses');
    if (!btn || !ctr || !sec || !('IntersectionObserver' in window)) return;
    var narrow = window.matchMedia('(max-width: 1060px)'), ctrVisible = true, inSection = false;
    function upd(){ btn.hidden = !(narrow.matches && inSection && !ctrVisible); }
    new IntersectionObserver(function(es){ ctrVisible = es[0].isIntersecting; upd(); }).observe(ctr);
    new IntersectionObserver(function(es){ inSection = es[0].isIntersecting; upd(); }, { rootMargin: '0px 0px -40% 0px' }).observe(sec);
    if (narrow.addEventListener) narrow.addEventListener('change', upd);
  })();

  apply();
  fromHash(true);
})();
"""


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    ap.add_argument("--verify", action="store_true", help="check every citation anchor against the working tree")
    ap.add_argument("--check", action="store_true", help="fail if docs/aiscan-data-map.html is not up to date")
    ap.add_argument("--out", default=str(OUT))
    args = ap.parse_args()
    text = page()
    if args.verify:
        problems = verify()
        if problems:
            for p in problems:
                print(f"citation: {p}", file=sys.stderr)
            return 1
        n = len(set(iter_cites(all_content())))
        print(f"verified {n} distinct citations")
    out = Path(args.out)
    if args.check:
        if not out.exists() or out.read_text(encoding="utf-8") != text:
            print(f"{out} is stale; run python docs/data-map/build_data_map.py", file=sys.stderr)
            return 1
        print(f"{out} is up to date")
        return 0
    out.write_text(text, encoding="utf-8", newline="\n")
    print(f"wrote {out.relative_to(ROOT) if out.is_relative_to(ROOT) else out} ({len(text.encode('utf-8')):,} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
