"""Briefing section renderers wired by report/build-briefing.py.

Access map, scan-to-scan changes, and telemetry approvals/usage each render
their own HTML fragment. The briefing builder calls them and supplies a short
"not collected" note when a fragment is empty.
"""

from sections.access_map import render_access_map_nav, render_access_map_section
from sections.changes import render_changes_nav, render_changes_section
from sections.telemetry import (
    approvals_nav_link,
    render_approvals_section,
    render_usage_section,
    telemetry_nav_links,
    usage_nav_link,
)

__all__ = [
    "approvals_nav_link",
    "render_access_map_nav",
    "render_access_map_section",
    "render_approvals_section",
    "render_changes_nav",
    "render_changes_section",
    "render_usage_section",
    "telemetry_nav_links",
    "usage_nav_link",
]
