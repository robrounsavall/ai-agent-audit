"""
Signed-in account inventory for the AI tools aiscan already covers.

Usage:
    python accounts.py --evidence-root ./audit-run [--repo-roots ...] [--dry-run]

Read-only. For each tool the evidence row is: tool, signed_in
(yes/no/unknown), account identifier (email, username, org, plan when stored
in plain config), auth method, a home-relative source path, and last sign-in
time when a timestamp field exists.

This collector never prints or stores a token, API key, password, cookie, or
other secret value. It does not call the network, does not decrypt credential
stores, and does not open cookie or secret-store files.

Deliberately not read:
- Claude `.credentials.json` contents (presence only)
- token / API key / password values in auth.json, settings env, and MCP config
- Codex access_token and refresh_token (id_token is decoded locally; only
  email and plan claims are kept; the token string is discarded)
- Cursor state.vscdb keys other than cursorAuth/cachedEmail,
  cursorAuth/stripeMembershipType, cursorAuth/cachedSignUpType, and
  cursorAuth/stripeSubscriptionStatus. The database is copied first; the
  original is not opened with sqlite.
- Grok Bot cookies, Local Storage, Session Storage, Network, Cache, and
  sand-secrets / box-secrets files
- Git credential helpers and GitHub oauth_token lines in hosts.yml
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import re
import shutil
import sqlite3
import sys
import tempfile
import tomllib
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import paths
from common import (
    add_base_args,
    compute_scope_hash,
    default_repo_roots,
    finish_collector,
    looks_like_secret,
    make_envelope,
    make_finding,
    mask_secrets,
    parse_iso,
    redact_paths,
    redaction_disabled,
    validate_evidence_root,
)

__version__ = "1.0.0"

COLLECTOR = "accounts"

# Fixed sentences. No user data.
LIMITS = (
    "No network calls. Credential stores are not decrypted.",
    "Token, API key, password, and cookie values are never written.",
    "Claude .credentials.json is presence-only and is not opened.",
    "Codex email and plan come from the id_token payload only. The token is discarded.",
    "Cursor state.vscdb is copied, then only four cursorAuth keys are read.",
    "Grok Bot cookies, local/session storage, Network, and secrets-store files are not opened.",
    "GitHub hosts.yml contributes the user field only. oauth_token lines are ignored.",
    "Process environment is checked for API key names only: ANTHROPIC_API_KEY, OPENAI_API_KEY, XAI_API_KEY, CURSOR_API_KEY.",
)

_EMAIL_RE = re.compile(
    r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9\-]+(?:\.[A-Za-z0-9\-]+)+"
)
_SECRET_KEY_RE = re.compile(
    r"(token|secret|password|cookie|credential|authorization|api[_-]?key|encrypted[_-]?key|private[_-]?key)",
    re.I,
)
_AUTH_NAME_RE = re.compile(r"(token|secret|key|password|auth)", re.I)
_SERVER_NAME_RE = re.compile(r"[A-Za-z0-9._:-]{1,60}")
_PLAN_RE = re.compile(r"[A-Za-z0-9_ .+-]{1,40}")
_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}")

ROW_FIELDS = (
    "tool",
    "signed_in",
    "account",
    "organization",
    "plan",
    "auth_method",
    "source",
    "last_sign_in",
)

ENV_KEYS = (
    ("ANTHROPIC_API_KEY", "claude-code"),
    ("OPENAI_API_KEY", "codex"),
    ("XAI_API_KEY", "grok"),
    ("CURSOR_API_KEY", "cursor"),
)

CURSOR_KEYS = (
    "cursorAuth/cachedEmail",
    "cursorAuth/stripeMembershipType",
    "cursorAuth/cachedSignUpType",
    "cursorAuth/stripeSubscriptionStatus",
)

MCP_REPO_FILES = (
    Path(".mcp.json"),
    Path(".cursor") / "mcp.json",
    Path(".claude") / "settings.local.json",
    Path(".claude") / "settings.json",
    Path(".grok") / "config.toml",
)

JSON_LIMIT = 32 * 1024 * 1024
SMALL_JSON_LIMIT = 2 * 1024 * 1024
TEXT_LIMIT = 256 * 1024
MCP_CAP = 40
WALK_NODE_CAP = 5000
WALK_DEPTH_CAP = 8

EMAIL_NORMS = {"email", "emailaddress", "useremail"}
ORG_NORMS = {
    "organization",
    "organizationname",
    "org",
    "orgname",
    "team",
    "teamname",
    "organizationlogin",
}
PLAN_NORMS = {
    "plan",
    "plantype",
    "tier",
    "membership",
    "membershiptype",
    "stripemembershiptype",
    "subscription",
    "sku",
    "billingtype",
    "chatgptplantype",
}
USER_NORMS = {
    "username",
    "login",
    "handle",
    "githublogin",
    "displayname",
    "preferredusername",
}
TIME_NORMS = {"lastrefresh", "lastlogin", "lastsignin", "signedinat", "loggedinat"}
API_KEY_NORMS = {"apikey", "openaiapikey", "primaryapikey"}


@dataclass
class Locations:
    home: Path
    appdata: Path
    claude_home: Path
    claude_json: Path
    codex_home: Path
    codex_auth: Path
    codex_config: Path
    cursor_db: Path
    cursor_mcp: list[Path]
    grok_home: Path
    grok_config: Path
    grok_auth: Path
    copilot_dirs: list[Path]
    grok_bot_root: Path
    gh_hosts: list[Path]
    gitconfigs: list[Path]
    extra_mcp: list[Path]
    repo_roots: list[Path]
    claude_desktop_config: Path


@dataclass
class Extracted:
    email: str = ""
    username: str = ""
    organization: str = ""
    plan: str = ""
    last_sign_in: str = ""
    secret_key_names: list[str] = field(default_factory=list)
    saw_id_token: bool = False

    def merge(self, other: Extracted) -> None:
        if not self.email and other.email:
            self.email = other.email
        if not self.username and other.username:
            self.username = other.username
        if not self.organization and other.organization:
            self.organization = other.organization
        if not self.plan and other.plan:
            self.plan = other.plan
        if not self.last_sign_in and other.last_sign_in:
            self.last_sign_in = other.last_sign_in
        self.saw_id_token = self.saw_id_token or other.saw_id_token
        for name in other.secret_key_names:
            if name not in self.secret_key_names:
                self.secret_key_names.append(name)


def norm_key(key: str) -> str:
    return re.sub(r"[^a-z0-9]", "", str(key).lower())


def clean_ident(value: Any, *, max_len: int = 120) -> str:
    """Keep a short identifier. Reject secrets, JWTs, and non-strings."""
    if not isinstance(value, str):
        return ""
    text = value.strip()
    if len(text) >= 2 and text[0] == text[-1] and text[0] in "\"'":
        text = text[1:-1].strip()
    if not text or len(text) > max_len:
        return ""
    if any(ch in text for ch in "\r\n\x00"):
        return ""
    if looks_like_secret(text):
        return ""
    lowered = text.lower()
    if lowered.startswith(("bearer ", "sk-", "xai-", "ghp_", "gho_", "github_pat_")):
        return ""
    if "://" in text:
        return ""
    if text.count(".") >= 2 and len(text) > 40:
        return ""
    return text


def clean_email(value: Any) -> str:
    text = clean_ident(value, max_len=120)
    if not text or _EMAIL_RE.fullmatch(text) is None:
        return ""
    return text


def clean_plan(value: Any) -> str:
    text = clean_ident(value, max_len=40)
    if not text or _PLAN_RE.fullmatch(text) is None:
        return ""
    return text


def clean_time(value: Any) -> str:
    if not isinstance(value, str):
        return ""
    text = value.strip()
    if not text or len(text) > 40 or _DATE_RE.match(text) is None:
        return ""
    if looks_like_secret(text):
        return ""
    return parse_iso(text)


def clean_key_name(name: str) -> str:
    if not isinstance(name, str):
        return ""
    text = name.strip()
    if not text or len(text) > 60 or looks_like_secret(text):
        return ""
    if not re.fullmatch(r"[A-Za-z0-9._:-]+", text):
        return ""
    return text


def nonempty(value: Any) -> bool:
    """True when a config value is set. The value itself is never returned."""
    if value is None or value is False:
        return False
    if isinstance(value, str):
        return bool(value.strip())
    if isinstance(value, (int, float)):
        return True
    if isinstance(value, (dict, list)):
        return bool(value)
    return False


def mask_identifiers(text: str) -> str:
    """Mask emails when -Redact is on. Always strip secret-shaped strings."""
    if not text:
        return ""
    if redaction_disabled():
        return mask_secrets(text)
    masked = _EMAIL_RE.sub("<email>", text)
    return mask_secrets(redact_paths(masked))


def blank_row(**kwargs: str) -> dict[str, str]:
    row = {key: "" for key in ROW_FIELDS}
    row["signed_in"] = "unknown"
    row.update(kwargs)
    return row


def display_source(path: Path, home: Path, appdata: Path) -> str:
    """Home-relative source label. Never an absolute path with a username."""
    text = str(path).replace("\\", "/").rstrip("/")
    low = text.lower()
    for root, prefix in ((appdata, "%APPDATA%/"), (home, "~/")):
        root_s = str(root).replace("\\", "/").rstrip("/")
        root_low = root_s.lower()
        if root_low and (low == root_low or low.startswith(root_low + "/")):
            rest = text[len(root_s):].lstrip("/")
            return prefix + rest if rest else prefix.rstrip("/")
    return Path(text).name


def publish_row(row: dict[str, str], home: Path, appdata: Path) -> dict[str, str]:
    out = blank_row()
    for key in ROW_FIELDS:
        out[key] = str(row.get(key) or "")
    if out["source"] and not out["source"].startswith("env:"):
        source_path = Path(out["source"])
        # Already-relative labels (written by readers) pass through.
        if out["source"].startswith(("~/", "%APPDATA%/", "env:")) or not source_path.is_absolute():
            pass
        else:
            out["source"] = display_source(source_path, home, appdata)
    for key in ("account", "organization", "plan", "source", "last_sign_in", "auth_method"):
        out[key] = mask_identifiers(out[key])
    return out


def read_text_limited(path: Path, limit: int) -> str | None:
    try:
        if not path.is_file() or path.stat().st_size > limit:
            return None
        return path.read_text(encoding="utf-8")
    except OSError:
        return None


def load_json_file(path: Path, limit: int = JSON_LIMIT) -> dict | None:
    text = read_text_limited(path, limit)
    if text is None:
        return None
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return None
    return data if isinstance(data, dict) else None


def load_toml_file(path: Path, limit: int = SMALL_JSON_LIMIT) -> dict | None:
    try:
        if not path.is_file() or path.stat().st_size > limit:
            return None
        with path.open("rb") as handle:
            data = tomllib.load(handle)
    except (OSError, tomllib.TOMLDecodeError):
        return None
    return data if isinstance(data, dict) else None


def jwt_claims(token: str) -> dict[str, Any]:
    """Decode a JWT payload. The token string is not retained."""
    if not isinstance(token, str) or token.count(".") != 2:
        return {}
    segment = token.split(".", 2)[1]
    if not segment or len(segment) > 20000:
        return {}
    pad = "=" * (-len(segment) % 4)
    try:
        raw = base64.urlsafe_b64decode(segment + pad)
        if len(raw) > 100_000:
            return {}
        data = json.loads(raw.decode("utf-8"))
    except Exception:
        return {}
    return data if isinstance(data, dict) else {}


def identity_from_claims(claims: dict[str, Any]) -> dict[str, str]:
    """Allowlisted Codex id_token claims. Account ids and the token are dropped."""
    found = {"account": "", "organization": "", "plan": ""}
    if not isinstance(claims, dict):
        return found
    email = clean_email(claims.get("email"))
    profile = claims.get("https://api.openai.com/profile")
    if not email and isinstance(profile, dict):
        email = clean_email(profile.get("email"))
    auth = claims.get("https://api.openai.com/auth")
    plan = ""
    org = ""
    if isinstance(auth, dict):
        plan = clean_plan(auth.get("chatgpt_plan_type") or auth.get("plan_type"))
        org = clean_ident(auth.get("organization_name") or auth.get("org_name") or "")
    if not plan:
        plan = clean_plan(claims.get("chatgpt_plan_type"))
    account = email
    if not account:
        preferred = clean_ident(claims.get("preferred_username"))
        if preferred and "@" not in preferred:
            account = preferred
        elif preferred:
            account = clean_email(preferred)
    found["account"] = account
    found["plan"] = plan
    found["organization"] = org
    return found


def _note_secret(acc: Extracted, key: str) -> None:
    name = str(key)[:60]
    if name and name not in acc.secret_key_names:
        acc.secret_key_names.append(name)


def walk_identity(node: Any, acc: Extracted, state: dict[str, int]) -> None:
    """Copy allowlisted identifier fields. Secret-named values are not stored."""
    if state["nodes"] >= WALK_NODE_CAP or state["depth"] > WALK_DEPTH_CAP:
        return
    state["nodes"] += 1
    if isinstance(node, dict):
        for key, val in list(node.items())[:80]:
            if not isinstance(key, str):
                continue
            if isinstance(key, str) and acc.email == "" and _EMAIL_RE.fullmatch(key):
                email = clean_email(key)
                if email:
                    acc.email = email
            norm = norm_key(key)
            if norm == "idtoken" and isinstance(val, str):
                acc.saw_id_token = True
                _note_secret(acc, key)
                claims = jwt_claims(val)
                state["depth"] += 1
                walk_identity(claims, acc, state)
                state["depth"] -= 1
                continue
            if _SECRET_KEY_RE.search(key):
                if nonempty(val):
                    _note_secret(acc, key)
                continue
            if norm in EMAIL_NORMS and isinstance(val, str) and not acc.email:
                acc.email = clean_email(val)
            elif norm in USER_NORMS and isinstance(val, str):
                if "@" in val and not acc.email:
                    acc.email = clean_email(val)
                elif not acc.username:
                    acc.username = clean_ident(val, max_len=80)
            elif norm in ORG_NORMS and isinstance(val, str) and not acc.organization:
                acc.organization = clean_ident(val, max_len=80)
            elif norm in PLAN_NORMS and not acc.plan:
                acc.plan = clean_plan(val)
            elif norm in TIME_NORMS and isinstance(val, str) and not acc.last_sign_in:
                acc.last_sign_in = clean_time(val)
            elif isinstance(val, (dict, list)):
                state["depth"] += 1
                walk_identity(val, acc, state)
                state["depth"] -= 1
    elif isinstance(node, list):
        for item in node[:40]:
            state["depth"] += 1
            walk_identity(item, acc, state)
            state["depth"] -= 1


def extract_tree(data: Any) -> Extracted:
    acc = Extracted()
    walk_identity(data, acc, {"nodes": 0, "depth": 0})
    return acc


def auth_signals(acc: Extracted) -> set[str]:
    found: set[str] = set()
    if acc.saw_id_token:
        found.add("oauth")
    for name in acc.secret_key_names:
        norm = norm_key(name)
        if norm in API_KEY_NORMS or "apikey" in norm:
            found.add("api_key")
        elif "token" in norm:
            found.add("oauth")
    return found


def account_label(acc: Extracted) -> str:
    return acc.email or acc.username


def decode_state_value(raw: Any) -> str:
    if isinstance(raw, bytes):
        raw = raw.decode("utf-8", errors="replace")
    if not isinstance(raw, str):
        return ""
    text = raw.strip()
    if len(text) >= 2 and text[0] == '"' and text[-1] == '"':
        try:
            loaded = json.loads(text)
        except json.JSONDecodeError:
            return text
        if isinstance(loaded, str):
            return loaded
    return text


def read_cursor_auth(db_path: Path) -> tuple[str, dict[str, str]]:
    """Copy state.vscdb and query four keys.

    Status is ``missing``, ``unreadable``, or ``ok``. The original database
    is never opened. ``ok`` with an empty dict means those keys are absent.
    """
    try:
        if not db_path.is_file():
            return "missing", {}
    except OSError:
        return "unreadable", {}
    try:
        with tempfile.TemporaryDirectory(prefix="aiscan-cursor-") as tmp:
            dest = Path(tmp) / "state.vscdb"
            shutil.copyfile(db_path, dest)
            uri = dest.resolve().as_uri() + "?mode=ro&immutable=1"
            con = sqlite3.connect(uri, uri=True)
            try:
                found: dict[str, str] = {}
                for key in CURSOR_KEYS:
                    try:
                        row = con.execute(
                            "SELECT value FROM ItemTable WHERE key = ?",
                            (key,),
                        ).fetchone()
                    except sqlite3.Error:
                        return "unreadable", {}
                    if row and row[0] is not None:
                        found[key] = decode_state_value(row[0])
                return "ok", found
            finally:
                con.close()
    except (OSError, sqlite3.Error):
        return "unreadable", {}


def cursor_rows(locs: Locations) -> list[dict[str, str]]:
    source = display_source(locs.cursor_db, locs.home, locs.appdata)
    status, values = read_cursor_auth(locs.cursor_db)
    if status == "missing":
        return [blank_row(tool="cursor", signed_in="unknown", auth_method="not_present", source=source)]
    if status == "unreadable":
        return [blank_row(tool="cursor", signed_in="unknown", auth_method="unreadable", source=source)]
    email = clean_email(values.get("cursorAuth/cachedEmail", ""))
    plan = clean_plan(values.get("cursorAuth/stripeMembershipType", ""))
    signup = clean_ident(values.get("cursorAuth/cachedSignUpType", ""), max_len=40)
    # Status is a signed-in signal only. It is not an account identifier.
    subscription = clean_ident(values.get("cursorAuth/stripeSubscriptionStatus", ""), max_len=40)
    if email or plan or signup or subscription:
        return [
            blank_row(
                tool="cursor",
                signed_in="yes",
                account=email,
                plan=plan,
                auth_method="oauth",
                source=source,
            )
        ]
    return [blank_row(tool="cursor", signed_in="unknown", auth_method="unknown", source=source)]


def claude_rows(locs: Locations) -> list[dict[str, str]]:
    source = display_source(locs.claude_json, locs.home, locs.appdata)
    cred = locs.claude_home / ".credentials.json"
    home_exists = locs.claude_home.is_dir()
    json_exists = locs.claude_json.is_file()
    try:
        cred_exists = cred.is_file()
    except OSError:
        cred_exists = False
    rows: list[dict[str, str]] = []
    if not json_exists and not home_exists and not cred_exists:
        rows.append(blank_row(tool="claude-code", signed_in="unknown", auth_method="not_present", source=source))
        return rows

    email = ""
    org = ""
    plan = ""
    api_key_in_file = False
    data = load_json_file(locs.claude_json) if json_exists else None
    if isinstance(data, dict):
        account = data.get("oauthAccount")
        if isinstance(account, dict):
            email = clean_email(account.get("emailAddress") or account.get("email"))
            org = clean_ident(account.get("organizationName"), max_len=80)
            plan = clean_plan(account.get("billingType") or account.get("planType") or account.get("plan"))
            if not email:
                display = clean_ident(account.get("displayName"), max_len=80)
                if display and "@" not in display:
                    email = ""
                    # Kept only when no email exists; stored in account below.
                    org = org
                    username = display
                else:
                    username = ""
            else:
                username = ""
        else:
            username = ""
        primary = data.get("primaryApiKey")
        api_key_in_file = nonempty(primary)
    else:
        username = ""

    account_value = email or username
    if account_value or cred_exists:
        rows.append(
            blank_row(
                tool="claude-code",
                signed_in="yes",
                account=account_value,
                organization=org,
                plan=plan,
                auth_method="oauth",
                source=source if account_value else display_source(cred, locs.home, locs.appdata),
            )
        )
    else:
        rows.append(
            blank_row(
                tool="claude-code",
                signed_in="unknown",
                auth_method="unknown",
                source=source if json_exists else display_source(locs.claude_home, locs.home, locs.appdata),
            )
        )
    if api_key_in_file:
        rows.append(
            blank_row(
                tool="claude-code",
                signed_in="unknown",
                auth_method="api_key",
                source=source,
            )
        )
    settings = load_json_file(locs.claude_home / "settings.json", limit=SMALL_JSON_LIMIT)
    if isinstance(settings, dict):
        env = settings.get("env")
        if isinstance(env, dict):
            for key, val in env.items():
                if not isinstance(key, str) or not _AUTH_NAME_RE.search(key) or not nonempty(val):
                    continue
                safe = clean_key_name(key)
                rows.append(
                    blank_row(
                        tool="claude-code",
                        signed_in="unknown",
                        auth_method="api_key",
                        source=display_source(locs.claude_home / "settings.json", locs.home, locs.appdata)
                        + (f"#env:{safe}" if safe else "#env"),
                    )
                )
    return rows


def codex_rows(locs: Locations) -> list[dict[str, str]]:
    source = display_source(locs.codex_auth, locs.home, locs.appdata)
    if not locs.codex_auth.is_file() and not locs.codex_home.is_dir():
        return [blank_row(tool="codex", signed_in="unknown", auth_method="not_present", source=source)]
    data = load_json_file(locs.codex_auth, limit=SMALL_JSON_LIMIT) if locs.codex_auth.is_file() else None
    if locs.codex_auth.is_file() and data is None:
        return [blank_row(tool="codex", signed_in="unknown", auth_method="unreadable", source=source)]
    if not isinstance(data, dict):
        return [blank_row(tool="codex", signed_in="unknown", auth_method="unknown", source=display_source(locs.codex_home, locs.home, locs.appdata))]

    rows: list[dict[str, str]] = []
    tokens = data.get("tokens") if isinstance(data.get("tokens"), dict) else {}
    id_token = tokens.get("id_token") if isinstance(tokens, dict) else None
    if not isinstance(id_token, str):
        id_token = data.get("id_token") if isinstance(data.get("id_token"), str) else ""
    access_present = nonempty(tokens.get("access_token")) if isinstance(tokens, dict) else False
    refresh_present = nonempty(tokens.get("refresh_token")) if isinstance(tokens, dict) else False
    ident = identity_from_claims(jwt_claims(id_token)) if isinstance(id_token, str) and id_token else {
        "account": "",
        "organization": "",
        "plan": "",
    }
    mode = data.get("auth_mode")
    mode_s = mode.strip().lower() if isinstance(mode, str) else ""
    last = clean_time(data.get("last_refresh"))
    oauthish = bool(ident["account"]) or bool(id_token) or access_present or refresh_present or mode_s == "chatgpt"
    if oauthish:
        rows.append(
            blank_row(
                tool="codex",
                signed_in="yes",
                account=ident["account"],
                organization=ident["organization"],
                plan=ident["plan"],
                auth_method="oauth",
                source=source,
                last_sign_in=last,
            )
        )
    api_present = nonempty(data.get("OPENAI_API_KEY")) or mode_s in {"apikey", "api_key", "api-key"}
    if api_present and (nonempty(data.get("OPENAI_API_KEY")) or mode_s in {"apikey", "api_key", "api-key"}):
        # auth_mode apikey with a null key still means the file is in api-key mode
        # only when a key value is actually present, or mode says so AND a key exists.
        if nonempty(data.get("OPENAI_API_KEY")):
            rows.append(
                blank_row(
                    tool="codex",
                    signed_in="unknown",
                    auth_method="api_key",
                    source=source,
                )
            )
    if not rows:
        rows.append(blank_row(tool="codex", signed_in="unknown", auth_method="unknown", source=source))
    return rows


def _grok_identity_files(locs: Locations) -> list[Path]:
    names = ("auth.json", "user-settings.json", "user_settings.json", "user-settings.toml")
    files = [locs.grok_auth]
    for name in names:
        candidate = locs.grok_home / name
        if candidate not in files:
            files.append(candidate)
    # de-dupe while keeping order
    seen: set[str] = set()
    ordered: list[Path] = []
    for path in files:
        key = str(path)
        if key in seen:
            continue
        seen.add(key)
        ordered.append(path)
    return ordered


def grok_rows(locs: Locations) -> list[dict[str, str]]:
    source_home = display_source(locs.grok_home, locs.home, locs.appdata)
    files = _grok_identity_files(locs)
    present = [path for path in files if path.is_file()]
    if not present and not locs.grok_home.is_dir():
        return [blank_row(tool="grok", signed_in="unknown", auth_method="not_present", source=source_home)]
    combined = Extracted()
    identity_source = ""
    any_parsed = False
    for path in present:
        if path.suffix.lower() == ".toml":
            data = load_toml_file(path)
        else:
            data = load_json_file(path, limit=SMALL_JSON_LIMIT)
        if not isinstance(data, dict):
            continue
        any_parsed = True
        extracted = extract_tree(data)
        if account_label(extracted) and not identity_source:
            identity_source = display_source(path, locs.home, locs.appdata)
        combined.merge(extracted)
    if present and not any_parsed:
        return [blank_row(tool="grok", signed_in="unknown", auth_method="unreadable", source=display_source(present[0], locs.home, locs.appdata))]
    if not present:
        return [blank_row(tool="grok", signed_in="unknown", auth_method="unknown", source=source_home)]

    signals = auth_signals(combined)
    label = account_label(combined)
    source = identity_source or display_source(present[0], locs.home, locs.appdata)
    rows: list[dict[str, str]] = []
    if label or "oauth" in signals:
        method = "oauth" if "oauth" in signals else "config"
        rows.append(
            blank_row(
                tool="grok",
                signed_in="yes",
                account=label,
                organization=combined.organization,
                plan=combined.plan,
                auth_method=method,
                source=source,
                last_sign_in=combined.last_sign_in,
            )
        )
    elif combined.plan or combined.organization:
        rows.append(
            blank_row(
                tool="grok",
                signed_in="unknown",
                organization=combined.organization,
                plan=combined.plan,
                auth_method="config",
                source=source,
                last_sign_in=combined.last_sign_in,
            )
        )
    if "api_key" in signals:
        rows.append(
            blank_row(
                tool="grok",
                signed_in="unknown",
                auth_method="api_key",
                source=source,
            )
        )
    if not rows:
        rows.append(blank_row(tool="grok", signed_in="unknown", auth_method="unknown", source=source))
    return rows


def grok_bot_rows(locs: Locations) -> list[dict[str, str]]:
    root = locs.grok_bot_root
    source = display_source(root, locs.home, locs.appdata)
    try:
        exists = root.is_dir()
    except OSError:
        exists = False
    if not exists:
        return [blank_row(tool="grok-bot", signed_in="unknown", auth_method="not_present", source=source)]
    # Plain JSON only. Cookies, storage, Network, and secrets files stay closed.
    candidates = (
        root / "desktop-status.json",
        root / "Preferences",
        root / "Local State",
    )
    combined = Extracted()
    identity_source = ""
    for path in candidates:
        data = load_json_file(path, limit=JSON_LIMIT)
        if not isinstance(data, dict):
            continue
        extracted = extract_tree(data)
        if account_label(extracted) and not identity_source:
            identity_source = display_source(path, locs.home, locs.appdata)
        combined.merge(extracted)
    label = account_label(combined)
    if not label and not combined.plan:
        return [blank_row(tool="grok-bot", signed_in="unknown", auth_method="unknown", source=source)]
    return [
        blank_row(
            tool="grok-bot",
            signed_in="yes" if label else "unknown",
            account=label,
            organization=combined.organization,
            plan=combined.plan,
            auth_method="oauth" if label else "unknown",
            source=identity_source or source,
        )
    ]


def copilot_rows(locs: Locations) -> list[dict[str, str]]:
    dirs = [path for path in locs.copilot_dirs if path.is_dir()]
    fallback = locs.copilot_dirs[0] if locs.copilot_dirs else locs.appdata / "Code"
    source = display_source(fallback, locs.home, locs.appdata)
    if not dirs:
        return [blank_row(tool="copilot", signed_in="unknown", auth_method="not_present", source=source)]
    combined = Extracted()
    identity_source = ""
    token_file = False
    for directory in dirs:
        try:
            children = list(directory.iterdir())
        except OSError:
            continue
        for child in children:
            try:
                if not child.is_file():
                    continue
            except OSError:
                continue
            name_low = child.name.lower()
            if "token" in name_low or "secret" in name_low or "cookie" in name_low:
                token_file = True
                continue
            if child.suffix.lower() == ".json" or child.name in {"copilot-user", "user"}:
                if child.suffix.lower() == ".json":
                    data = load_json_file(child, limit=SMALL_JSON_LIMIT)
                    if isinstance(data, dict):
                        extracted = extract_tree(data)
                        if account_label(extracted) and not identity_source:
                            identity_source = display_source(child, locs.home, locs.appdata)
                        combined.merge(extracted)
                else:
                    text = read_text_limited(child, 200)
                    if text:
                        ident = clean_email(text.strip()) or clean_ident(text.strip(), max_len=80)
                        if ident and not combined.email and not combined.username:
                            if "@" in ident:
                                combined.email = clean_email(ident)
                            else:
                                combined.username = ident
                            identity_source = display_source(child, locs.home, locs.appdata)
    label = account_label(combined)
    if label or token_file:
        return [
            blank_row(
                tool="copilot",
                signed_in="yes",
                account=label,
                organization=combined.organization,
                plan=combined.plan,
                auth_method="oauth",
                source=identity_source or source,
            )
        ]
    return [
        blank_row(
            tool="copilot",
            signed_in="unknown",
            organization=combined.organization,
            plan=combined.plan,
            auth_method="unknown" if (combined.plan or combined.organization) else "unknown",
            source=source,
        )
    ]


def parse_gitconfig(text: str) -> dict[str, str]:
    section = ""
    email = ""
    name = ""
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or stripped.startswith(";"):
            continue
        if stripped.startswith("[") and stripped.endswith("]"):
            section = stripped[1:-1].strip().lower().split(" ", 1)[0]
            continue
        if section != "user" or "=" not in stripped:
            continue
        key, _, val = stripped.partition("=")
        key = key.strip().lower()
        val = val.strip().strip('"').strip("'")
        if key == "email":
            email = val
        elif key == "name":
            name = val
    return {"email": email, "name": name}


def git_rows(locs: Locations) -> list[dict[str, str]]:
    source = display_source(locs.home / ".gitconfig", locs.home, locs.appdata)
    for path in locs.gitconfigs:
        text = read_text_limited(path, TEXT_LIMIT)
        if text is None:
            continue
        parsed = parse_gitconfig(text)
        email = clean_email(parsed.get("email", ""))
        name = clean_ident(parsed.get("name", ""), max_len=80)
        if not email and not name:
            continue
        return [
            blank_row(
                tool="git",
                signed_in="yes",
                account=email or name,
                auth_method="git_config",
                source=display_source(path, locs.home, locs.appdata),
            )
        ]
    if any(path.is_file() for path in locs.gitconfigs):
        return [blank_row(tool="git", signed_in="no", auth_method="git_config", source=source)]
    return [blank_row(tool="git", signed_in="unknown", auth_method="not_present", source=source)]


def parse_hosts_users(text: str) -> list[tuple[str, str]]:
    """Return (host, user). oauth_token and every other key are ignored."""
    host = ""
    found: list[tuple[str, str]] = []
    for line in text.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if line[0] not in " \t":
            raw = line.strip()
            host = raw[:-1].strip() if raw.endswith(":") else ""
            continue
        stripped = line.strip()
        if stripped.lower().startswith("user:"):
            user = stripped.split(":", 1)[1].strip().strip('"').strip("'")
            if host and user:
                found.append((host, user))
    return found


def gh_rows(locs: Locations) -> list[dict[str, str]]:
    fallback = locs.gh_hosts[0] if locs.gh_hosts else locs.home / ".config" / "gh" / "hosts.yml"
    source = display_source(fallback, locs.home, locs.appdata)
    for path in locs.gh_hosts:
        text = read_text_limited(path, TEXT_LIMIT)
        if text is None:
            continue
        users = parse_hosts_users(text)
        rows: list[dict[str, str]] = []
        for host, user in users:
            account = clean_ident(user, max_len=80)
            host_label = clean_ident(host, max_len=80)
            if not account:
                continue
            rows.append(
                blank_row(
                    tool="gh",
                    signed_in="yes",
                    account=account,
                    organization=host_label,
                    auth_method="oauth",
                    source=display_source(path, locs.home, locs.appdata),
                )
            )
        if rows:
            return rows
        return [blank_row(tool="gh", signed_in="unknown", auth_method="unknown", source=display_source(path, locs.home, locs.appdata))]
    return [blank_row(tool="gh", signed_in="unknown", auth_method="not_present", source=source)]


def servers_from_mapping(data: dict) -> list[tuple[str, dict]]:
    found: list[tuple[str, dict]] = []
    for key in ("mcpServers", "mcp_servers"):
        block = data.get(key)
        if not isinstance(block, dict):
            continue
        for name, cfg in block.items():
            if isinstance(name, str) and isinstance(cfg, dict):
                found.append((name, cfg))
    return found


def mcp_methods(cfg: dict) -> list[str]:
    methods: list[str] = []
    env = cfg.get("env")
    if isinstance(env, dict):
        for key, val in env.items():
            if not isinstance(key, str) or not _AUTH_NAME_RE.search(key) or not nonempty(val):
                continue
            safe = clean_key_name(key)
            methods.append(f"env:{safe}" if safe else "env:present")
    headers = cfg.get("headers")
    if isinstance(headers, dict):
        for key, val in headers.items():
            if not isinstance(key, str) or not _AUTH_NAME_RE.search(key) or not nonempty(val):
                continue
            safe = clean_key_name(key)
            methods.append(f"header:{safe}" if safe else "header:present")
    args = cfg.get("args")
    if isinstance(args, list):
        for item in args:
            if isinstance(item, str) and re.search(r"(?i)authorization|bearer", item):
                methods.append("args:authorization")
                break
    for url_key in ("url", "serverUrl", "server_url"):
        url = cfg.get(url_key)
        if not isinstance(url, str) or "://" not in url:
            continue
        hostpart = url.split("://", 1)[1].split("/", 1)[0]
        if "@" in hostpart:
            methods.append("url_userinfo")
            break
    # Stable, unique.
    ordered: list[str] = []
    for method in methods:
        if method not in ordered:
            ordered.append(method)
    return ordered


def clean_server_name(name: str) -> str:
    text = clean_ident(name, max_len=60)
    if not text or _SERVER_NAME_RE.fullmatch(text) is None:
        return "server"
    return text


def _load_mcp_doc(path: Path) -> dict | None:
    if path.suffix.lower() == ".toml":
        return load_toml_file(path)
    return load_json_file(path, limit=SMALL_JSON_LIMIT)


def mcp_rows(locs: Locations) -> list[dict[str, str]]:
    candidates: list[Path] = []
    candidates.extend(locs.cursor_mcp)
    candidates.extend(locs.extra_mcp)
    candidates.append(locs.home / ".mcp.json")
    candidates.append(locs.claude_json)
    candidates.append(locs.claude_home / "settings.json")
    candidates.append(locs.claude_home / ".mcp.json")
    candidates.append(locs.claude_desktop_config)
    candidates.append(locs.codex_config)
    candidates.append(locs.grok_config)
    for root in locs.repo_roots[:30]:
        for rel in MCP_REPO_FILES:
            candidates.append(root / rel)

    seen: set[str] = set()
    rows: list[dict[str, str]] = []
    for path in candidates:
        if len(rows) >= MCP_CAP:
            break
        try:
            key = str(path.resolve()) if path.exists() else str(path)
        except OSError:
            key = str(path)
        if key in seen:
            continue
        seen.add(key)
        if not path.is_file():
            continue
        data = _load_mcp_doc(path)
        if not isinstance(data, dict):
            continue
        for name, cfg in servers_from_mapping(data):
            if len(rows) >= MCP_CAP:
                break
            methods = mcp_methods(cfg)
            if not methods:
                continue
            rows.append(
                blank_row(
                    tool=f"mcp:{clean_server_name(name)}",
                    signed_in="unknown",
                    auth_method=", ".join(methods),
                    source=display_source(path, locs.home, locs.appdata),
                )
            )
    return rows


def env_rows(env: Mapping[str, str]) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for name, tool in ENV_KEYS:
        value = env.get(name)
        if isinstance(value, str) and value.strip():
            rows.append(
                blank_row(
                    tool=tool,
                    signed_in="unknown",
                    auth_method="api_key",
                    source=f"env:{name}",
                )
            )
    return rows


def is_api_key_method(method: str) -> bool:
    low = method.lower()
    return (
        low == "api_key"
        or "api_key" in low
        or low.startswith("env:")
        or "env:" in low
        or low.startswith("header:")
        or "header:" in low
        or "url_userinfo" in low
        or "args:authorization" in low
    )


def is_subscription_method(method: str) -> bool:
    return method.lower().startswith("oauth")


def distinct_account_keys(rows: list[dict[str, str]]) -> list[str]:
    seen: list[str] = []
    for item in rows:
        if str(item.get("tool") or "").startswith("mcp:"):
            continue
        key = str(item.get("account") or "").strip().lower()
        if key and key not in seen:
            seen.append(key)
    return seen


def build_findings(rows: list[dict[str, str]]) -> list[dict]:
    findings: list[dict] = []
    distinct = distinct_account_keys(rows)
    if len(distinct) >= 2:
        parts: list[str] = []
        seen_bits: set[str] = set()
        for item in rows:
            account = str(item.get("account") or "")
            if not account or str(item.get("tool") or "").startswith("mcp:"):
                continue
            bit = f"{item.get('tool')}={account}"
            if bit in seen_bits:
                continue
            seen_bits.add(bit)
            parts.append(bit)
        sample = "; ".join(parts[:12])
        findings.append(
            make_finding(
                "accounts.identity.multiple",
                "medium",
                "Identity & SSO",
                "Agent tools are signed in as more than one account",
                evidence_count=len(distinct),
                sample_redacted=mask_identifiers(f"{sample}; distinct={len(distinct)}"),
                tags=["identity"],
            )
        )

    api_tools: list[str] = []
    sub_tools: list[str] = []
    for item in rows:
        tool = str(item.get("tool") or "")
        method = str(item.get("auth_method") or "")
        if is_api_key_method(method) and tool not in api_tools:
            api_tools.append(tool)
        if is_subscription_method(method) and tool not in sub_tools:
            sub_tools.append(tool)
    if api_tools and sub_tools:
        same = sorted(set(api_tools) & set(sub_tools))
        severity = "medium" if same else "low"
        sample = "subscription: " + ", ".join(sub_tools[:8]) + "; api_key: " + ", ".join(api_tools[:8])
        findings.append(
            make_finding(
                "accounts.auth.api_key_and_subscription",
                severity,
                "Identity & SSO",
                "API-key auth and subscription auth are both in use",
                evidence_count=len(api_tools) + len(sub_tools),
                sample_redacted=mask_identifiers(sample),
                tags=["api_key", "subscription"],
            )
        )
    return findings


def _safe_rows(tool: str, fn) -> list[dict[str, str]]:
    """One bad file must not abort the scan or echo file contents."""
    try:
        return fn()
    except Exception:
        return [blank_row(tool=tool, signed_in="unknown", auth_method="unreadable")]


def collect(locs: Locations, environ: Mapping[str, str] | None = None) -> dict[str, Any]:
    env: Mapping[str, str] = os.environ if environ is None else environ
    scope_paths = [
        locs.claude_json,
        locs.claude_home,
        locs.codex_auth,
        locs.codex_home,
        locs.codex_config,
        locs.cursor_db,
        locs.grok_home,
        locs.grok_auth,
        locs.grok_config,
        locs.grok_bot_root,
        locs.claude_desktop_config,
        *locs.copilot_dirs,
        *locs.gh_hosts,
        *locs.gitconfigs,
        *locs.cursor_mcp,
        *locs.extra_mcp,
        *locs.repo_roots,
    ]
    envelope = make_envelope(
        COLLECTOR,
        __version__,
        compute_scope_hash(str(path) for path in scope_paths),
        platform_detected=False,
    )
    raw_rows: list[dict[str, str]] = []
    raw_rows.extend(_safe_rows("claude-code", lambda: claude_rows(locs)))
    raw_rows.extend(_safe_rows("codex", lambda: codex_rows(locs)))
    raw_rows.extend(_safe_rows("cursor", lambda: cursor_rows(locs)))
    raw_rows.extend(_safe_rows("copilot", lambda: copilot_rows(locs)))
    raw_rows.extend(_safe_rows("grok", lambda: grok_rows(locs)))
    raw_rows.extend(_safe_rows("grok-bot", lambda: grok_bot_rows(locs)))
    raw_rows.extend(_safe_rows("gh", lambda: gh_rows(locs)))
    raw_rows.extend(_safe_rows("git", lambda: git_rows(locs)))
    raw_rows.extend(_safe_rows("mcp", lambda: mcp_rows(locs)))
    raw_rows.extend(_safe_rows("env", lambda: env_rows(env)))

    distinct = distinct_account_keys(raw_rows)
    published = [publish_row(item, locs.home, locs.appdata) for item in raw_rows]
    # Samples pass through mask_identifiers, so -Redact masks emails without
    # collapsing the distinct count (that count is taken from the raw rows).
    findings = build_findings(raw_rows)

    signed_in = sum(1 for item in published if item["signed_in"] == "yes")
    unknown = sum(1 for item in published if item["signed_in"] == "unknown")
    not_signed = sum(1 for item in published if item["signed_in"] == "no")
    api_key_rows = sum(1 for item in raw_rows if is_api_key_method(item.get("auth_method", "")))
    subscription_rows = sum(1 for item in raw_rows if is_subscription_method(item.get("auth_method", "")))
    detected = any(
        item.get("auth_method") not in {"not_present", ""}
        or item.get("signed_in") == "yes"
        for item in raw_rows
    )
    envelope["platform_detected"] = detected
    envelope["accounts"] = published
    envelope["findings"] = findings
    envelope["limits"] = list(LIMITS)
    envelope["summary"] = {
        "tools_reported": len(published),
        "signed_in": signed_in,
        "unknown": unknown,
        "not_signed_in": not_signed,
        "distinct_accounts": len(distinct),
        "api_key_rows": api_key_rows,
        "subscription_rows": subscription_rows,
        "findings": len(findings),
    }
    return envelope


def locations_from_runtime(tp: paths.ToolPaths, repo_roots: list[Path], env: Mapping[str, str]) -> Locations:
    home = Path(env.get("USERPROFILE") or env.get("HOME") or str(Path.home()))
    appdata = Path(env.get("APPDATA") or (home / "AppData" / "Roaming"))
    gh_hosts: list[Path] = []
    gh_config = env.get("GH_CONFIG_DIR")
    if gh_config:
        gh_hosts.append(Path(gh_config) / "hosts.yml")
    gh_hosts.append(appdata / "GitHub CLI" / "hosts.yml")
    gh_hosts.append(home / ".config" / "gh" / "hosts.yml")
    gitconfigs: list[Path] = []
    git_global = env.get("GIT_CONFIG_GLOBAL")
    if git_global:
        gitconfigs.append(Path(git_global))
    gitconfigs.append(home / ".gitconfig")
    gitconfigs.append(home / ".config" / "git" / "config")
    return Locations(
        home=home,
        appdata=appdata,
        claude_home=tp.claude_home,
        claude_json=home / ".claude.json",
        codex_home=tp.codex_home,
        codex_auth=tp.codex_auth,
        codex_config=tp.codex_config,
        cursor_db=tp.cursor_db,
        cursor_mcp=[tp.cursor_user_mcp, tp.cursor_appdata_mcp],
        grok_home=tp.grok_home,
        grok_config=tp.grok_config,
        grok_auth=tp.grok_auth,
        copilot_dirs=[
            appdata / "Code" / "User" / "globalStorage" / "github.copilot",
            appdata / "Code" / "User" / "globalStorage" / "github.copilot-chat",
        ],
        grok_bot_root=appdata / "Grok Bot",
        gh_hosts=gh_hosts,
        gitconfigs=gitconfigs,
        extra_mcp=[tp.shared_mcp],
        repo_roots=repo_roots,
        claude_desktop_config=appdata / "Claude" / "claude_desktop_config.json",
    )


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Signed-in account inventory")
    add_base_args(parser)
    paths.add_path_args(parser)
    parser.add_argument(
        "--repo-roots",
        default=None,
        help="Comma-separated repo roots for project MCP configs "
        "(default: common code dirs under the user profile)",
    )
    args = parser.parse_args(argv)
    evidence_root = validate_evidence_root(args.evidence_root)
    tp = paths.resolve_from_args(args)
    if args.repo_roots:
        repo_roots = [Path(part.strip()) for part in args.repo_roots.split(",") if part.strip()]
    else:
        repo_roots = default_repo_roots()
    envelope = collect(locations_from_runtime(tp, repo_roots, os.environ))
    finish_collector(envelope, evidence_root, dry_run=args.dry_run)
    sys.exit(0 if envelope["platform_detected"] else 2)


if __name__ == "__main__":
    main()
