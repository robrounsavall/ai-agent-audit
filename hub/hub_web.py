"""HTTP server for the hub: dashboard pages, JSON API, and scan ingest.

Standard library only (``http.server``). Defaults are for one person on one
machine: it binds to 127.0.0.1 and nothing is readable without the access
token. What it defends against:

- another local user or process reading the dashboard: every page and API
  read needs the access token (a cookie after sign-in, or a bearer header)
- a web page in your browser calling the hub (DNS rebinding, cross-site
  requests): the ``Host`` header must be a name this hub was started with,
  form posts need a CSRF token and a same-origin ``Origin``, and no CORS
  header is ever sent
- scan text reaching the page as markup: pages escape every value and the
  Content-Security-Policy allows no inline script or style
- oversized or malformed uploads: bodies are size-capped and every bundle
  goes through ``hub_bundle.normalize_bundle`` before the database

Ingest tokens can only add scans. They cannot read anything.
"""

from __future__ import annotations

import hmac
import json
import socket
import sys
import threading
import time
from dataclasses import dataclass, field
from http import HTTPStatus
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlsplit

import hub_paths

import hub_db
import hub_pages as pages
import hub_queries as q
from hub_bundle import BundleError, normalize_bundle

MAX_BUNDLE_BYTES = 32 * 1024 * 1024
MAX_FORM_BYTES = 64 * 1024
COOKIE_NAME = "aiscan_hub"
COOKIE_MAX_AGE = 30 * 24 * 3600
LOOPBACK_NAMES = frozenset({"127.0.0.1", "localhost", "::1"})
_STATIC = {
    "hub.css": "text/css; charset=utf-8",
    "hub.js": "text/javascript; charset=utf-8",
}
_CSP = (
    "default-src 'none'; style-src 'self'; script-src 'self'; img-src 'self' data:; "
    "form-action 'self'; frame-ancestors 'none'; base-uri 'none'"
)
# Failed sign-ins and bad ingest tokens allowed per window before the hub
# answers 429. One process, one counter: this is a brake, not a lockout.
_FAIL_LIMIT = 20
_FAIL_WINDOW = 300.0


@dataclass
class HubConfig:
    db_path: Path
    ui_token: str
    bind: str = "127.0.0.1"
    port: int = 8765
    allowed_hosts: frozenset[str] = LOOPBACK_NAMES
    tls: bool = False
    version: str = ""
    _failures: list[float] = field(default_factory=list)
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def csrf_token(self) -> str:
        return hmac.new(self.ui_token.encode("utf-8"), b"aiscan-hub-csrf", "sha256").hexdigest()

    def note_failure(self) -> None:
        with self._lock:
            self._failures.append(time.monotonic())

    def throttled(self) -> bool:
        cutoff = time.monotonic() - _FAIL_WINDOW
        with self._lock:
            self._failures[:] = [t for t in self._failures if t >= cutoff]
            return len(self._failures) >= _FAIL_LIMIT


def _same(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))


def _host_name(header: str) -> str:
    """Hostname from a Host or Origin authority, lowercased, without the port."""
    text = (header or "").strip().lower()
    if text.startswith("["):
        return text[1:].split("]", 1)[0]
    return text.rsplit(":", 1)[0] if ":" in text else text


def _int(value: Any, default: int | None = None, *, low: int = 0, high: int = 10**9) -> int | None:
    try:
        number = int(str(value))
    except (TypeError, ValueError):
        return default
    return number if low <= number <= high else default


def _format_bytes(size: int) -> str:
    value = float(size)
    for unit in ("bytes", "KB", "MB", "GB"):
        if value < 1024 or unit == "GB":
            return f"{value:.0f} {unit}" if unit == "bytes" else f"{value:.1f} {unit}"
        value /= 1024
    return f"{size} bytes"


class HubHandler(BaseHTTPRequestHandler):
    server_version = "aiscan-hub"
    sys_version = ""
    protocol_version = "HTTP/1.1"
    config: HubConfig  # set on the subclass made by make_server

    # ---- plumbing ---------------------------------------------------------

    def log_message(self, fmt: str, *args: Any) -> None:
        # Path only. A query string can carry the sign-in token.
        path = urlsplit(self.path).path
        status = args[1] if len(args) > 1 else ""
        sys.stderr.write(f"[hub] {self.command} {path} {status}\n")

    def _send(
        self,
        status: int,
        body: bytes,
        content_type: str,
        headers: dict[str, str] | None = None,
    ) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Content-Security-Policy", _CSP)
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cache-Control", "no-store")
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _html(self, body: str, status: int = 200, headers: dict[str, str] | None = None) -> None:
        self._send(status, body.encode("utf-8"), "text/html; charset=utf-8", headers)

    def _json(self, payload: Any, status: int = 200) -> None:
        self._send(status, json.dumps(payload, ensure_ascii=False).encode("utf-8"), "application/json; charset=utf-8")

    def _redirect(self, location: str, headers: dict[str, str] | None = None) -> None:
        self._send(HTTPStatus.SEE_OTHER, b"", "text/plain; charset=utf-8", {"Location": location, **(headers or {})})

    def _page(self, title: str, active: str, body: str, status: int = 200) -> None:
        self._html(pages.page(title, active, body, csrf=self.config.csrf_token(), version=self.config.version), status)

    def _host_ok(self) -> bool:
        return _host_name(self.headers.get("Host", "")) in self.config.allowed_hosts

    def _bearer(self) -> str:
        value = self.headers.get("Authorization", "")
        return value[7:].strip() if value[:7].lower() == "bearer " else ""

    def _ui_authed(self) -> bool:
        token = self.config.ui_token
        bearer = self._bearer()
        if bearer and _same(bearer, token):
            return True
        cookie = SimpleCookie()
        try:
            cookie.load(self.headers.get("Cookie", ""))
        except Exception:
            return False
        morsel = cookie.get(COOKIE_NAME)
        return bool(morsel and _same(morsel.value, token))

    def _session_cookie(self, value: str, max_age: int) -> str:
        secure = "; Secure" if self.config.tls else ""
        return f"{COOKIE_NAME}={value}; Path=/; HttpOnly; SameSite=Lax; Max-Age={max_age}{secure}"

    def _body(self, limit: int) -> bytes | None:
        """Request body, or None after an error response was sent."""
        length = _int(self.headers.get("Content-Length"), None)
        if length is None:
            self._json({"error": "Content-Length is required"}, HTTPStatus.LENGTH_REQUIRED)
            return None
        if length > limit:
            self.close_connection = True
            self._json({"error": f"body is larger than {limit} bytes"}, HTTPStatus.REQUEST_ENTITY_TOO_LARGE)
            return None
        return self.rfile.read(length)

    def _form(self) -> dict[str, str] | None:
        raw = self._body(MAX_FORM_BYTES)
        if raw is None:
            return None
        try:
            parsed = parse_qs(raw.decode("utf-8"), keep_blank_values=True)
        except UnicodeDecodeError:
            parsed = {}
        return {key: values[0] for key, values in parsed.items()}

    def _origin_ok(self) -> bool:
        """A form post must come from this hub's own pages."""
        origin = self.headers.get("Origin")
        if origin is None:
            return True  # Non-browser client. The CSRF field still applies.
        parts = urlsplit(origin)
        return bool(parts.hostname) and parts.netloc.lower() == self.headers.get("Host", "").strip().lower()

    # ---- dispatch ---------------------------------------------------------

    def do_HEAD(self) -> None:  # noqa: N802
        self.do_GET()

    def do_GET(self) -> None:  # noqa: N802
        self._dispatch("GET")

    def do_POST(self) -> None:  # noqa: N802
        self._dispatch("POST")

    def _dispatch(self, method: str) -> None:
        try:
            if not self._host_ok():
                self._send(HTTPStatus.MISDIRECTED_REQUEST, b"Unknown host name for this hub.\n", "text/plain; charset=utf-8")
                return
            url = urlsplit(self.path)
            params = {key: values[0] for key, values in parse_qs(url.query, keep_blank_values=True).items()}
            path = url.path.rstrip("/") or "/"
            if method == "GET":
                self._get(path, params)
            else:
                self._post(path)
        except (BrokenPipeError, ConnectionResetError):
            return
        except Exception as exc:  # noqa: BLE001 - last resort, never leak a trace to the client
            sys.stderr.write(f"[hub] error: {type(exc).__name__}: {exc}\n")
            try:
                self._send(HTTPStatus.INTERNAL_SERVER_ERROR, b"The hub hit an error. See its console.\n", "text/plain; charset=utf-8")
            except Exception:  # noqa: BLE001
                pass

    def _get(self, path: str, params: dict[str, str]) -> None:
        if path.startswith("/static/"):
            self._static(path[len("/static/"):])
            return
        if path == "/api/v1/health":
            self._json({"status": "ok"})
            return
        if path == "/login":
            self._login(params.get("token", ""), from_form=False)
            return
        is_api = path.startswith("/api/")
        if not self._ui_authed():
            if is_api:
                self._json({"error": "access token required"}, HTTPStatus.UNAUTHORIZED)
            else:
                self._redirect("/login")
            return
        conn = hub_db.connect(self.config.db_path)
        try:
            if is_api:
                self._api_get(conn, path, params)
            else:
                self._page_get(conn, path, params)
        finally:
            conn.close()

    def _post(self, path: str) -> None:
        if path == "/api/v1/scans":
            self._ingest()
            return
        if path == "/login":
            form = self._form()
            if form is not None:
                self._login(form.get("token", ""), from_form=True)
            return
        if path in ("/logout", "/findings/triage"):
            form = self._form()
            if form is None:
                return
            if not self._ui_authed() or not self._origin_ok() or not _same(form.get("csrf", ""), self.config.csrf_token()):
                self._html(pages.login_page("That request could not be verified. Sign in and try again."), HTTPStatus.FORBIDDEN)
                return
            if path == "/logout":
                self._redirect("/login", {"Set-Cookie": self._session_cookie("", 0)})
                return
            self._triage(form)
            return
        self._send(HTTPStatus.NOT_FOUND, b"Not found.\n", "text/plain; charset=utf-8")

    # ---- handlers ---------------------------------------------------------

    def _static(self, name: str) -> None:
        content_type = _STATIC.get(name)
        if content_type is None:
            self._send(HTTPStatus.NOT_FOUND, b"Not found.\n", "text/plain; charset=utf-8")
            return
        self._send(200, (hub_paths.STATIC_DIR / name).read_bytes(), content_type)

    def _login(self, token: str, *, from_form: bool) -> None:
        if not token:
            if self._ui_authed():
                self._redirect("/")
            else:
                self._html(pages.login_page())
            return
        if self.config.throttled():
            self._html(pages.login_page("Too many failed attempts. Wait a few minutes."), HTTPStatus.TOO_MANY_REQUESTS)
            return
        if _same(token, self.config.ui_token):
            self._redirect("/", {"Set-Cookie": self._session_cookie(self.config.ui_token, COOKIE_MAX_AGE)})
            return
        self.config.note_failure()
        self._html(pages.login_page("That access token is not valid."), HTTPStatus.UNAUTHORIZED)

    def _ingest(self) -> None:
        if self.config.throttled():
            self._json({"error": "too many failed attempts"}, HTTPStatus.TOO_MANY_REQUESTS)
            return
        bearer = self._bearer()
        conn = hub_db.connect(self.config.db_path)
        try:
            token_id = hub_db.find_token(conn, bearer)
            if token_id is None and not (bearer and _same(bearer, self.config.ui_token)):
                self.config.note_failure()
                self.close_connection = True
                self._json({"error": "a valid ingest token is required"}, HTTPStatus.UNAUTHORIZED)
                return
            raw = self._body(MAX_BUNDLE_BYTES)
            if raw is None:
                return
            try:
                payload = json.loads(raw.decode("utf-8"))
            except (UnicodeDecodeError, ValueError, RecursionError):
                self._json({"error": "body is not valid JSON"}, HTTPStatus.BAD_REQUEST)
                return
            try:
                # Backstop. The sender already masked this bundle; secrets
                # are masked again here in case a client did not.
                bundle, warnings = normalize_bundle(payload, share_safe=True, keep_emails=True, scrub_paths=False)
            except BundleError as exc:
                self._json({"error": str(exc)}, HTTPStatus.UNPROCESSABLE_ENTITY)
                return
            result = hub_db.ingest_bundle(conn, bundle, via="http", token_id=token_id)
            result["warnings"] = warnings
            self._json(result, HTTPStatus.OK if result["duplicate"] else HTTPStatus.CREATED)
        finally:
            conn.close()

    def _triage(self, form: dict[str, str]) -> None:
        host_id = _int(form.get("host"))
        collector = form.get("collector", "")
        key = form.get("key", "")
        conn = hub_db.connect(self.config.db_path)
        try:
            try:
                if host_id is None:
                    raise LookupError
                hub_db.set_triage(conn, host_id, collector, key, form.get("state", ""), form.get("note", ""))
            except (LookupError, ValueError):
                self._page("Not saved", "findings", pages.message_page("Not saved", "That finding or state does not exist."), 400)
                return
        finally:
            conn.close()
        from urllib.parse import urlencode
        self._redirect("/finding?" + urlencode({"host": host_id, "collector": collector, "key": key}))

    def _finding_filters(self, params: dict[str, str]) -> dict[str, Any]:
        status = params.get("status", "open")
        return {
            "status": status if status in ("open", "resolved", "all") else "open",
            "severity": params.get("severity", ""),
            "triage": params.get("triage", ""),
            "collector": params.get("collector", "")[:64],
            "host": _int(params.get("host")),
            "q": params.get("q", "")[:200].strip(),
        }

    def _page_get(self, conn: Any, path: str, params: dict[str, str]) -> None:
        offset = _int(params.get("offset"), 0) or 0
        if path == "/":
            attention, _total = q.findings(conn, status="open", triage="attention", limit=8)
            attention = [row for row in attention if row["severity"] in ("critical", "high")]
            data = {
                "overview": q.overview(conn), "trend": q.fleet_trend(conn), "hosts": q.hosts(conn),
                "changes": q.recent_changes(conn), "attention": attention,
            }
            self._page("Overview", "overview", pages.overview_page(data))
            return
        if path.startswith("/hosts/"):
            host_id = _int(path.rsplit("/", 1)[1])
            host = q.host(conn, host_id) if host_id is not None else None
            if host is None:
                self._not_found()
                return
            rows, _total = q.findings(conn, status="open", host_id=host_id, limit=50)
            data = {
                "host": host, "trend": q.host_trend(conn, host_id), "runs": q.current_runs(conn, host_id),
                "findings": rows, "scans": q.scans(conn, host_id=host_id, limit=30),
            }
            self._page(host["name"], "overview", pages.host_page(data))
            return
        if path == "/scans":
            total = conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
            data = {"scans": q.scans(conn, offset=offset), "total": total, "offset": offset}
            self._page("Scans", "scans", pages.scans_page(data))
            return
        if path.startswith("/scans/"):
            scan_id = _int(path.rsplit("/", 1)[1])
            scan = q.scan(conn, scan_id) if scan_id is not None else None
            if scan is None:
                self._not_found()
                return
            self._page("Scan", "scans", pages.scan_page({"scan": scan, "changes": q.scan_changes(conn, scan_id)}))
            return
        if path == "/findings":
            filters = self._finding_filters(params)
            rows, total = q.findings(
                conn, status=filters["status"], severity=filters["severity"], collector=filters["collector"],
                host_id=filters["host"], triage=filters["triage"], query=filters["q"], offset=offset,
            )
            data = {
                "filters": filters, "rows": rows, "total": total, "offset": offset,
                "collectors": q.collectors_with_findings(conn), "hosts": q.hosts(conn),
            }
            self._page("Findings", "findings", pages.findings_page(data))
            return
        if path == "/finding":
            host_id = _int(params.get("host"))
            item = q.finding(conn, host_id, params.get("collector", ""), params.get("key", "")) if host_id is not None else None
            if item is None:
                self._not_found()
                return
            self._page(item["title"] or "Finding", "findings", pages.finding_page({"finding": item}, self.config.csrf_token()))
            return
        if path == "/permissions":
            decision = params.get("decision", "allow")
            filters = {
                "decision": decision if decision in ("allow", "ask", "deny", "all") else "allow",
                "risk": params.get("risk", ""), "host": _int(params.get("host")),
                "q": params.get("q", "")[:200].strip(),
            }
            rows, total = q.rules(
                conn, decision=filters["decision"], risk=filters["risk"], host_id=filters["host"],
                query=filters["q"], offset=offset,
            )
            data = {"filters": filters, "rows": rows, "total": total, "offset": offset,
                    "totals": q.rule_totals(conn), "hosts": q.hosts(conn)}
            self._page("Permissions", "permissions", pages.permissions_page(data))
            return
        if path == "/mcp":
            self._page("MCP servers", "mcp", pages.mcp_page({"servers": q.mcp_servers(conn)}))
            return
        if path == "/accounts":
            self._page("Accounts", "accounts", pages.accounts_page({"accounts": q.accounts(conn)}))
            return
        if path == "/settings":
            db_path = Path(self.config.db_path)
            size = db_path.stat().st_size if db_path.is_file() else 0
            scheme = "https" if self.config.tls else "http"
            data = {
                "tokens": q.tokens(conn), "db_path": str(db_path), "db_size": _format_bytes(size),
                "listen": f"{scheme}://{self.config.bind}:{self.config.port}", "version": self.config.version,
            }
            self._page("Settings", "settings", pages.settings_page(data))
            return
        self._not_found()

    def _not_found(self) -> None:
        self._page("Not found", "", pages.message_page("Not found", "There is nothing at this address."), 404)

    def _api_get(self, conn: Any, path: str, params: dict[str, str]) -> None:
        offset = _int(params.get("offset"), 0) or 0
        limit = _int(params.get("limit"), q.PAGE_SIZE, low=1, high=1000) or q.PAGE_SIZE
        host_id = _int(params.get("host"))
        if path == "/api/v1/overview":
            self._json(q.overview(conn))
        elif path == "/api/v1/hosts":
            self._json({"hosts": q.hosts(conn)})
        elif path == "/api/v1/trend":
            self._json({"points": q.host_trend(conn, host_id) if host_id is not None else q.fleet_trend(conn)})
        elif path == "/api/v1/scans":
            self._json({"scans": q.scans(conn, host_id=host_id, limit=limit, offset=offset)})
        elif path.startswith("/api/v1/scans/"):
            scan_id = _int(path.rsplit("/", 1)[1])
            scan = q.scan(conn, scan_id) if scan_id is not None else None
            if scan is None:
                self._json({"error": "no such scan"}, HTTPStatus.NOT_FOUND)
                return
            scan["changes"] = q.scan_changes(conn, scan_id)
            self._json(scan)
        elif path == "/api/v1/findings":
            filters = self._finding_filters(params)
            rows, total = q.findings(
                conn, status=filters["status"], severity=filters["severity"], collector=filters["collector"],
                host_id=filters["host"], triage=filters["triage"], query=filters["q"], limit=limit, offset=offset,
            )
            self._json({"total": total, "findings": rows})
        elif path == "/api/v1/rules":
            rows, total = q.rules(conn, decision=params.get("decision", "allow"), risk=params.get("risk", ""),
                                  host_id=host_id, query=params.get("q", "")[:200], limit=limit, offset=offset)
            self._json({"total": total, "rules": rows})
        elif path == "/api/v1/mcp-servers":
            self._json({"servers": q.mcp_servers(conn)})
        else:
            self._json({"error": "not found"}, HTTPStatus.NOT_FOUND)


class _Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = False


class _Server6(_Server):
    address_family = socket.AF_INET6


def make_server(config: HubConfig) -> ThreadingHTTPServer:
    """Bind the hub. ``config.port`` 0 picks a free port and updates the config."""
    handler = type("BoundHubHandler", (HubHandler,), {"config": config})
    cls = _Server6 if ":" in config.bind else _Server
    server = cls((config.bind, config.port), handler)
    config.port = server.server_address[1]
    return server
