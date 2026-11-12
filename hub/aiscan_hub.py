#!/usr/bin/env python3
"""aiscan hub: a local database and dashboard for aiscan scans.

    python hub/aiscan_hub.py ingest <scan folder or folder of scans> ...
    python hub/aiscan_hub.py serve
    python hub/aiscan_hub.py status
    python hub/aiscan_hub.py push <scan folder> --server https://hub.example
    python hub/aiscan_hub.py token create --name laptop
    python hub/aiscan_hub.py prune --keep-days 365 --dry-run

``ingest``, ``serve``, ``status``, ``token`` and ``prune`` work on a SQLite
file on this machine and make no outbound network calls. ``serve`` listens
on 127.0.0.1 unless told otherwise.

``push`` is the only command that sends data to another machine, and it
runs only when you call it. It sends a share-safe bundle (secrets, paths,
and emails masked) to the one server you name. ``--dry-run`` prints exactly
what would be sent.

Standard library only, Python 3.11+, the same as the collectors.
"""

from __future__ import annotations

import argparse
import json
import os
import secrets
import sys
import time
import urllib.error
import urllib.request
import webbrowser
from pathlib import Path
from urllib.parse import urlsplit

import hub_paths

import hub_db
import hub_queries
from hub_bundle import BundleError, build_bundle, is_scan_folder

PUSH_PATH = "/api/v1/scans"
PUSH_TIMEOUT = 60


def _version() -> str:
    from tool_version import tool_version

    return tool_version()


def _scan_folders(path: Path) -> list[Path]:
    """``path`` if it is a scan folder, else its child scan folders."""
    if is_scan_folder(path):
        return [path]
    if not path.is_dir():
        return []
    try:
        children = sorted(child for child in path.iterdir() if child.is_dir() and is_scan_folder(child))
    except OSError:
        return []
    return children


# ---- ingest ---------------------------------------------------------------

def cmd_ingest(args: argparse.Namespace) -> int:
    folders: list[Path] = []
    for raw in args.paths:
        found = _scan_folders(Path(raw))
        if not found:
            # Leaf name only: agents run this and must not repeat full paths.
            print(f"Not a scan folder, and no scan folders inside it: {Path(raw).name}", file=sys.stderr)
        folders.extend(found)
    if not folders:
        return 1
    conn = hub_db.connect(hub_paths.resolve_db_path(args.db))
    added = duplicate = failed = 0
    try:
        for folder in folders:
            try:
                bundle, warnings = build_bundle(folder)
                result = hub_db.ingest_bundle(conn, bundle, via="local")
            except BundleError as exc:
                failed += 1
                print(f"  skipped {folder.name}: {exc}", file=sys.stderr)
                continue
            for warning in warnings:
                print(f"  note for {folder.name}: {warning}", file=sys.stderr)
            if result["duplicate"]:
                duplicate += 1
            else:
                added += 1
    finally:
        conn.close()
    print(f"Hub: {added} scan(s) added, {duplicate} already stored, {failed} skipped.")
    return 0 if (added or duplicate) else 1


# ---- serve ----------------------------------------------------------------

def load_ui_token(data_dir: Path, *, rotate: bool = False) -> str:
    """Read the dashboard access token, creating it on first use."""
    path = data_dir / hub_paths.UI_TOKEN_FILENAME
    if not rotate:
        try:
            text = path.read_text(encoding="utf-8").strip()
        except OSError:
            text = ""
        if len(text) >= 24:
            return text
    data_dir.mkdir(parents=True, exist_ok=True)
    token = secrets.token_urlsafe(32)
    path.write_text(token + "\n", encoding="utf-8")
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return token


def cmd_serve(args: argparse.Namespace) -> int:
    import hub_web

    db_path = hub_paths.resolve_db_path(args.db)
    loopback = args.bind in hub_web.LOOPBACK_NAMES
    tls = bool(args.tls_cert and args.tls_key)
    if bool(args.tls_cert) != bool(args.tls_key):
        print("Pass both --tls-cert and --tls-key, or neither.", file=sys.stderr)
        return 1
    if not loopback and not tls and not args.insecure_http:
        print(
            f"Refusing to listen on {args.bind} over plain HTTP: the access token and scan data "
            "would cross the network unencrypted.\nPass --tls-cert and --tls-key, or put the hub "
            "behind a TLS reverse proxy and pass --insecure-http to accept that.",
            file=sys.stderr,
        )
        return 1
    hub_db.connect(db_path).close()
    token = load_ui_token(db_path.parent, rotate=args.rotate_token)
    allowed = set(hub_web.LOOPBACK_NAMES) | {args.bind.lower()} | {h.lower() for h in args.allowed_host}
    allowed.discard("0.0.0.0")
    allowed.discard("::")
    config = hub_web.HubConfig(
        db_path=db_path, ui_token=token, bind=args.bind, port=args.port,
        allowed_hosts=frozenset(allowed), tls=tls, version=_version(),
    )
    try:
        server = hub_web.make_server(config)
    except OSError as exc:
        print(f"Could not listen on {args.bind}:{args.port}: {exc.strerror or exc}", file=sys.stderr)
        return 1
    if tls:
        import ssl

        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(args.tls_cert, args.tls_key)
        server.socket = context.wrap_socket(server.socket, server_side=True)
    scheme = "https" if tls else "http"
    shown = "127.0.0.1" if args.bind in ("0.0.0.0", "::") else args.bind
    host = f"[{shown}]" if ":" in shown else shown
    base = f"{scheme}://{host}:{config.port}"
    print(f"aiscan hub {config.version}")
    print(f"Dashboard: {base}/")
    # The sign-in link carries the access token. It goes to this console
    # only. Under -AgentMode it is not printed at all.
    if os.environ.get("AISCAN_AGENT_MODE", "").strip().lower() in ("1", "true", "yes"):
        print("Sign-in link not printed in agent mode. The token is in the ui-token file next to the database.")
    else:
        print(f"Sign in:   {base}/login?token={token}")
    if not loopback:
        print(f"Listening on {args.bind}. Other machines reach it by a name passed with --allowed-host.")
    print("Press Ctrl+C to stop.")
    if not args.no_browser and loopback:
        try:
            webbrowser.open(f"{base}/login?token={token}")
        except Exception:  # noqa: BLE001 - a missing browser must not stop the server
            pass
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")
    finally:
        server.server_close()
    return 0


def cmd_demo(args: argparse.Namespace) -> int:
    """Fill a separate demo database with invented scans, then serve it."""
    import hub_demo
    from hub_bundle import normalize_bundle

    db_path = Path(args.db) if args.db else hub_paths.default_data_dir() / "demo.db"
    for suffix in ("", "-wal", "-shm"):
        Path(str(db_path) + suffix).unlink(missing_ok=True)
    conn = hub_db.connect(db_path)
    try:
        for raw in hub_demo.demo_bundles():
            bundle, _warnings = normalize_bundle(raw)
            hub_db.ingest_bundle(conn, bundle, via="demo")
    finally:
        conn.close()
    print("Demo database built from invented data. Your real hub database is untouched.")
    if args.no_serve:
        return 0
    args.db = str(db_path)
    return cmd_serve(args)


# ---- push -----------------------------------------------------------------

class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """A redirect could carry the bundle and token to another host. Refuse."""

    def redirect_request(self, *args, **kwargs):  # type: ignore[no-untyped-def]
        return None


def push_url(server: str, *, insecure_http: bool) -> str:
    """Validated ingest URL for ``server``. Raises ValueError with the reason."""
    parts = urlsplit(server.strip())
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise ValueError("--server must be an http(s) URL such as https://hub.example:8765")
    if parts.username or parts.password or parts.query or parts.fragment:
        raise ValueError("--server must not contain credentials, a query, or a fragment")
    loopback = parts.hostname in ("127.0.0.1", "localhost", "::1")
    if parts.scheme == "http" and not loopback and not insecure_http:
        raise ValueError(
            "refusing to send over plain HTTP to another machine. Use https, or pass --insecure-http"
        )
    return f"{parts.scheme}://{parts.netloc}{parts.path.rstrip('/')}{PUSH_PATH}"


def cmd_push(args: argparse.Namespace) -> int:
    folder = Path(args.scan)
    try:
        bundle, warnings = build_bundle(folder, share_safe=True, keep_emails=args.keep_emails)
    except BundleError as exc:
        print(f"Cannot push {folder.name}: {exc}", file=sys.stderr)
        return 1
    for warning in warnings:
        print(f"  note: {warning}", file=sys.stderr)
    body = json.dumps(bundle, ensure_ascii=False).encode("utf-8")
    if args.dry_run:
        print(json.dumps(bundle, indent=2, ensure_ascii=False))
        print(f"Dry run: {len(body):,} bytes would be sent. Nothing was sent.", file=sys.stderr)
        return 0
    if not args.server:
        print("--server is required unless --dry-run is set.", file=sys.stderr)
        return 1
    try:
        url = push_url(args.server, insecure_http=args.insecure_http)
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    token = os.environ.get(args.token_env, "").strip()
    if not token:
        print(
            f"Set {args.token_env} to an ingest token first. Create one on the hub with:\n"
            "  python hub\\aiscan_hub.py token create --name <this machine>",
            file=sys.stderr,
        )
        return 1
    opener = urllib.request.build_opener(_NoRedirect)
    last_error = ""
    for attempt in range(3):
        if attempt:
            time.sleep(2 * attempt)
        request = urllib.request.Request(
            url, data=body, method="POST",
            headers={"Content-Type": "application/json", "Authorization": f"Bearer {token}",
                     "User-Agent": "aiscan-hub-push"},
        )
        try:
            with opener.open(request, timeout=PUSH_TIMEOUT) as response:
                result = json.loads(response.read(1024 * 1024).decode("utf-8"))
        except urllib.error.HTTPError as exc:
            detail = ""
            try:
                detail = str(json.loads(exc.read(65536).decode("utf-8")).get("error") or "")
            except Exception:  # noqa: BLE001
                pass
            last_error = f"server answered {exc.code}" + (f": {detail}" if detail else "")
            if exc.code < 500:
                break
            continue
        except (urllib.error.URLError, TimeoutError, OSError, ValueError) as exc:
            reason = getattr(exc, "reason", exc)
            last_error = f"could not reach the server ({reason})"
            continue
        state = "already stored" if result.get("duplicate") else "stored"
        print(f"Pushed {len(body):,} bytes. Scan {state} as #{result.get('scan_id')}.")
        for warning in result.get("warnings") or []:
            print(f"  server note: {warning}", file=sys.stderr)
        return 0
    print(f"Push failed: {last_error}. The scan folder is unchanged; run push again to retry.", file=sys.stderr)
    return 2


# ---- status, tokens, prune ------------------------------------------------

def cmd_status(args: argparse.Namespace) -> int:
    db_path = hub_paths.resolve_db_path(args.db)
    if not db_path.is_file():
        print("No hub database yet. Add a scan with: .\\aiscan.ps1 all -Hub")
        return 0
    conn = hub_db.connect(db_path)
    try:
        overview = hub_queries.overview(conn)
    finally:
        conn.close()
    if args.json:
        print(json.dumps(overview, indent=2))
        return 0
    counts = overview["open"]
    print(f"Machines: {overview['hosts']}   Scans: {overview['scans']}   Last scan: {overview['last_scan'] or 'none'}")
    print(
        f"Open findings: {overview['open_total']} "
        f"(critical {counts['critical']}, high {counts['high']}, medium {counts['medium']}, low {counts['low']})"
    )
    print(f"Agents detected: {overview['agents']}   Allow rules: {overview['allow_rules']}   MCP servers: {overview['mcp_servers']}")
    return 0


def cmd_token(args: argparse.Namespace) -> int:
    conn = hub_db.connect(hub_paths.resolve_db_path(args.db))
    try:
        if args.action == "list":
            rows = hub_queries.tokens(conn)
            if not rows:
                print("No ingest tokens.")
            for row in rows:
                state = "revoked" if row["revoked_at"] else "active"
                print(f"{row['name']}\t{state}\tcreated {row['created_at']}\tlast used {row['last_used_at'] or 'never'}")
            return 0
        if not args.name:
            print("--name is required.", file=sys.stderr)
            return 1
        if args.action == "create":
            try:
                token = hub_db.create_token(conn, args.name)
            except Exception:  # sqlite3.IntegrityError: the name is taken
                print(f"A token named {args.name} already exists. Revoke it or pick another name.", file=sys.stderr)
                return 1
            print("Ingest token (shown once, store it now):")
            print(token)
            print(f"On the sending machine: set {hub_paths.ENV_TOKEN} to this value, then run push.")
            return 0
        if hub_db.revoke_token(conn, args.name):
            print(f"Revoked {args.name}.")
            return 0
        print(f"No active token named {args.name}.", file=sys.stderr)
        return 1
    finally:
        conn.close()


def cmd_prune(args: argparse.Namespace) -> int:
    if args.keep_days is None and args.keep_last is None:
        print("Pass --keep-days, --keep-last, or both.", file=sys.stderr)
        return 1
    conn = hub_db.connect(hub_paths.resolve_db_path(args.db))
    try:
        count = hub_db.prune(conn, keep_days=args.keep_days, keep_last=args.keep_last, dry_run=args.dry_run)
        if count and not args.dry_run:
            conn.execute("VACUUM")
    finally:
        conn.close()
    verb = "would be removed" if args.dry_run else "removed"
    print(f"{count} scan(s) {verb}. Each machine's newest scan is always kept.")
    return 0


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="aiscan_hub.py", description="Local database and dashboard for aiscan scans.")
    parser.add_argument("--db", default=None, help=f"Database file. Default: {hub_paths.ENV_DB}, else the per-user data folder")
    sub = parser.add_subparsers(dest="command", required=True)

    ingest = sub.add_parser("ingest", help="Add scan folders to the hub database")
    ingest.add_argument("paths", nargs="+", help="A scan folder, or a folder that holds scan folders")
    ingest.set_defaults(func=cmd_ingest)

    def serve_options(target: argparse.ArgumentParser) -> None:
        target.add_argument("--bind", default="127.0.0.1", help="Address to listen on. Default 127.0.0.1")
        target.add_argument("--port", type=int, default=8765)
        target.add_argument("--no-browser", action="store_true", help="Do not open the dashboard in a browser")
        target.add_argument("--allowed-host", action="append", default=[], metavar="NAME",
                            help="Extra host name this hub answers to (repeatable), such as hub.example")
        target.add_argument("--tls-cert", default=None, help="PEM certificate chain. Enables HTTPS with --tls-key")
        target.add_argument("--tls-key", default=None, help="PEM private key")
        target.add_argument("--insecure-http", action="store_true",
                            help="Allow plain HTTP on a non-loopback address (for use behind a TLS proxy)")
        target.add_argument("--rotate-token", action="store_true", help="Replace the dashboard access token")

    serve = sub.add_parser("serve", help="Run the dashboard")
    serve_options(serve)
    serve.set_defaults(func=cmd_serve)

    demo = sub.add_parser("demo", help="Build a demo database from invented data and run the dashboard on it")
    serve_options(demo)
    demo.add_argument("--no-serve", action="store_true", help="Build the demo database and exit")
    demo.set_defaults(func=cmd_demo)

    push = sub.add_parser("push", help="Send one scan, share-safe, to a hub on another machine")
    push.add_argument("scan", help="Scan folder")
    push.add_argument("--server", default=None, help="Hub base URL, such as https://hub.example:8765")
    push.add_argument("--token-env", default=hub_paths.ENV_TOKEN,
                      help=f"Environment variable that holds the ingest token. Default {hub_paths.ENV_TOKEN}")
    push.add_argument("--keep-emails", action="store_true", help="Send account emails instead of <email>")
    push.add_argument("--insecure-http", action="store_true", help="Allow plain HTTP to a non-loopback server")
    push.add_argument("--dry-run", action="store_true", help="Print the bundle that would be sent, and send nothing")
    push.set_defaults(func=cmd_push)

    status = sub.add_parser("status", help="Counts from the hub database")
    status.add_argument("--json", action="store_true")
    status.set_defaults(func=cmd_status)

    token = sub.add_parser("token", help="Manage ingest tokens for other machines")
    token.add_argument("action", choices=["create", "list", "revoke"])
    token.add_argument("--name", default=None)
    token.set_defaults(func=cmd_token)

    prune = sub.add_parser("prune", help="Remove old scans")
    prune.add_argument("--keep-days", type=int, default=None)
    prune.add_argument("--keep-last", type=int, default=None, help="Scans to keep per machine regardless of age")
    prune.add_argument("--dry-run", action="store_true")
    prune.set_defaults(func=cmd_prune)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    sys.exit(main())
