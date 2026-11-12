"""The HTTP server: access control, ingest, escaping, and headers.

Each test class starts a real server on a free loopback port.
"""

from __future__ import annotations

import http.client
import json
import tempfile
import threading
import unittest
from pathlib import Path
from urllib.parse import urlencode

import bootstrap  # noqa: F401
from bootstrap import finding, raw_bundle

import hub_db
import hub_web
from hub_bundle import normalize_bundle

UI_TOKEN = "test-ui-token-0123456789abcdef"
T1 = "2026-10-01T12:00:00+00:00"
T2 = "2026-10-02T12:00:00+00:00"
XSS = '<script>alert("x")</script>'
FAKE_KEY = "AKIA" + "ABCDEFGHIJKLMNOP"


class HubServerCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.db_path = Path(cls.tmp.name) / "hub.db"
        conn = hub_db.connect(cls.db_path)
        bundle, _ = normalize_bundle(raw_bundle(T1, {
            "claude": [finding("a.one", "critical", title=f"Title {XSS}", sample_redacted=XSS)],
        }))
        cls.scan_id = hub_db.ingest_bundle(conn, bundle)["scan_id"]
        cls.ingest_token = hub_db.create_token(conn, "laptop")
        conn.close()
        cls.config = hub_web.HubConfig(db_path=cls.db_path, ui_token=UI_TOKEN, port=0, version="test")
        cls.server = hub_web.make_server(cls.config)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.cookie = f"{hub_web.COOKIE_NAME}={UI_TOKEN}"
        cls.host_header = f"127.0.0.1:{cls.config.port}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=5)
        cls.tmp.cleanup()

    def request(self, method, path, *, body=None, headers=None, cookie=True):
        conn = http.client.HTTPConnection("127.0.0.1", self.config.port, timeout=10)
        send = dict(headers or {})
        if cookie:
            send.setdefault("Cookie", self.cookie)
        if isinstance(body, (dict, list)):
            body = json.dumps(body).encode("utf-8")
            send.setdefault("Content-Type", "application/json")
        try:
            conn.request(method, path, body=body, headers=send)
            response = conn.getresponse()
            return response.status, dict(response.getheaders()), response.read().decode("utf-8")
        finally:
            conn.close()

    def form(self, path, fields, **kwargs):
        headers = {"Content-Type": "application/x-www-form-urlencoded", **kwargs.pop("headers", {})}
        return self.request("POST", path, body=urlencode(fields).encode("utf-8"), headers=headers, **kwargs)


class AccessTests(HubServerCase):
    def test_pages_need_the_access_token(self):
        for path in ("/", "/findings", "/scans", "/permissions", "/mcp", "/accounts", "/settings"):
            status, headers, _ = self.request("GET", path, cookie=False)
            self.assertEqual((status, headers.get("Location")), (303, "/login"), path)

    def test_api_reads_need_the_access_token(self):
        status, _, body = self.request("GET", "/api/v1/overview", cookie=False)
        self.assertEqual(status, 401)
        self.assertNotIn("hosts", body)
        status, _, _ = self.request("GET", "/api/v1/overview", cookie=False,
                                    headers={"Authorization": f"Bearer {UI_TOKEN}"})
        self.assertEqual(status, 200)

    def test_ingest_token_cannot_read(self):
        status, _, _ = self.request("GET", "/api/v1/findings", cookie=False,
                                    headers={"Authorization": f"Bearer {self.ingest_token}"})
        self.assertEqual(status, 401)

    def test_health_is_open_and_says_nothing(self):
        status, _, body = self.request("GET", "/api/v1/health", cookie=False)
        self.assertEqual((status, json.loads(body)), (200, {"status": "ok"}))

    def test_unknown_host_header_is_refused(self):
        for name in ("evil.example", "127.0.0.1.evil.example", ""):
            status, _, _ = self.request("GET", "/", headers={"Host": name})
            self.assertEqual(status, 421, name)

    def test_login_sets_an_http_only_cookie_and_leaves_the_token_out_of_the_url(self):
        status, headers, _ = self.request("GET", f"/login?token={UI_TOKEN}", cookie=False)
        self.assertEqual((status, headers.get("Location")), (303, "/"))
        cookie = headers.get("Set-Cookie", "")
        self.assertIn("HttpOnly", cookie)
        self.assertIn("SameSite=Lax", cookie)
        status, _, body = self.form("/login", {"token": "wrong"}, cookie=False)
        self.assertEqual(status, 401)
        self.assertNotIn(UI_TOKEN, body)

    def test_every_response_carries_the_security_headers(self):
        for path in ("/", "/login", "/static/hub.css", "/api/v1/health", "/nope"):
            _, headers, _ = self.request("GET", path)
            self.assertIn("script-src 'self'", headers.get("Content-Security-Policy", ""), path)
            self.assertEqual(headers.get("X-Content-Type-Options"), "nosniff", path)
            self.assertEqual(headers.get("X-Frame-Options"), "DENY", path)
            self.assertNotIn("Access-Control-Allow-Origin", headers, path)

    def test_static_serves_only_known_files(self):
        self.assertEqual(self.request("GET", "/static/hub.js")[0], 200)
        for name in ("../hub_db.py", "..%2Fhub_db.py", "hub.db", "nope.css"):
            self.assertEqual(self.request("GET", f"/static/{name}")[0], 404, name)


class PageTests(HubServerCase):
    def test_pages_render(self):
        host_id = 1
        paths = ["/", f"/hosts/{host_id}", "/scans", f"/scans/{self.scan_id}", "/findings",
                 "/findings?status=all&severity=critical&q=Title", "/permissions?decision=all",
                 "/mcp", "/accounts", "/settings",
                 "/finding?" + urlencode({"host": host_id, "collector": "claude", "key": "a.one"})]
        for path in paths:
            status, _, body = self.request("GET", path)
            self.assertEqual(status, 200, path)
            self.assertIn("aiscan hub", body, path)

    def test_scan_text_is_escaped_everywhere(self):
        paths = ["/", "/findings", f"/scans/{self.scan_id}", "/hosts/1",
                 "/finding?" + urlencode({"host": 1, "collector": "claude", "key": "a.one"})]
        for path in paths:
            _, _, body = self.request("GET", path)
            self.assertNotIn(XSS, body, path)
            self.assertNotIn("<script>alert", body, path)
        _, _, body = self.request("GET", "/findings?" + urlencode({"q": XSS}))
        self.assertNotIn(XSS, body)

    def test_pages_have_no_inline_script_or_style(self):
        for path in ("/", "/findings", f"/scans/{self.scan_id}", "/hosts/1"):
            _, _, body = self.request("GET", path)
            self.assertNotIn("<script>", body, path)
            self.assertNotIn(" style=", body, path)
            self.assertNotIn(" onclick=", body, path)

    def test_missing_things_are_404(self):
        for path in ("/hosts/999", "/scans/999", "/scans/abc", "/finding?host=1&collector=x&key=y", "/nope"):
            self.assertEqual(self.request("GET", path)[0], 404, path)


class IngestTests(HubServerCase):
    def bundle(self, **collectors):
        return raw_bundle(T2, collectors or {"codex": [finding("c.one")]}, host="REMOTE-HOST")

    def post(self, payload, token=None, **kwargs):
        headers = {"Authorization": f"Bearer {token or self.ingest_token}"}
        return self.request("POST", "/api/v1/scans", body=payload, headers=headers, cookie=False, **kwargs)

    def test_ingest_needs_a_token(self):
        status, _, _ = self.request("POST", "/api/v1/scans", body=self.bundle(), cookie=False)
        self.assertEqual(status, 401)
        self.assertEqual(self.post(self.bundle(), token="aish_wrong")[0], 401)
        # The dashboard cookie is not an ingest credential.
        self.assertEqual(self.request("POST", "/api/v1/scans", body=self.bundle())[0], 401)

    def test_ingest_stores_once_and_marks_the_scan_share_safe(self):
        payload = self.bundle(codex=[finding("c.http", "high")])
        status, _, body = self.post(payload)
        self.assertEqual(status, 201)
        first = json.loads(body)
        status, _, body = self.post(payload)
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)["scan_id"], first["scan_id"])
        self.assertTrue(json.loads(body)["duplicate"])
        _, _, body = self.request("GET", f"/api/v1/scans/{first['scan_id']}")
        stored = json.loads(body)
        self.assertEqual((stored["host"], stored["via"], stored["share_safe"]), ("REMOTE-HOST", "http", 1))

    def test_server_masks_secrets_and_drops_raw_fields_again(self):
        payload = self.bundle(grok=[finding("g.one", sample_redacted=f"token {FAKE_KEY}", raw_evidence_ref="raw/x")])
        payload["collectors"]["grok"]["raw_pointers"] = [{"path": "raw/chat/secret.md"}]
        status, _, body = self.post(payload)
        self.assertEqual(status, 201)
        conn = hub_db.connect(self.db_path)
        try:
            dump = "\n".join(conn.iterdump())
        finally:
            conn.close()
        self.assertNotIn(FAKE_KEY, dump)
        self.assertNotIn("raw/chat/secret.md", dump)
        self.assertNotIn("raw_evidence_ref", dump)

    def test_bad_payloads_are_refused(self):
        self.assertEqual(self.post(b"not json")[0], 400)
        self.assertEqual(self.post({"bundle_version": 1, "collectors": {}})[0], 422)
        self.assertEqual(self.post({"bundle_version": 7, "collectors": {"a": {}}})[0], 422)

    def test_oversized_body_is_refused_before_it_is_read(self):
        headers = {"Authorization": f"Bearer {self.ingest_token}", "Content-Type": "application/json",
                   "Content-Length": str(hub_web.MAX_BUNDLE_BYTES + 1)}
        conn = http.client.HTTPConnection("127.0.0.1", self.config.port, timeout=10)
        try:
            conn.putrequest("POST", "/api/v1/scans")
            for key, value in headers.items():
                conn.putheader(key, value)
            conn.endheaders()
            self.assertEqual(conn.getresponse().status, 413)
        finally:
            conn.close()

    def test_revoked_token_stops_working(self):
        conn = hub_db.connect(self.db_path)
        token = hub_db.create_token(conn, "temp")
        hub_db.revoke_token(conn, "temp")
        conn.close()
        self.assertEqual(self.post(self.bundle(), token=token)[0], 401)


class TriageTests(HubServerCase):
    fields = {"host": "1", "collector": "claude", "key": "a.one", "state": "acknowledged", "note": "seen"}

    def test_triage_needs_the_csrf_token(self):
        status, _, _ = self.form("/findings/triage", self.fields)
        self.assertEqual(status, 403)
        status, _, _ = self.form("/findings/triage", {**self.fields, "csrf": "wrong"})
        self.assertEqual(status, 403)

    def test_triage_refuses_another_origin(self):
        fields = {**self.fields, "csrf": self.config.csrf_token()}
        status, _, _ = self.form("/findings/triage", fields, headers={"Origin": "http://evil.example"})
        self.assertEqual(status, 403)

    def test_triage_needs_a_session(self):
        fields = {**self.fields, "csrf": self.config.csrf_token()}
        self.assertEqual(self.form("/findings/triage", fields, cookie=False)[0], 403)

    def test_triage_saves(self):
        fields = {**self.fields, "csrf": self.config.csrf_token()}
        origin = {"Origin": f"http://{self.host_header}"}
        status, headers, _ = self.form("/findings/triage", fields, headers=origin)
        self.assertEqual(status, 303)
        self.assertTrue(headers["Location"].startswith("/finding?"))
        _, _, body = self.request("GET", headers["Location"])
        self.assertIn("seen", body)
        status, _, _ = self.form("/findings/triage", {**fields, "state": "made_up"}, headers=origin)
        self.assertEqual(status, 400)


if __name__ == "__main__":
    unittest.main()
