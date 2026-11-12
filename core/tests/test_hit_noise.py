"""Listed secret hits leave out matches that are plainly not credentials.

Every case here came from a real scan: message ids, commit ids, encrypted
reasoning blobs, placeholder connection strings, and the words "Authorization:
Bearer" with nothing after them. Masking still covers all of them.
"""

from __future__ import annotations

import os
import unittest

os.environ["USERPROFILE"] = r"C:\Users\Test User"
os.environ["APPDATA"] = r"C:\Users\Test User\AppData\Roaming"

import bootstrap  # noqa: E402,F401
from common import mask_secrets, secret_spans, shannon_entropy  # noqa: E402

HEX32 = "9f2c4e6a8b0d1f3a5c7e9b1d3f5a7c9e"
HEX40 = "3f2b9c1d4e5a6b7c8d9e" * 2
HEX64 = HEX32 * 2
B64 = "Zx9Yw8Vu7Ts6Rq5Po4Nm3Lk2Ji1Hg0FeDc"
TOKEN = "eyJhbGciOiJIUzI1NiJ9a8Kq2"


def kinds(text: str) -> list[str]:
    return [kind for kind, _s, _e in secret_spans(text)]


class TestNotListed(unittest.TestCase):
    def test_vendor_object_ids(self):
        for prefix in ("rs_", "fc_", "msg_", "resp_", "ctc_", "ws_", "toolu_"):
            self.assertEqual(kinds(f'"id":"{prefix}{HEX40}"'), [], prefix)

    def test_hashes_and_commit_ids_named_by_their_key_or_context(self):
        self.assertEqual(kinds(f'"shapeHash":"{HEX64}"'), [])
        self.assertEqual(kinds(f'"requestDigest": "{HEX64}"'), [])
        self.assertEqual(kinds(f"commit {HEX40}"), [])
        self.assertEqual(kinds(f"\\ncommit {HEX40}\\nAuthor: x"), [])
        self.assertEqual(kinds(f"sha256: {HEX64}"), [])
        self.assertEqual(kinds(f'"tail":["{HEX64}","{HEX64}"]'), [])
        self.assertEqual(kinds(f"C__Users_me_code_{HEX32}"), [])

    def test_encrypted_blobs_and_signatures(self):
        self.assertEqual(kinds(f'"encrypted_content":"{B64}{B64}"'), [])
        self.assertEqual(kinds(f'"signature": "{B64}"'), [])

    def test_paths_alphabets_and_low_entropy_runs(self):
        self.assertEqual(kinds("openxmlformats/officedocument/2006/relationships/styles"), [])
        self.assertEqual(kinds("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"), [])
        self.assertEqual(kinds("aaaaaaaa11111111bbbbbbbb22222222cccc"), [])
        self.assertLess(shannon_entropy("aaaaaaaa11111111bbbbbbbb22222222cccc"), 4.0)
        self.assertGreater(shannon_entropy(B64), 4.0)

    def test_authorization_without_a_real_token(self):
        for text in (
            "Authorization: Bearer",
            "Authorization: Bearer ${TOKEN}",
            "Authorization: Bearer <your-token>",
            "Authorization: Bearer token",
            "set the Authorization: header to the key",
            "Bearer authentication is required",
            "Bearer token",
        ):
            self.assertEqual(kinds(text), [], text)

    def test_placeholder_passwords_and_connection_strings(self):
        for text in (
            "password=changeme",
            "password=${DB_PASSWORD}",
            "password=<password>",
            "password=%s",
            "postgres://${POSTGRES_USER}:${POSTGRES_PASSWORD}@postgres:5432/app",
            "postgresql://user:password@localhost:5432/app",
            "postgresql+asyncpg://postgres:postgres@127.0.0.1:5432/app",
            "https://git@github.com/acme/repo.git",
        ):
            self.assertEqual(kinds(text), [], text)


class TestStillListed(unittest.TestCase):
    def test_real_shapes_survive(self):
        self.assertEqual(kinds(f"SESSION_SECRET={HEX64}"), ["hex_secret"])
        self.assertEqual(kinds(f'"api_token": "{B64}"'), ["generic_secret"])
        self.assertEqual(kinds(f"Authorization: Bearer {TOKEN}"), ["authorization"])
        self.assertEqual(kinds(f"curl -H 'X-Auth: Bearer {TOKEN}'"), ["bearer"])
        self.assertEqual(kinds("password=Tr0ub4dor&3"), ["password_assign"])
        self.assertEqual(kinds("postgres://app:Sup3rS3cret!@db.internal.test:5432/billing"), ["url_userinfo"])
        self.assertEqual(kinds("postgresql://app:Sup3rS3cret9@localhost:5432/billing"), ["url_userinfo"])

    def test_a_rejected_match_is_not_reported_by_a_looser_pattern(self):
        # The commit id is dropped as hex. It must not come back as generic.
        self.assertEqual(kinds(f"commit {HEX40}"), [])

    def test_masking_is_unchanged_for_everything_the_list_drops(self):
        for text in (f'"id":"rs_{HEX40}"', f"commit {HEX40}", "password=changeme", "Bearer token-value-1"):
            self.assertIn("REDACTED", mask_secrets(text), text)


if __name__ == "__main__":
    unittest.main()
