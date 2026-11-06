import json
import unittest

from harlens.har import HarError, load_har, parse_har
from harlens.redact import REDACTED, looks_sensitive, mask, redact_url, sanitize_har
from helpers import entry, har, write_tmp


class LoadTests(unittest.TestCase):
    def test_valid_file(self):
        entries, skipped = load_har(write_tmp(self, har(entry("https://a.example.com/"))))
        self.assertEqual((len(entries), skipped), (1, 0))

    def test_errors_are_friendly(self):
        cases = {
            "missing": "/nonexistent/file.har",
            "empty": write_tmp(self, "", raw=True),
            "not json": write_tmp(self, "{oops", raw=True),
            "not har": write_tmp(self, {"hello": 1}),
            "no entries": write_tmp(self, {"log": {"entries": []}}),
            "no usable entries": write_tmp(self, {"log": {"entries": [{}, 5, {"request": {"url": ""}}]}}),
        }
        for label, path in cases.items():
            with self.subTest(label), self.assertRaises(HarError):
                load_har(path)

    def test_bad_entries_are_skipped_not_fatal(self):
        entries, skipped = parse_har({"log": {"entries": [entry("https://a.example.com/"), None, {"request": {"url": "nope"}}]}})
        self.assertEqual((len(entries), skipped), (1, 2))


class RedactTests(unittest.TestCase):
    def test_looks_sensitive(self):
        for name in ("token", "access_token", "api-key", "apiKey", "password", "sessionid", "X-Auth"):
            self.assertTrue(looks_sensitive(name), name)
        for name in ("author", "page", "tokenize", "inside", ""):
            self.assertFalse(looks_sensitive(name), name)

    def test_mask_never_reveals_everything(self):
        self.assertEqual(mask("abc"), "***")
        self.assertNotIn("abcdefghij", mask("abcdefghijklmnop"))
        self.assertEqual(mask(""), "")

    def test_redact_url(self):
        self.assertEqual(redact_url("https://u:p@a.example.com:8443/x?token=abc&q=1#frag"),
                         "https://a.example.com:8443/x?token=REDACTED&q=1")
        self.assertEqual(redact_url("http://[::1]:99/"), "http://[::1]:99/")

    def test_sanitize_removes_secrets_without_touching_input(self):
        original = har(entry("https://a.example.com/x?token=SECRET1&q=ok", method="POST", mime="application/json",
                             req={"Authorization": "Bearer SECRET2", "Accept": "*/*"},
                             resp=[("Set-Cookie", "sid=SECRET3")],
                             post={"mimeType": "application/json", "text": '{"password": "SECRET4", "name": "ann"}'}))
        original["log"]["entries"][0]["response"]["content"]["text"] = '{"access_token": "SECRET5", "ok": true}'
        before = json.dumps(original)
        clean, count = sanitize_har(original)
        self.assertEqual(json.dumps(original), before)
        dump = json.dumps(clean)
        for i in range(1, 6):
            self.assertNotIn(f"SECRET{i}", dump)
        self.assertIn("q=ok", dump)
        self.assertIn("ann", dump)
        self.assertIn("*/*", dump)
        self.assertIn(REDACTED, dump)
        self.assertGreaterEqual(count, 5)

    def test_sanitized_file_gives_same_audit_as_original(self):
        from harlens.checks import run_checks
        original = har(entry("https://a.example.com/", resp=[("Set-Cookie", "sessionid=SECRETVALUE; Path=/")],
                             req={"Cookie": "sessionid=SECRETVALUE; theme=dark"}))
        clean, _ = sanitize_har(original)
        text = json.dumps(clean)
        self.assertNotIn("SECRETVALUE", text)
        self.assertIn("sessionid=[REDACTED]; Path=/", text)
        self.assertIn("sessionid=[REDACTED]; theme=[REDACTED]", text)
        key = lambda d: sorted((f.rule, f.title) for f in run_checks(parse_har(d)[0]))
        self.assertEqual(key(clean), key(original))


if __name__ == "__main__":
    unittest.main()
