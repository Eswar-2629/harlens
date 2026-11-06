import unittest

from harlens.checks import run_checks, summarize
from harlens.har import parse_har
from helpers import entry, har

FULL = [("Content-Security-Policy", "default-src 'self'; frame-ancestors 'self'"),
        ("X-Content-Type-Options", "nosniff"), ("Referrer-Policy", "no-referrer"),
        ("Strict-Transport-Security", "max-age=31536000")]


def audit(*entries):
    return run_checks(parse_har(har(*entries))[0])


def titles(findings):
    return [f.title for f in findings]


class HeaderTests(unittest.TestCase):
    def test_bare_https_page_flags_every_header(self):
        t = titles(audit(entry("https://a.example.com/")))
        for expected in ("Missing Content-Security-Policy", "No clickjacking protection",
                         "Missing X-Content-Type-Options: nosniff", "Missing Referrer-Policy",
                         "Missing Strict-Transport-Security"):
            self.assertIn(expected, t)

    def test_fully_configured_page_is_clean(self):
        self.assertEqual(audit(entry("https://a.example.com/", resp=FULL)), [])

    def test_short_hsts_is_low(self):
        resp = [h for h in FULL if h[0] != "Strict-Transport-Security"] + [("Strict-Transport-Security", "max-age=60")]
        found = audit(entry("https://a.example.com/", resp=resp))
        self.assertEqual(titles(found), ["Short Strict-Transport-Security lifetime"])

    def test_localhost_and_non_documents_are_exempt(self):
        self.assertNotIn("Missing Strict-Transport-Security", titles(audit(entry("https://localhost/", resp=FULL[:3]))))
        self.assertEqual(audit(entry("https://a.example.com/x.json", mime="application/json")), [])

    def test_reported_once_per_origin(self):
        found = audit(entry("https://a.example.com/"), entry("https://a.example.com/b"))
        self.assertEqual(len([f for f in found if f.title == "Missing Content-Security-Policy"]), 1)


class CookieTests(unittest.TestCase):
    def cookie(self, value, url="https://a.example.com/x.json"):
        return titles(audit(entry(url, mime="application/json", resp=[("Set-Cookie", value)])))

    def test_flags_and_severity(self):
        found = audit(entry("https://a.example.com/x.json", mime="application/json",
                            resp=[("Set-Cookie", "sessionid=abc; Path=/")]))
        by_title = {f.title: f.severity for f in found}
        self.assertEqual(by_title["Cookie without HttpOnly flag"], "high")
        self.assertIn("Cookie without Secure flag", by_title)
        self.assertIn("Cookie without SameSite attribute", by_title)

    def test_secure_cookie_is_clean(self):
        self.assertEqual(self.cookie("pref=1; Secure; HttpOnly; SameSite=Lax"), [])

    def test_samesite_none_needs_secure(self):
        self.assertIn("SameSite=None without Secure",
                      self.cookie("a=1; HttpOnly; SameSite=None", url="http://a.example.com/x.json"))

    def test_cookie_value_never_in_findings(self):
        found = audit(entry("https://a.example.com/x.json", mime="application/json",
                            resp=[("Set-Cookie", "sessionid=TOPSECRETVALUE")]))
        self.assertNotIn("TOPSECRETVALUE", repr([f.to_dict() for f in found]))


class NetworkRuleTests(unittest.TestCase):
    def test_mixed_content_active_vs_passive(self):
        found = audit(entry("https://a.example.com/", resp=FULL),
                      entry("http://c.example.com/a.js", mime="application/javascript"),
                      entry("http://c.example.com/a.png", mime="image/png"))
        sev = {f.url.rsplit("/", 1)[1]: f.severity for f in found if f.rule == "HL003"}
        self.assertEqual(sev, {"a.js": "high", "a.png": "medium"})

    def test_http_to_https_redirect_is_not_mixed_content(self):
        found = audit(entry("https://a.example.com/", resp=FULL),
                      entry("http://a.example.com/old", status=301, resp=[("Location", "https://a.example.com/new")]))
        self.assertFalse([f for f in found if f.rule == "HL003"])

    def test_no_mixed_content_without_https_page(self):
        self.assertFalse([f for f in audit(entry("http://a.example.com/")) if f.rule == "HL003"])

    def test_secret_in_url_is_masked(self):
        found = audit(entry("https://a.example.com/api?api_key=SUPERSECRETKEY123", mime="application/json"))
        self.assertEqual([f.rule for f in found], ["HL004"])
        dump = repr(found[0].to_dict())
        self.assertNotIn("SUPERSECRETKEY123", dump)
        self.assertIn("api_key=REDACTED", found[0].url)

    def test_credentials_in_url_userinfo(self):
        found = audit(entry("https://bob:hunter2@a.example.com/", mime="application/json"))
        self.assertEqual(found[0].title, "Credentials embedded in URL")
        self.assertNotIn("hunter2", repr(found[0].to_dict()))

    def test_author_param_is_not_flagged(self):
        self.assertEqual(audit(entry("https://a.example.com/p?author=bob&tokenize=1", mime="application/json")), [])

    def test_cleartext_credentials(self):
        found = audit(entry("http://a.example.com/login", method="POST", mime="application/json",
                            req={"Authorization": "Bearer x"},
                            post={"mimeType": "application/json", "text": '{"password": "p"}'}))
        self.assertEqual([f.rule for f in found if f.rule == "HL005"], ["HL005"])

    def test_localhost_http_is_ignored(self):
        self.assertEqual(audit(entry("http://localhost:3000/login", req={"Authorization": "Bearer x"},
                                     mime="application/json")), [])

    def test_cors_rules(self):
        wild = audit(entry("https://a.example.com/d", mime="application/json",
                           resp=[("Access-Control-Allow-Origin", "*"), ("Access-Control-Allow-Credentials", "true")]))
        self.assertEqual(wild[0].severity, "high")
        null = audit(entry("https://a.example.com/d", mime="application/json", resp=[("Access-Control-Allow-Origin", "null")]))
        self.assertEqual(null[0].severity, "medium")
        ok = audit(entry("https://a.example.com/d", mime="application/json", resp=[("Access-Control-Allow-Origin", "*")]))
        self.assertEqual(ok, [])

    def test_disclosure(self):
        found = audit(entry("https://a.example.com/d", mime="application/json", resp=[("Server", "nginx/1.18.0")]))
        self.assertEqual(found[0].rule, "HL007")
        self.assertEqual(audit(entry("https://a.example.com/d", mime="application/json", resp=[("Server", "nginx")])), [])

    def test_summary_counts(self):
        s = summarize(audit(entry("https://a.example.com/")))
        self.assertEqual(sum(s.values()), 5)


if __name__ == "__main__":
    unittest.main()
