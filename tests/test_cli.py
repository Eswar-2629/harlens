import contextlib
import io
import json
import os
import unittest

from harlens.cli import main
from helpers import entry, har, write_tmp

SAMPLES = os.path.join(os.path.dirname(__file__), "..", "samples")


def run(*argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try:
            code = main(list(argv))
        except SystemExit as exc:
            code = exc.code
    return code, out.getvalue(), err.getvalue()


class CliTests(unittest.TestCase):
    def test_json_output_on_sample(self):
        code, out, _ = run("audit", os.path.join(SAMPLES, "insecure-shop.har"), "--format", "json")
        data = json.loads(out)
        self.assertEqual(code, 0)
        self.assertGreater(data["summary"]["high"], 0)
        self.assertNotIn("demo_not_a_real_key_12345", out)

    def test_fail_on_threshold(self):
        bad = os.path.join(SAMPLES, "insecure-shop.har")
        good = os.path.join(SAMPLES, "well-configured.har")
        self.assertEqual(run("audit", bad, "--fail-on", "high")[0], 1)
        self.assertEqual(run("audit", good, "--fail-on", "low")[0], 0)

    def test_html_report_is_escaped(self):
        path = write_tmp(self, har(entry("https://a.example.com/<script>alert(1)</script>", mime="application/json",
                                         resp=[("Server", "evil/1.0 <img src=x onerror=alert(1)>")])))
        code, out, _ = run("audit", path, "--format", "html")
        self.assertEqual(code, 0)
        self.assertNotIn("<script>alert", out)
        self.assertNotIn("<img src=x", out)
        self.assertIn("&lt;img", out)

    def test_html_empty_state(self):
        _, out, _ = run("audit", os.path.join(SAMPLES, "well-configured.har"), "--format", "html")
        self.assertIn("No findings", out)

    def test_output_file(self):
        target = write_tmp(self, "")
        code, out, _ = run("audit", os.path.join(SAMPLES, "insecure-shop.har"), "-o", target)
        self.assertEqual((code, out), (0, ""))
        with open(target, encoding="utf-8") as fh:
            self.assertIn("HARLens audit", fh.read())

    def test_bad_input_exits_2_with_message(self):
        code, _, err = run("audit", "/nonexistent.har")
        self.assertEqual(code, 2)
        self.assertIn("harlens: error:", err)
        self.assertEqual(run("audit", write_tmp(self, "{", raw=True))[0], 2)

    def test_unwritable_output_exits_2(self):
        code, _, err = run("audit", os.path.join(SAMPLES, "insecure-shop.har"), "-o", "/nonexistent-dir/r.txt")
        self.assertEqual(code, 2)
        self.assertIn("Cannot write", err)

    def test_sanitize_roundtrip(self):
        src = write_tmp(self, har(entry("https://a.example.com/x?token=SECRETVALUE1", req={"Cookie": "a=SECRETVALUE2"})))
        dst = write_tmp(self, "")
        code, _, err = run("sanitize", src, "-o", dst)
        self.assertEqual(code, 0)
        self.assertIn("redactions", err)
        with open(dst, encoding="utf-8") as fh:
            text = fh.read()
        self.assertNotIn("SECRETVALUE", text)
        json.loads(text)

    def test_sanitize_refuses_to_overwrite_input(self):
        src = write_tmp(self, har(entry("https://a.example.com/")))
        code, _, err = run("sanitize", src, "-o", src)
        self.assertEqual(code, 2)
        self.assertIn("never overwritten", err)

    def test_no_command_is_usage_error(self):
        self.assertEqual(run()[0], 2)


if __name__ == "__main__":
    unittest.main()
