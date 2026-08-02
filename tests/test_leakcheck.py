"""The independent checker, tested as a detector in its own right.

Two things must both be true, and neither implies the other:

  1. The checker fires on raw archive content. If it does not, a clean report on redacted
     output means nothing, because the checker was blind rather than the output safe.
  2. The checker does not fire on redacted output.

The NUL tests exist because that byte defeats grep-based scanning silently. This checker
reads bytes in Python and reports the offset.
"""

import io
import os
import subprocess
import sys
import tempfile
import unittest
import contextlib

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "checker"))
sys.path.insert(0, os.path.join(ROOT, "scripts"))

import leakcheck                                        # noqa: E402
import fixture_support as fs                            # noqa: E402
from make_fixtures import fill, UPPER                   # noqa: E402
from sessionsearch import cli, redact                   # noqa: E402


class TestDetector(unittest.TestCase):
    def test_it_fires_on_each_shape(self):
        cases = [
            "sk-ant-api03-" + fill("a", 64),
            "ghp_" + fill("b", 36),
            "AKIA" + fill("c", 16, UPPER),
            "AIza" + fill("d", 35),
            "-----BEGIN RSA PRIVATE KEY-----",
            "postgres://admin:hunter2hunter2@db.example.com/app",
            os.path.join("/home", "someuser", "Projects"),
            "someone@example.org",
            "10.1.2.3",
            "nas.local",
            fill("entropy", 44),
        ]
        for text in cases:
            with self.subTest(text[:16]):
                self.assertTrue(leakcheck.scan_text(text), f"missed {text[:16]}")

    def test_it_stays_quiet_on_ordinary_text(self):
        clean = ["the CSV importer chokes on CRLF line endings",
                 "def load(text): return text.split(',')",
                 "3 passed in 0.04s",
                 "session aa11bb22  claude_code  2d ago  seq 3",
                 "[redacted:anthropic-key] and [redacted:high-entropy]",
                 "https://github.com/example/repo/pull/1234"]
        for text in clean:
            with self.subTest(text[:24]):
                self.assertEqual(leakcheck.scan_text(text), [], text)

    def test_mask_is_recognised_only_in_its_exact_form(self):
        self.assertEqual(leakcheck.scan_text("[redacted:aws-access-key-id]"), [])
        # Control: writing the word does not disarm the checker.
        self.assertTrue(leakcheck.scan_text("redacted AKIA" + fill("x", 16, UPPER)))


class TestNul(unittest.TestCase):
    def test_nul_is_found_by_offset(self):
        data = b"header\x00trailer"
        self.assertEqual(leakcheck.scan_bytes_for_nul(data), [6])
        self.assertEqual(leakcheck.scan_bytes_for_nul(b"clean"), [])

    def test_a_secret_hidden_behind_a_nul_is_still_found(self):
        """This is the exact failure that a grep based scan cannot see."""
        with tempfile.NamedTemporaryFile(suffix=".txt", delete=False) as fh:
            fh.write(b"harmless\x00 then ghp_" + fill("nul", 36).encode())
            path = fh.name
        try:
            findings = leakcheck.scan_file(path)
            labels = {f[2] for f in findings}
            self.assertTrue(any("NUL" in x for x in labels))
            self.assertIn("github token", labels)
            # Control: git itself calls this file binary, which is why grep skips it.
            out = subprocess.run(["git", "grep", "-I", "-c", "ghp_", "--no-index", "--",
                                  path], capture_output=True, text=True)
            self.assertNotIn("ghp_", out.stdout)
        finally:
            os.unlink(path)


class TestAgainstTheRealPipeline(unittest.TestCase):
    """Raw fixture archive: dirty. Rendered output from the same data: clean."""

    def test_the_raw_archive_is_full_of_leaks(self):
        arch = fs.archive_path("planted")
        findings = []
        for root, _dirs, files in os.walk(arch):
            for f in files:
                findings += leakcheck.scan_file(os.path.join(root, f))
        self.assertGreater(len(findings), 8,
                           "the fixture archive has nothing to redact, so a clean "
                           "rendered output would prove nothing")

    def test_rendered_output_over_the_same_data_is_clean(self):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(io.StringIO()):
            cli.main(["--index", fs.index_path("planted"), "show",
                      "aa11bb22-0000-4000-8000-000000000003", "--seq", "3",
                      "--span", "9", "--width", "5000"])
        rendered = buf.getvalue()
        self.assertIn("[redacted:", rendered)
        self.assertEqual(leakcheck.scan_text(rendered, "rendered"), [])

    def test_search_output_over_every_fixture_turn_is_clean(self):
        con = fs.con("planted")
        rows = con.execute("SELECT text FROM turns").fetchall()
        for r in rows:
            out = redact.redact(r["text"])
            self.assertEqual(leakcheck.scan_text(out), [], out[:120])


class TestIndependence(unittest.TestCase):
    def test_the_checker_imports_nothing_from_the_redactor(self):
        src = fs.read(os.path.join(ROOT, "checker", "leakcheck.py"))
        self.assertNotIn("import sessionsearch", src)
        self.assertNotIn("from sessionsearch", src)
        self.assertNotIn("import redact", src)

    def test_the_two_files_share_no_regex_source(self):
        a = {p.pattern for _l, p, _g in __import__("sessionsearch.redact",
                                                   fromlist=["x"])._RULES}
        b = {p.pattern for _l, p in leakcheck.SIGNATURES}
        self.assertEqual(a & b, set(), "a shared pattern means a shared blind spot")


if __name__ == "__main__":
    unittest.main()
