"""Redaction, checked from both sides.

Positive: each category is masked. Negative: ordinary text that merely resembles a secret
survives, because a redactor that masks everything is trivially safe and useless, and its
uselessness would not show up in a one-sided test.

The credential-shaped inputs are assembled at run time from `make_fixtures.fill`, so this
file contains no complete credential pattern. GitHub push protection scans full history
and rejects a fake key as readily as a real one.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                                "scripts"))

from make_fixtures import fill, UPPER                   # noqa: E402
from sessionsearch import redact                        # noqa: E402


class TestCategories(unittest.TestCase):
    def assertMasked(self, text, label=None):
        out = redact.redact(text)
        self.assertNotIn(text.strip(), out, f"unmasked: {text[:20]}…")
        self.assertIn("[redacted:", out)
        if label:
            self.assertIn(label, out)

    def test_provider_tokens(self):
        cases = [
            ("sk-ant-api03-" + fill("a", 64), "anthropic-key"),
            ("sk-or-v1-" + fill("b", 64), "openrouter-key"),
            ("sk-" + fill("c", 48), "openai-key"),
            ("ghp_" + fill("d", 36), "github-token"),
            ("github_pat_" + fill("e", 60), "github-token"),
            ("AKIA" + fill("f", 16, UPPER), "aws-access-key-id"),
            ("AIza" + fill("g", 35), "google-api-key"),
            ("xoxb-" + fill("h", 30), "slack-token"),
            ("hf_" + fill("i", 34), "huggingface-token"),
            ("glpat-" + fill("j", 20), "gitlab-token"),
            ("sk_live_" + fill("k", 24), "stripe-key"),
            ("eyJ" + fill("l", 20) + ".eyJ" + fill("m", 30) + "." + fill("n", 43), "jwt"),
        ]
        for text, label in cases:
            with self.subTest(label=label):
                self.assertMasked(text, label)

    def test_private_key_block(self):
        block = ("-----BEGIN RSA PRIVATE KEY-----\n" + fill("pk", 200)
                 + "\n-----END RSA PRIVATE KEY-----")
        out = redact.redact(block)
        self.assertNotIn("BEGIN RSA PRIVATE KEY", out)
        self.assertIn("[redacted:private-key]", out)

    def test_url_credentials(self):
        out = redact.redact("postgres://admin:hunter2hunter2@db.example.com/app")
        self.assertNotIn("hunter2hunter2", out)
        self.assertIn("[redacted:url-credentials]", out)

    def test_secret_assignment_by_key_name(self):
        out = redact.redact("MYSTERY_TOKEN=correcthorsebatterystaple")
        self.assertNotIn("correcthorsebatterystaple", out)
        # Control: the same value under a harmless key name is left alone, so the rule is
        # keyed on the name and is not just masking every long word.
        keep = redact.redact("COMMIT_MESSAGE=correcthorsebatterystaple")
        self.assertIn("correcthorsebatterystaple", keep)

    def test_addresses_and_home_paths(self):
        out = redact.redact("mail someone@example.org about " + os.path.join("/home", "bob", "src"))
        self.assertNotIn("someone@example.org", out)
        self.assertNotIn("bob", out)
        self.assertIn("~/src", out)

    def test_private_networks_but_not_loopback(self):
        out = redact.redact("hosts: 10.1.2.3, 192.168.0.9, nas.local, 127.0.0.1, 8.8.8.8")
        self.assertNotIn("10.1.2.3", out)
        self.assertNotIn("192.168.0.9", out)
        self.assertNotIn("nas.local", out)
        # Control: loopback and a public resolver stay readable on purpose.
        self.assertIn("127.0.0.1", out)
        self.assertIn("8.8.8.8", out)

    def test_control_bytes_are_escaped(self):
        out = redact.redact("before\x00after\x1bmore\ttab\nline")
        self.assertNotIn("\x00", out)
        self.assertNotIn("\x1b", out)
        self.assertIn("\\0", out)
        # Control: tab and newline are ordinary text and must survive.
        self.assertIn("\t", out)
        self.assertIn("\n", out)


class TestFalsePositives(unittest.TestCase):
    """What must NOT be destroyed, or the excerpts stop being readable."""

    KEEP = [
        "def load(text): return [l.split(',') for l in text.split('\\n')]",
        "the CSV importer chokes on CRLF line endings",
        "src/components/UserProfile2/index.tsx",
        "npm install --no-save playwright-core",
        "https://github.com/example/repo/pull/1234",
        "2026-08-01T12:34:56.789Z",
        "Traceback (most recent call last): ZeroDivisionError",
    ]

    def test_ordinary_text_is_untouched(self):
        for text in self.KEEP:
            with self.subTest(text=text[:30]):
                self.assertEqual(redact.redact(text), text)

    def test_a_deep_path_is_not_mistaken_for_base64(self):
        p = "Projects/thousand/projects/sessionsearch2/indexer"
        self.assertEqual(redact.redact(p), p)
        # Control: base64 of the same length IS masked, so the discrimination is real
        # rather than the rule being switched off.
        blob = fill("b64", 48)
        self.assertIn("[redacted:", redact.redact(blob))


class TestSelfCheck(unittest.TestCase):
    def test_self_check_passes_normally(self):
        self.assertTrue(redact.self_check())

    def test_self_check_notices_an_empty_rule_table(self):
        saved_rules, saved_home = redact._RULES, redact._HOME_RULES
        try:
            redact._RULES = []
            redact._HOME_RULES = []
            self.assertFalse(redact.self_check())
        finally:
            redact._RULES, redact._HOME_RULES = saved_rules, saved_home
        self.assertTrue(redact.self_check())


class TestCounts(unittest.TestCase):
    def test_counts_report_what_was_removed_without_showing_it(self):
        counts = {}
        redact.redact("AKIA" + fill("z", 16, UPPER) + " and a@b.com", counts)
        self.assertEqual(counts.get("aws-access-key-id"), 1)
        self.assertEqual(counts.get("address"), 1)
        # Control: clean text records nothing.
        counts2 = {}
        redact.redact("nothing to see here", counts2)
        self.assertEqual(counts2, {})


if __name__ == "__main__":
    unittest.main()
