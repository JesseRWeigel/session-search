"""Parsing: does a turn get the kind it deserves.

Every assertion here is paired with a control that must go the other way, because a
classifier that returns the same answer for everything passes any one-sided test.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import fixture_support as fs                            # noqa: E402
from sessionsearch import parse                         # noqa: E402


def kinds_of(con, session_prefix):
    rows = con.execute(
        "SELECT turns.kind, turns.tool, turns.target, turns.text FROM turns"
        " JOIN sessions ON sessions.rowid = turns.session"
        " WHERE sessions.session_id LIKE ? ORDER BY turns.seq",
        (session_prefix + "%",)).fetchall()
    return rows


class TestKinds(unittest.TestCase):
    def setUp(self):
        self.con = fs.con("planted")

    def test_user_text_is_a_request_and_tool_output_is_not(self):
        rows = kinds_of(self.con, "aa11bb22-0000-4000-8000-000000000001")
        first = rows[0]
        self.assertEqual(first["kind"], "user_request")
        self.assertIn("CRLF", first["text"])
        # Control: the same session's Read result must NOT be a user request.
        reads = [r for r in rows if r["tool"] == "Read"]
        self.assertTrue(reads)
        self.assertNotEqual(reads[0]["kind"], "user_request")

    def test_is_error_result_becomes_kind_error(self):
        rows = kinds_of(self.con, "aa11bb22-0000-4000-8000-000000000001")
        errors = [r for r in rows if r["kind"] == "error"]
        self.assertEqual(len(errors), 1)
        self.assertIn("expected 3 rows", errors[0]["text"])
        # Control: the passing test run in the same session is a plain tool_output.
        passing = [r for r in rows if "3 passed" in r["text"]]
        self.assertEqual(len(passing), 1)
        self.assertEqual(passing[0]["kind"], "tool_output")

    def test_tool_input_carries_a_target(self):
        rows = kinds_of(self.con, "aa11bb22-0000-4000-8000-000000000001")
        inputs = [r for r in rows if r["kind"] == "tool_input"]
        self.assertTrue(any(r["target"].endswith("importer.py") for r in inputs))
        # Control: no non-tool turn has a target.
        self.assertTrue(all(not r["target"] for r in rows if r["kind"] != "tool_input"))

    def test_meta_is_kept_out_of_ordinary_results(self):
        rows = kinds_of(self.con, "aa11bb22-0000-4000-8000-000000000004")
        self.assertIn("meta", [r["kind"] for r in rows])
        got = self.con.execute(
            "SELECT COUNT(*) FROM turns WHERE kind='meta'").fetchone()[0]
        self.assertGreater(got, 0)

    def test_thinking_is_its_own_kind(self):
        rows = kinds_of(self.con, "aa11bb22-0000-4000-8000-000000000001")
        self.assertIn("thinking", [r["kind"] for r in rows])
        self.assertNotIn("thinking", [r["kind"] for r in
                                      kinds_of(self.con, "aa11bb22-0000-4000-8000-000000000004")])


class TestErrorHeuristic(unittest.TestCase):
    """The unflagged-failure heuristic, and what it must not claim."""

    def check(self, text, expected):
        self.assertEqual(parse._kind_for_result(text, False), expected)

    def test_traceback_and_friends_are_errors(self):
        self.check("Traceback (most recent call last):\n  File x", "error")
        self.check("ValueError: bad input", "error")
        self.check("npm ERR! code E404", "error")
        self.check("fatal: not a git repository", "error")

    def test_ordinary_output_is_not(self):
        self.check("3 passed in 0.04s", "tool_output")
        self.check("total 12\ndrwxr-xr-x 2 user user 4096 Jan 1 stuff", "tool_output")
        # The word appears, but only past the window the heuristic reads, so a long log
        # that mentions an error at the end is not reclassified.
        self.check("ok\n" * 300 + "ValueError: late", "tool_output")

    def test_flagged_results_are_errors_regardless_of_text(self):
        self.assertEqual(parse._kind_for_result("all good", True), "error")


class TestCodex(unittest.TestCase):
    def setUp(self):
        self.con = fs.con("planted")

    def test_codex_session_parsed_with_project_and_kinds(self):
        rows = self.con.execute(
            "SELECT source, project, turns FROM sessions WHERE source='codex'").fetchall()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["project"], "/tmp/demo/graphics")
        kinds = [r["kind"] for r in kinds_of(self.con, "cc33dd44")]
        self.assertEqual(kinds, ["user_request", "thinking", "tool_input",
                                 "tool_output", "assistant_text"])

    def test_event_msg_duplicate_is_not_indexed_twice(self):
        rows = kinds_of(self.con, "cc33dd44")
        texts = [r["text"] for r in rows if r["kind"] == "assistant_text"]
        self.assertEqual(len(texts), 1, "event_msg duplicated the assistant turn")
        # Control: the fixture really does contain the duplicate, so the assertion above
        # is testing the parser and not an empty file.
        raw = fs.read(_codex_file())
        self.assertIn('"agent_message"', raw)

    def test_encrypted_reasoning_blob_is_not_indexed(self):
        rows = kinds_of(self.con, "cc33dd44")
        thinking = [r for r in rows if r["kind"] == "thinking"][0]
        self.assertIn("shortest-arc", thinking["text"])
        self.assertLess(len(thinking["text"]), 200)
        raw = fs.read(_codex_file())
        self.assertIn("encrypted_content", raw)


def _codex_file():
    base = os.path.join(fs.archive_path("planted"), "codex-sessions", "2026", "06", "14")
    return os.path.join(base, os.listdir(base)[0])


class TestPromptHistory(unittest.TestCase):
    def setUp(self):
        self.con = fs.con("planted")

    def test_session_without_a_transcript_is_recovered(self):
        row = self.con.execute(
            "SELECT source, turns FROM sessions WHERE session_id LIKE 'ee55ff66%'"
        ).fetchone()
        self.assertIsNotNone(row)
        self.assertEqual(row["source"], "claude_prompts")

    def test_session_with_a_transcript_is_not_duplicated(self):
        n = self.con.execute(
            "SELECT COUNT(*) FROM sessions WHERE session_id LIKE 'aa11bb22-0000-4000-8000-000000000001%'"
        ).fetchone()[0]
        self.assertEqual(n, 1, "the prompt-history copy was indexed as a second session")
        # Control: prompt history really does mention that session id.
        hist = fs.read(os.path.join(fs.archive_path("planted"), "claude-history.jsonl"))
        self.assertIn("aa11bb22-0000-4000-8000-000000000001", hist)


class TestTruncation(unittest.TestCase):
    def test_long_turns_are_clipped_and_say_so(self):
        text = "x" * (parse.MAX_TEXT + 500)
        clipped, trunc, orig = parse._clip(text)
        self.assertTrue(trunc)
        self.assertEqual(orig, parse.MAX_TEXT + 500)
        self.assertEqual(len(clipped), parse.MAX_TEXT)
        # Control: a short turn is not marked truncated.
        clipped, trunc, orig = parse._clip("short")
        self.assertFalse(trunc)
        self.assertEqual(clipped, "short")


if __name__ == "__main__":
    unittest.main()
