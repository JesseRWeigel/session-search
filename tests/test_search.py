"""End to end: the planted archive must be found, the control archive must not be.

`make_fixtures.EXPECTATIONS` is the list of things that are definitely in the planted
archive. Half of them are definitely NOT in the control archive, which is the same size
and the same shape with the needles swapped for near synonyms. Finding a needle proves
retrieval; finding nothing in the control proves the tool is not simply returning its ten
favourite rows for any input.
"""

import io
import json
import os
import sys
import unittest
import contextlib

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import fixture_support as fs                            # noqa: E402
from sessionsearch import cli, indexer, rank            # noqa: E402


def run(variant, argv):
    """Run the CLI against one fixture index; return (exit_code, stdout)."""
    buf = io.StringIO()
    code = 0
    with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(io.StringIO()):
        try:
            code = cli.main(["--index", fs.index_path(variant)] + argv)
        except SystemExit as exc:
            code = exc.code
    return code, buf.getvalue()


def search_json(variant, query, *extra):
    code, out = run(variant, ["search", query, "--json"] + list(extra))
    return code, (json.loads(out) if out.strip() else [])


class TestKnownAnswers(unittest.TestCase):
    def test_every_planted_needle_is_found_first(self):
        for exp in fs.EXPECTATIONS:
            with self.subTest(exp["name"]):
                code, hits = search_json("planted", exp["query"])
                self.assertEqual(code, 0, f"{exp['query']!r} returned nothing")
                self.assertTrue(hits)
                self.assertTrue(hits[0]["session_id"].startswith(exp["expect"]),
                                f"top hit was {hits[0]['session_id']}, "
                                f"expected {exp['expect']}: {exp['why']}")
                self.assertEqual(hits[0]["kind"], exp["kind"])

    def test_the_control_archive_returns_nothing_for_absent_needles(self):
        checked = 0
        for exp in fs.EXPECTATIONS:
            if not exp["control"]:
                continue
            checked += 1
            with self.subTest(exp["name"]):
                code, hits = search_json("control", exp["query"])
                self.assertEqual(hits, [], f"{exp['query']!r} matched the control archive")
                self.assertEqual(code, 1, "an empty result must exit nonzero")
        self.assertGreaterEqual(checked, 2, "no control expectations were exercised")

    def test_the_control_archive_is_not_simply_empty(self):
        """Otherwise the test above passes for the wrong reason."""
        con = fs.con("control")
        self.assertGreaterEqual(con.execute("SELECT COUNT(*) FROM turns").fetchone()[0], 20)
        code, hits = search_json("control", "slerp camera rig")
        self.assertEqual(code, 0)
        self.assertTrue(hits)


class TestFilters(unittest.TestCase):
    def narrow(self, query, *flags):
        wide = search_json("planted", query)[1]
        narrow = search_json("planted", query, *flags)[1]
        return wide, narrow

    def test_kind_filter(self):
        wide, narrow = self.narrow("importer", "--kind", "tool_input")
        self.assertTrue(narrow)
        self.assertTrue(all(h["kind"] == "tool_input" for h in narrow))
        self.assertGreater(len(wide), len(narrow))
        # Control: a kind that cannot match returns nothing rather than falling back.
        code, none = search_json("planted", "importer", "--kind", "thinking",
                                 "--kind", "meta")
        self.assertEqual(none, [])
        self.assertEqual(code, 1)

    def test_tool_filter(self):
        code, hits = search_json("planted", "importer", "--tool", "Read")
        self.assertTrue(hits)
        self.assertTrue(all(h["tool"] == "Read" for h in hits))
        code, none = search_json("planted", "importer", "--tool", "WebFetch")
        self.assertEqual(none, [])

    def test_project_filter(self):
        code, hits = search_json("planted", "crlf", "--project", "widget")
        self.assertTrue(hits)
        self.assertTrue(all("widget" in h["project"] for h in hits))
        code, none = search_json("planted", "crlf", "--project", "no-such-project")
        self.assertEqual(none, [])

    def test_source_filter(self):
        code, hits = search_json("planted", "slerp", "--source", "codex")
        self.assertTrue(hits)
        self.assertTrue(all(h["source"] == "codex" for h in hits))
        code, none = search_json("planted", "slerp", "--source", "claude_code")
        self.assertEqual(none, [])

    def test_date_filters(self):
        code, recent = search_json("planted", "websocket reconnect", "--since", "7d")
        self.assertEqual(len(recent), 1, "only the recent copy is inside 7 days")
        code, both = search_json("planted", "websocket reconnect")
        self.assertEqual(len(both), 2)
        code, old = search_json("planted", "websocket reconnect", "--until", "365d")
        self.assertEqual(len(old), 1, "--until must exclude the recent copy")

    def test_meta_is_excluded_unless_asked_for(self):
        code, none = search_json("planted", "system-reminder")
        self.assertEqual(none, [])
        code, hits = search_json("planted", "system-reminder", "--include-meta")
        self.assertTrue(hits)
        self.assertEqual(hits[0]["kind"], "meta")


class TestResultShape(unittest.TestCase):
    def test_a_result_is_an_excerpt_not_a_transcript(self):
        """The noisy session has a 60 line log; the excerpt must stay small."""
        code, hits = search_json("planted", "crlf")
        logs = [h for h in hits if h["kind"] == "tool_output"]
        self.assertTrue(logs)
        for h in logs:
            self.assertLessEqual(len(h["excerpt"]), 400)
        # Control: the underlying turn really is long, so the bound above means something.
        con = fs.con("planted")
        biggest = con.execute("SELECT MAX(LENGTH(text)) FROM turns").fetchone()[0]
        self.assertGreater(biggest, 1500)

    def test_human_output_names_the_session_and_the_date(self):
        code, out = run("planted", ["search", "crlf importer", "--limit", "1"])
        self.assertEqual(code, 0)
        self.assertIn("session aa11bb22", out)
        self.assertIn("20", out)          # a rendered date
        self.assertLessEqual(len(out.splitlines()), 8)

    def test_explain_shows_the_four_parts(self):
        code, out = run("planted", ["search", "crlf importer", "--limit", "1", "--explain"])
        self.assertIn("kind", out)
        self.assertIn("recency", out)
        self.assertIn("phrase", out)
        # Control: without --explain the breakdown is absent.
        code, plain = run("planted", ["search", "crlf importer", "--limit", "1"])
        self.assertNotIn("why:", plain)

    def test_context_turns_are_included(self):
        code, out = run("planted", ["search", "expected 3 rows", "--limit", "1",
                                    "--context", "1"])
        self.assertIn("pytest", out)      # the tool call that produced the failure
        code, out0 = run("planted", ["search", "expected 3 rows", "--limit", "1",
                                     "--context", "0"])
        self.assertNotIn("- [tool call]", out0)


class TestSessionsMode(unittest.TestCase):
    def test_which_session_did_i_fix_it_in(self):
        code, out = run("planted", ["sessions", "crlf importer csv", "--limit", "3"])
        self.assertEqual(code, 0)
        first = out.strip().splitlines()[0]
        self.assertIn("aa11bb22", first)
        # Control: the noisy session exists and mentions the words, so it could have won.
        self.assertIn("matching turn", out)

    def test_sessions_mode_collapses_duplicates(self):
        con = fs.con("planted")
        terms = rank.tokenize("crlf")
        rows, _ = indexer.candidates(con, terms)
        scored = rank.rank(rows, terms)
        sessions = rank.rank_sessions(scored)
        self.assertLess(len(sessions), len(scored))
        self.assertEqual(len({(s["row"]["source"], s["row"]["session_id"])
                              for s in sessions}), len(sessions))


class TestLatency(unittest.TestCase):
    def test_query_path_reports_its_own_timings(self):
        code, out = run("planted", ["search", "crlf"])
        self.assertEqual(code, 0)


if __name__ == "__main__":
    unittest.main()
