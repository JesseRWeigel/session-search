"""The ranking rule. Each component is tested by isolating it and by breaking it.

The pattern throughout: assert the ordering the rule promises, then assert that with the
deciding factor removed the ordering goes away. An ordering test with no control passes
whenever the ranker happens to return things in insertion order.
"""

import os
import sys
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import fixture_support as fs                            # noqa: E402
from sessionsearch import rank                          # noqa: E402

NOW = time.time()
DAY = 86400.0


def row(kind="assistant_text", text="", target="", days_ago=1000, seq=0,
        session_id="s", source="claude_code", last_ts=None):
    return {"kind": kind, "text": text, "target": target, "ts": NOW - days_ago * DAY,
            "seq": seq, "session_id": session_id, "source": source,
            "last_ts": last_ts if last_ts is not None else NOW - days_ago * DAY,
            "project": "", "tool": "", "path": "", "title": "", "truncated": 0,
            "orig_len": 0, "session": 1}


class TestComponents(unittest.TestCase):
    def test_kind_points_are_ordered_as_documented(self):
        order = ["user_request", "error", "assistant_text", "tool_input",
                 "tool_output", "thinking", "meta"]
        pts = [rank.KIND_POINTS[k] for k in order]
        self.assertEqual(pts, sorted(pts, reverse=True))
        self.assertEqual(rank.KIND_POINTS["user_request"], 5)
        self.assertEqual(rank.KIND_POINTS["meta"], 0)

    def test_distinct_terms_count_once(self):
        one = rank.parts(row(text="crlf"), ["crlf"], NOW)
        many = rank.parts(row(text="crlf " * 200), ["crlf"], NOW)
        self.assertEqual(one["terms"], many["terms"])
        # Control: a second DISTINCT term does add points.
        two = rank.parts(row(text="crlf importer"), ["crlf", "importer"], NOW)
        self.assertEqual(two["terms"], one["terms"] + rank.TERM_POINTS)

    def test_phrase_bonus_needs_the_terms_close_together(self):
        near = rank.parts(row(text="fix the crlf importer today"),
                          ["crlf", "importer"], NOW)
        far = rank.parts(row(text="crlf " + "x" * 400 + " importer"),
                         ["crlf", "importer"], NOW)
        self.assertEqual(near["phrase"], rank.PHRASE_POINTS)
        self.assertEqual(far["phrase"], 0)
        self.assertEqual(near["terms"], far["terms"])

    def test_recency_bands(self):
        for days, expected in ((0, 3), (7, 3), (8, 2), (30, 2), (31, 1),
                               (180, 1), (181, 0)):
            self.assertEqual(rank.parts(row(days_ago=days), [], NOW)["recency"],
                             expected, f"{days} days")

    def test_undated_turn_gets_no_recency_credit(self):
        r = row()
        r["ts"] = 0.0
        self.assertEqual(rank.parts(r, [], NOW)["recency"], 0)


class TestOrdering(unittest.TestCase):
    def test_a_request_outranks_a_shouting_log(self):
        req = row(kind="user_request", text="fix the crlf importer", days_ago=1)
        log = row(kind="tool_output", text=("crlf importer " * 200), days_ago=1, seq=1)
        scored = rank.rank([req, log], ["crlf", "importer"], NOW)
        self.assertIs(scored[0][2], req)
        # Control: give the log the same kind and the ordering collapses to a tie broken
        # by position, which proves the kind weight was what decided it.
        log2 = dict(log)
        log2["kind"] = "user_request"
        scored2 = rank.rank([req, log2], ["crlf", "importer"], NOW)
        self.assertEqual(scored2[0][0], scored2[1][0])

    def test_recency_decides_between_identical_turns(self):
        new = row(kind="user_request", text="websocket reconnect", days_ago=1)
        old = row(kind="user_request", text="websocket reconnect", days_ago=800, seq=1)
        scored = rank.rank([old, new], ["websocket"], NOW)
        self.assertIs(scored[0][2], new)
        # Control: age them the same and they tie.
        old2 = dict(old)
        old2["ts"] = new["ts"]
        scored2 = rank.rank([old2, new], ["websocket"], NOW)
        self.assertEqual(scored2[0][0], scored2[1][0])

    def test_ordering_is_deterministic(self):
        rows = [row(kind="user_request", text="a b", days_ago=5, seq=i,
                    session_id=f"s{i}") for i in range(20)]
        a = [id(r) for _s, _p, r in rank.rank(list(rows), ["a"], NOW)]
        b = [id(r) for _s, _p, r in rank.rank(list(reversed(rows)), ["a"], NOW)]
        self.assertEqual(a, b)

    def test_score_is_the_sum_of_the_four_named_parts(self):
        r = row(kind="error", text="crlf importer", days_ago=2)
        score, parts = rank.score_row(r, ["crlf", "importer"], NOW)
        self.assertEqual(score, sum(parts.values()))
        self.assertEqual(set(parts), {"kind", "terms", "phrase", "recency"})
        self.assertEqual(score, 4 + 4 + 3 + 3)


class TestSessionRanking(unittest.TestCase):
    def test_repeat_mentions_add_up_to_five(self):
        best = row(kind="user_request", text="crlf", days_ago=1, session_id="A")
        others = [row(kind="tool_output", text="crlf", days_ago=1, session_id="A",
                      seq=i + 1) for i in range(10)]
        scored = rank.rank([best] + others, ["crlf"], NOW)
        sessions = rank.rank_sessions(scored)
        self.assertEqual(len(sessions), 1)
        self.assertEqual(sessions[0]["extra"], 5)
        # Control: a session with one hit gets no bonus at all.
        solo = rank.rank_sessions(rank.rank([row(kind="user_request", text="crlf",
                                                 session_id="B", days_ago=1)],
                                            ["crlf"], NOW))
        self.assertEqual(solo[0]["extra"], 0)

    def test_one_strong_hit_beats_many_weak_ones(self):
        strong = row(kind="user_request", text="crlf importer bug", days_ago=1,
                     session_id="A")
        weak = [row(kind="thinking", text="crlf", days_ago=1, session_id="B", seq=i)
                for i in range(8)]
        sessions = rank.rank_sessions(rank.rank([strong] + weak, ["crlf", "importer"], NOW))
        self.assertEqual(sessions[0]["row"]["session_id"], "A")


class TestTokenize(unittest.TestCase):
    def test_quoted_spans_stay_together(self):
        self.assertEqual(rank.tokenize('fix "carriage return" bug'),
                         ["fix", "carriage return", "bug"])
        # Control: without quotes the same words are separate terms.
        self.assertEqual(rank.tokenize("fix carriage return bug"),
                         ["fix", "carriage", "return", "bug"])

    def test_punctuation_heavy_terms_survive(self):
        self.assertEqual(rank.tokenize("parse.py sk-ant foo:bar"),
                         ["parse.py", "sk-ant", "foo:bar"])


class TestAgainstTheFixtureIndex(unittest.TestCase):
    """The documented rule, exercised through the real query path."""

    def test_explain_parts_sum_to_the_score(self):
        from sessionsearch import indexer
        con = fs.con("planted")
        terms = rank.tokenize("crlf importer")
        rows, _ = indexer.candidates(con, terms)
        for score, parts, _r in rank.rank(rows, terms):
            self.assertEqual(score, sum(parts.values()))


if __name__ == "__main__":
    unittest.main()
