"""Excerpting: show the part that matched, and not the other nineteen thousand characters."""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sessionsearch import excerpt                       # noqa: E402

HAYSTACK = ("preamble " * 60) + "the carriage return fix went in here " + ("tail " * 60)


class TestWindow(unittest.TestCase):
    def test_window_lands_on_the_match_not_the_start(self):
        s, e = excerpt.best_window(HAYSTACK, ["carriage"])
        self.assertLessEqual(s, HAYSTACK.index("carriage"))
        self.assertGreaterEqual(e, HAYSTACK.index("carriage") + 8)
        self.assertGreater(s, 100, "the window did not move off the beginning")
        # Control: with no terms it falls back to the head of the text.
        self.assertEqual(excerpt.best_window(HAYSTACK, []), (0, excerpt.WIDTH))

    def test_window_prefers_covering_more_distinct_terms(self):
        text = "alpha " + ("x " * 200) + "alpha beta gamma"
        s, e = excerpt.best_window(text, ["alpha", "beta", "gamma"])
        self.assertIn("gamma", text[s:e])
        self.assertIn("beta", text[s:e])

    def test_snip_is_bounded_and_marks_what_it_dropped(self):
        out = excerpt.snip(HAYSTACK, ["carriage"])
        self.assertLessEqual(len(out), excerpt.WIDTH + 4)
        self.assertIn("carriage return", out)
        self.assertTrue(out.startswith(excerpt.ELLIPSIS))
        self.assertTrue(out.endswith(excerpt.ELLIPSIS))
        # Control: text that fits is returned whole, with no ellipsis at all.
        short = excerpt.snip("a short line", ["short"])
        self.assertEqual(short, "a short line")

    def test_snip_collapses_newlines_so_one_hit_is_one_paragraph(self):
        out = excerpt.snip("line one\nline two\nline three\n" * 20, ["two"])
        self.assertNotIn("\n", out)

    def test_context_line_is_shorter_than_the_hit(self):
        out = excerpt.context_line(HAYSTACK)
        self.assertLessEqual(len(out), excerpt.CONTEXT_WIDTH + 1)
        self.assertLess(excerpt.CONTEXT_WIDTH, excerpt.WIDTH)

    def test_a_missing_term_does_not_break_excerpting(self):
        out = excerpt.snip(HAYSTACK, ["nowhere"])
        self.assertTrue(out)
        self.assertLessEqual(len(out), excerpt.WIDTH + 4)


if __name__ == "__main__":
    unittest.main()
