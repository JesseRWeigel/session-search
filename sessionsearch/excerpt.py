"""Pick the part of a turn worth showing.

A result that dumps four hundred lines of transcript is not a result. A turn in this
archive is up to 20 000 characters, and the median tool output is a directory listing
nobody wants to reread. So: find the tightest window that covers the most distinct query
terms, show that window, and show one turn either side clipped hard, which is usually
enough to tell whether this is the moment you were thinking of.
"""

from __future__ import annotations

WIDTH = 260          # characters shown from the matching turn
CONTEXT_WIDTH = 130  # characters shown from each neighbouring turn
ELLIPSIS = "…"


def best_window(text: str, terms, width=WIDTH):
    """Return (start, end) covering as many distinct terms as possible, at most `width`.

    Scans candidate starts at every occurrence of every term, which is O(occurrences^2) in
    the worst case and trivial in practice because a turn is bounded.
    """
    if not text:
        return (0, 0)
    if not terms:
        return (0, min(len(text), width))
    low = text.lower()
    occ = []
    for t in terms:
        tl = t.lower()
        start = 0
        while True:
            k = low.find(tl, start)
            if k < 0:
                break
            occ.append((k, k + len(tl), tl))
            start = k + 1
    if not occ:
        return (0, min(len(text), width))
    occ.sort()
    best = None
    for i, (s, _e, _t) in enumerate(occ):
        end = s + width
        covered = {t for (a, b, t) in occ if a >= s and b <= end}
        span_end = max([b for (a, b, t) in occ if a >= s and b <= end] or [s])
        cand = (len(covered), -(span_end - s), -s)
        if best is None or cand > best[0]:
            best = (cand, s, end)
    s = best[1]
    # Centre the window on the matched span rather than starting exactly at it, so a
    # match near the end of a sentence still shows what led up to it.
    s = max(0, s - width // 4)
    return (s, min(len(text), s + width))


def snip(text: str, terms, width=WIDTH):
    """One-paragraph excerpt with ellipses where text was removed."""
    if text is None:
        return ""
    text = text.replace("\r", "")
    if len(text) <= width and "\n" not in text.strip():
        return text.strip()
    s, e = best_window(text, terms, width)
    # Nudge to a whitespace boundary so words are not sliced in half.
    if s > 0:
        k = text.find(" ", s, min(s + 20, e))
        if k != -1:
            s = k + 1
    if e < len(text):
        k = text.rfind(" ", max(s, e - 20), e)
        if k != -1 and k > s:
            e = k
    body = " ".join(text[s:e].split())
    return (ELLIPSIS if s > 0 else "") + body + (ELLIPSIS if e < len(text) else "")


def context_line(text: str, width=CONTEXT_WIDTH):
    if not text:
        return ""
    body = " ".join(text.split())
    return body[:width] + (ELLIPSIS if len(body) > width else "")
