"""The ranking rule, written out in full.

There is no learned model here and no bm25. The score is the sum of four named integers,
every one of which can be printed next to the result with `--explain`, because the query
this tool exists to answer is "when did I last do something like this" and the honest form
of that answer is "this one, because a human typed it, three weeks ago, with all your
words in one sentence".

    score = kind + terms + phrase + recency

  kind      user_request 5, error 4, assistant_text 3, tool_input 2, tool_output 1,
            thinking 1, meta 0.
            A thing you asked for beats a thing a tool printed, because the archive holds
            perhaps fifty tool outputs for every request and the request is what you
            actually remember.
  terms     2 points per DISTINCT query term present in the turn. Repeats earn nothing, so
            a log line that screams the same word two hundred times cannot outrank a
            sentence that uses every word once.
  phrase    3 if every query term occurs inside one 60-character window, else 0.
  recency   3 if the turn is 7 days old or less, 2 within 30 days, 1 within 180 days,
            0 beyond that, and 0 for a turn with no usable timestamp.

Ties break on newer first, then session id, then position in the session, so the output is
deterministic and two runs over the same index produce the same order.

Session ranking, used by `sessions` and by "which session did I fix X in":

    session_score = best turn score + min(5, number of other matching turns)

which prefers a session that engaged with the topic repeatedly over one that mentioned it
once, without letting a chatty session bury a direct hit.
"""

from __future__ import annotations

import re
import time

KIND_POINTS = {
    "user_request": 5,
    "error": 4,
    "assistant_text": 3,
    "tool_input": 2,
    "tool_output": 1,
    "thinking": 1,
    "meta": 0,
}

TERM_POINTS = 2
PHRASE_POINTS = 3
PHRASE_WINDOW = 60
RECENCY_BANDS = ((7, 3), (30, 2), (180, 1))
DAY = 86400.0

_WORD = re.compile(r"[A-Za-z0-9_]+")


def tokenize(q: str):
    """Query terms. Quoted spans stay together and are matched as phrases."""
    terms, i, n = [], 0, len(q)
    while i < n:
        c = q[i]
        if c == '"':
            j = q.find('"', i + 1)
            if j == -1:
                terms.append(q[i + 1:].strip())
                break
            span = q[i + 1:j].strip()
            if span:
                terms.append(span)
            i = j + 1
        elif c.isspace():
            i += 1
        else:
            j = i
            while j < n and not q[j].isspace():
                j += 1
            terms.append(q[i:j])
            i = j
    return [t for t in (t.strip() for t in terms) if t]


def _positions(hay: str, term: str):
    out, start = [], 0
    t = term.lower()
    while True:
        k = hay.find(t, start)
        if k < 0:
            return out
        out.append(k)
        start = k + 1


def parts(row, terms, now=None):
    """Return the four named components for one candidate row."""
    now = time.time() if now is None else now
    text = (row["text"] or "")
    target = (row["target"] or "")
    hay = (text + "\n" + target).lower()

    found = {}
    for t in terms:
        pos = _positions(hay, t)
        if pos:
            found[t] = pos

    kind = KIND_POINTS.get(row["kind"], 0)
    term_pts = TERM_POINTS * len(found)

    phrase = 0
    if terms and len(found) == len(terms):
        phrase = PHRASE_POINTS if _in_window(found, terms) else 0

    ts = row["ts"] or 0.0
    recency = 0
    if ts > 0:
        age_days = max(0.0, (now - ts) / DAY)
        for limit, pts in RECENCY_BANDS:
            if age_days <= limit:
                recency = pts
                break

    return {"kind": kind, "terms": term_pts, "phrase": phrase, "recency": recency}


def _in_window(found, terms):
    """True when one position can be picked per term so that all fit in PHRASE_WINDOW.

    Sweeps every occurrence of the rarest term and asks whether the others have an
    occurrence nearby, which is exact for the "all inside one window" question and cheap.
    """
    rarest = min(terms, key=lambda t: len(found[t]))
    for anchor in found[rarest]:
        lo, hi = anchor, anchor + len(rarest)
        ok = True
        for t in terms:
            if t == rarest:
                continue
            best = None
            for p in found[t]:
                lo2, hi2 = min(lo, p), max(hi, p + len(t))
                if hi2 - lo2 <= PHRASE_WINDOW:
                    best = (lo2, hi2)
                    break
            if best is None:
                ok = False
                break
            lo, hi = best
        if ok:
            return True
    return False


def score_row(row, terms, now=None):
    p = parts(row, terms, now)
    return sum(p.values()), p


def rank(rows, terms, now=None, limit=None):
    """Score every candidate and sort. Returns [(score, parts, row)]."""
    now = time.time() if now is None else now
    scored = []
    for r in rows:
        s, p = score_row(r, terms, now)
        scored.append((s, p, r))
    scored.sort(key=lambda x: (-x[0], -(x[2]["ts"] or 0.0),
                               x[2]["session_id"], x[2]["seq"]))
    return scored[:limit] if limit else scored


def rank_sessions(scored, limit=None):
    """Collapse ranked turns into ranked sessions. Rule is in the module docstring."""
    by_session = {}
    for s, p, r in scored:
        key = (r["source"], r["session_id"])
        e = by_session.get(key)
        if e is None:
            by_session[key] = {"best": s, "best_parts": p, "row": r, "hits": 1}
        else:
            e["hits"] += 1
            if s > e["best"]:
                e["best"], e["best_parts"], e["row"] = s, p, r
    out = []
    for key, e in by_session.items():
        extra = min(5, e["hits"] - 1)
        out.append({"score": e["best"] + extra, "best": e["best"], "extra": extra,
                    "hits": e["hits"], "row": e["row"], "parts": e["best_parts"]})
    out.sort(key=lambda d: (-d["score"], -(d["row"]["last_ts"] or 0.0),
                            d["row"]["session_id"]))
    return out[:limit] if limit else out
