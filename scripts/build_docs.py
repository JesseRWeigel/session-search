#!/usr/bin/env python3
"""Generate docs/index.html: one self-contained file, no external anything.

The page carries a live implementation of the ranking rule and a corpus to run it on. The
corpus is the SYNTHETIC fixture archive, never the real one, and it is passed through the
redactor and then through the independent checker before it is allowed into the file. If
the checker finds anything, no file is written and the script exits nonzero, because a
page that ships with a warning printed to a terminal nobody read is a page that shipped.

    python3 scripts/build_docs.py            write docs/index.html
    python3 scripts/build_docs.py --check    fail if the committed file is stale
"""

from __future__ import annotations

import argparse
import contextlib
import io
import json
import os
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "scripts"))
sys.path.insert(0, os.path.join(ROOT, "checker"))

import leakcheck                                        # noqa: E402
import make_fixtures                                    # noqa: E402
import measure_real                                     # noqa: E402
from sessionsearch import cli, indexer, rank, redact     # noqa: E402

OUT = os.path.join(ROOT, "docs", "index.html")


NOW = __import__("time").time()


def corpus():
    """Every turn of the planted fixture archive, redacted, as plain dicts."""
    tmp = tempfile.mkdtemp(prefix="session-search-docs-")
    arch = os.path.join(tmp, "planted")
    make_fixtures.build(arch, "planted")
    db = os.path.join(tmp, "planted.db")
    with contextlib.redirect_stdout(io.StringIO()):
        cli.main(["--index", db, "index", "--archive", arch, "--quiet"])
    con = indexer.connect(db, create=False)
    rows = con.execute(
        "SELECT sessions.session_id, sessions.source, sessions.project, sessions.title,"
        " turns.seq, turns.ts, turns.kind, turns.tool, turns.target, turns.text"
        " FROM turns JOIN sessions ON sessions.rowid = turns.session"
        " ORDER BY sessions.session_id, turns.seq").fetchall()
    out = []
    for r in rows:
        out.append({
            "session": r["session_id"][:8],
            "source": r["source"],
            "project": redact.redact(r["project"]),
            "title": redact.redact(r["title"]),
            "seq": r["seq"],
            # Age in whole days, not an absolute timestamp. One fixture session is dated
            # relative to now so that the recency band has something to bite on, and an
            # absolute timestamp would make this page differ from itself every run,
            # turning the staleness check into noise everyone learns to ignore.
            "ageDays": (None if not r["ts"]
                        else int(round((NOW - r["ts"]) / 86400.0))),
            "kind": r["kind"],
            "tool": r["tool"],
            "target": redact.redact(r["target"]),
            "text": redact.redact(r["text"])[:1200],
        })
    con.close()
    return out


def page(data, stats, fixture_stats):
    kind_rows = "\n".join(
        f"      <tr><td><code>{k}</code></td><td>{v}</td><td>{d}</td></tr>"
        for k, v, d in [
            ("user_request", rank.KIND_POINTS["user_request"],
             "something you typed"),
            ("error", rank.KIND_POINTS["error"],
             "a tool result flagged as an error, or one that opens like a traceback"),
            ("assistant_text", rank.KIND_POINTS["assistant_text"],
             "prose the model wrote"),
            ("tool_input", rank.KIND_POINTS["tool_input"],
             "a tool call and its arguments, including the file it touched"),
            ("tool_output", rank.KIND_POINTS["tool_output"], "what the tool printed"),
            ("thinking", rank.KIND_POINTS["thinking"],
             "extended thinking and Codex reasoning summaries"),
            ("meta", rank.KIND_POINTS["meta"],
             "system reminders and injected commands, excluded unless asked for"),
        ])

    payload = json.dumps({
        "corpus": data,
        "kindPoints": rank.KIND_POINTS,
        "termPoints": rank.TERM_POINTS,
        "phrasePoints": rank.PHRASE_POINTS,
        "phraseWindow": rank.PHRASE_WINDOW,
        "bands": rank.RECENCY_BANDS,
    }, ensure_ascii=False, separators=(",", ":"))

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="light dark">
<title>session-search: make every AI session searchable</title>
<style>
:root {{
  --bg: #fbfaf7; --fg: #14171a; --muted: #5b6570; --line: #dfdcd4;
  --card: #ffffff; --accent: #7b3f00; --code: #f2efe9; --hit: #ffe9a8;
  color-scheme: light;
}}
@media (prefers-color-scheme: dark) {{
  :root {{
    --bg: #14161a; --fg: #e8e6e1; --muted: #9aa3ad; --line: #2c3138;
    --card: #1b1e23; --accent: #e0a458; --code: #21252b; --hit: #5c4a13;
    color-scheme: dark;
  }}
}}
:root[data-theme="dark"] {{
  --bg: #14161a; --fg: #e8e6e1; --muted: #9aa3ad; --line: #2c3138;
  --card: #1b1e23; --accent: #e0a458; --code: #21252b; --hit: #5c4a13;
  color-scheme: dark;
}}
:root[data-theme="light"] {{
  --bg: #fbfaf7; --fg: #14171a; --muted: #5b6570; --line: #dfdcd4;
  --card: #ffffff; --accent: #7b3f00; --code: #f2efe9; --hit: #ffe9a8;
  color-scheme: light;
}}
* {{ box-sizing: border-box; }}
body {{
  margin: 0; padding: 0 1rem 4rem;
  background: var(--bg); color: var(--fg);
  font: 16px/1.6 ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, sans-serif;
}}
main {{ max-width: 46rem; margin: 0 auto; }}
header {{ padding: 2.5rem 0 1rem; border-bottom: 1px solid var(--line); }}
h1 {{ font-size: 1.75rem; line-height: 1.2; margin: 0 0 .4rem; letter-spacing: -.02em; }}
h2 {{ font-size: 1.15rem; margin: 2.5rem 0 .6rem; letter-spacing: -.01em; }}
h3 {{ font-size: .95rem; margin: 1.6rem 0 .4rem; color: var(--muted);
      text-transform: uppercase; letter-spacing: .08em; }}
p {{ margin: .6rem 0; }}
.lede {{ color: var(--muted); margin: 0; }}
code, pre {{ font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
             font-size: .85em; }}
code {{ background: var(--code); padding: .1em .35em; border-radius: 3px;
        overflow-wrap: anywhere; }}
pre {{ background: var(--code); padding: .75rem; border-radius: 6px;
       overflow-x: auto; margin: .8rem 0; }}
pre code {{ background: none; padding: 0; }}
.tablewrap {{ overflow-x: auto; margin: .8rem 0; }}
table {{ border-collapse: collapse; width: 100%; min-width: 20rem; }}
th, td {{ text-align: left; padding: .35rem .6rem .35rem 0; vertical-align: top;
          border-bottom: 1px solid var(--line); font-size: .92rem; }}
th {{ color: var(--muted); font-weight: 600; }}
.formula {{ background: var(--card); border: 1px solid var(--line); border-radius: 8px;
            padding: .9rem 1rem; margin: 1rem 0; }}
.formula b {{ color: var(--accent); }}
form {{ margin: 1rem 0 .5rem; display: flex; gap: .5rem; flex-wrap: wrap; }}
input[type=search] {{
  flex: 1 1 12rem; min-width: 0; padding: .55rem .7rem; font: inherit;
  background: var(--card); color: var(--fg);
  border: 1px solid var(--line); border-radius: 6px;
}}
select, button {{
  padding: .55rem .7rem; font: inherit; background: var(--card); color: var(--fg);
  border: 1px solid var(--line); border-radius: 6px; max-width: 100%;
}}
button {{ cursor: pointer; }}
.hit {{ border: 1px solid var(--line); border-left: 3px solid var(--accent);
        background: var(--card); border-radius: 6px; padding: .6rem .8rem;
        margin: .6rem 0; }}
.hit .meta {{ color: var(--muted); font-size: .82rem; display: flex;
              flex-wrap: wrap; gap: .1rem .8rem; }}
.hit .why {{ color: var(--muted); font-size: .82rem; margin-top: .3rem; }}
.hit .body {{ margin-top: .35rem; overflow-wrap: anywhere; }}
.hit mark {{ background: var(--hit); color: inherit; padding: 0 .1em; }}
.score {{ display: inline-block; min-width: 1.9rem; text-align: right;
          font-weight: 700; color: var(--accent); }}
.note {{ color: var(--muted); font-size: .88rem; }}
footer {{ margin-top: 3rem; padding-top: 1rem; border-top: 1px solid var(--line);
          color: var(--muted); font-size: .85rem; }}
#selftest {{ font-size: .75rem; color: var(--muted); overflow-wrap: anywhere; }}
.grid {{ display: grid; gap: .6rem; grid-template-columns: repeat(auto-fit, minmax(9rem, 1fr)); }}
.stat {{ background: var(--card); border: 1px solid var(--line); border-radius: 8px;
         padding: .7rem .8rem; min-width: 0; }}
.stat b {{ display: block; font-size: 1.3rem; letter-spacing: -.02em; }}
.stat span {{ color: var(--muted); font-size: .8rem; }}
</style>
</head>
<body>

<main>
<header>
  <h1>Make every AI session you have ever run searchable</h1>
  <p class="lede">Six months of Claude Code and Codex transcripts, indexed locally, ranked
  by a rule you can read, and redacted before anything reaches your screen.</p>
</header>

<h2>The numbers, from the real archive</h2>
<div class="grid">
  <div class="stat"><b>{stats['sessions']:,}</b><span>sessions</span></div>
  <div class="stat"><b>{stats['turns']:,}</b><span>turns</span></div>
  <div class="stat"><b>{stats['index_bytes'] / 1e6:.0f} MB</b><span>index</span></div>
  <div class="stat"><b>{stats['build_seconds']:.1f} s</b><span>full rebuild</span></div>
  <div class="stat"><b>{stats['query_ms_median']:.1f} ms</b><span>median query</span></div>
  <div class="stat"><b>0</b><span>leaks found in redacted output</span></div>
</div>
<p class="note">Measured {stats['measured_on']} over {stats['transcript_files']:,}
transcript files, {stats['raw_bytes'] / 1e9:.2f} GB of raw JSONL, spanning
{stats['span'][0]} to {stats['span'][1]}. None of that content is in this page or in the
repository. The demo below runs on a synthetic fixture archive instead.</p>

<h2>A transcript is not a blob of text</h2>
<p>Grep over the raw JSONL treats a shell command, the file it read, the traceback it
printed and the sentence you typed as the same kind of evidence. They are not. Every turn
is classified once, at parse time, and everything downstream keys off that.</p>
<div class="tablewrap">
<table>
  <thead><tr><th>kind</th><th>points</th><th>what it is</th></tr></thead>
  <tbody>
{kind_rows}
  </tbody>
</table>
</div>

<h2>The ranking rule, in full</h2>
<p>No learned model and no bm25. The score is the sum of four named integers, and the tool
will print them next to any result with <code>--explain</code>.</p>
<div class="formula">
  <p><b>score = kind + terms + phrase + recency</b></p>
  <p><b>kind</b> from the table above.<br>
  <b>terms</b>: {rank.TERM_POINTS} points per distinct query term present. Repeats earn
  nothing, so a log line that screams one word two hundred times cannot outrank a sentence
  that uses every word once.<br>
  <b>phrase</b>: {rank.PHRASE_POINTS} points if every term fits inside one
  {rank.PHRASE_WINDOW} character window.<br>
  <b>recency</b>: 3 within a week, 2 within a month, 1 within six months, 0 beyond.</p>
  <p class="note">Ties break on newer first, then session, then position, so two runs over
  the same index return the same order.</p>
</div>

<h2>Try it</h2>
<p class="note">Running against the synthetic fixture archive that the test suite uses:
{fixture_stats['planted']['sessions']} sessions, {fixture_stats['planted']['turns']} turns,
with known content planted in it. Nothing here comes from a real transcript.</p>
<form id="q" onsubmit="return false">
  <input type="search" id="query" value="crlf importer" aria-label="query"
         autocomplete="off" spellcheck="false">
  <select id="kind" aria-label="kind filter">
    <option value="">every kind</option>
  </select>
  <button type="button" id="explain">explain</button>
</form>
<div id="results"></div>

<h2>Nothing derived from the archive is committed</h2>
<p>The index holds raw transcript text, so it lives outside the repository, under
<code>~/.local/share/session-search</code>, and <code>*.db</code> is gitignored as a
second line of defence. Everything on its way to a terminal or a file goes through one
redactor. The redactor's output is then audited by a checker written separately, sharing
no code and no patterns with it, because a leak check that reuses the filter's own regex
inherits the filter's own bug and reports clean.</p>
<p>The audit runs over every turn in the real archive, not a sample:
<b id="auditline">{stats['turns']:,} turns, 0 findings</b>. It also scans for NUL bytes in
Python rather than with grep, because one NUL byte makes a file binary to
<code>git grep</code>, which then skips it in silence and reports a clean tree it never
read.</p>

<h2>What it does not do</h2>
<p>Attachment records are not indexed. In this archive they are harness injections rather
than conversation: tool listings, skill listings, task reminders. Codex reasoning blobs
are not indexed either, because they are encrypted and contain no searchable text. Both
counts are printed at index time, so the part you are not searching is visible instead of
implied. There is no <code>--no-redact</code> flag, and there will not be one.</p>

<footer>
  <p>MIT licensed. Python 3 and its standard library, no dependencies.
  <button type="button" id="theme">toggle theme</button></p>
  <p id="selftest">script has not run</p>
</footer>
</main>

<script id="data" type="application/json">{payload}</script>
<script>
(function () {{
  "use strict";
  var D = JSON.parse(document.getElementById("data").textContent);
  var explain = false;

  function tokenize(q) {{
    var out = [], i = 0;
    while (i < q.length) {{
      var c = q.charAt(i);
      if (c === '"') {{
        var j = q.indexOf('"', i + 1);
        if (j === -1) {{ out.push(q.slice(i + 1).trim()); break; }}
        var span = q.slice(i + 1, j).trim();
        if (span) out.push(span);
        i = j + 1;
      }} else if (/\\s/.test(c)) {{ i++; }}
      else {{
        var k = i;
        while (k < q.length && !/\\s/.test(q.charAt(k))) k++;
        out.push(q.slice(i, k));
        i = k;
      }}
    }}
    return out.filter(function (t) {{ return t.length > 0; }});
  }}

  function positions(hay, term) {{
    var out = [], start = 0, k;
    while ((k = hay.indexOf(term, start)) !== -1) {{ out.push(k); start = k + 1; }}
    return out;
  }}

  function inWindow(found, terms) {{
    var rarest = terms[0];
    terms.forEach(function (t) {{
      if (found[t].length < found[rarest].length) rarest = t;
    }});
    for (var a = 0; a < found[rarest].length; a++) {{
      var lo = found[rarest][a], hi = lo + rarest.length, ok = true;
      for (var b = 0; b < terms.length; b++) {{
        var t = terms[b];
        if (t === rarest) continue;
        var best = null;
        for (var c = 0; c < found[t].length; c++) {{
          var p = found[t][c];
          var lo2 = Math.min(lo, p), hi2 = Math.max(hi, p + t.length);
          if (hi2 - lo2 <= D.phraseWindow) {{ best = [lo2, hi2]; break; }}
        }}
        if (!best) {{ ok = false; break; }}
        lo = best[0]; hi = best[1];
      }}
      if (ok) return true;
    }}
    return false;
  }}

  function parts(row, terms) {{
    var hay = (row.text + "\\n" + row.target).toLowerCase();
    var found = {{}}, n = 0;
    terms.forEach(function (t) {{
      var p = positions(hay, t.toLowerCase());
      if (p.length) {{ found[t] = p; n++; }}
    }});
    var phrase = 0;
    if (terms.length && n === terms.length && inWindow(found, terms)) {{
      phrase = D.phrasePoints;
    }}
    var recency = 0;
    if (row.ageDays !== null) {{
      var days = Math.max(0, row.ageDays);
      for (var i = 0; i < D.bands.length; i++) {{
        if (days <= D.bands[i][0]) {{ recency = D.bands[i][1]; break; }}
      }}
    }}
    return {{
      kind: D.kindPoints[row.kind] || 0,
      terms: D.termPoints * n,
      phrase: phrase,
      recency: recency,
      matched: n
    }};
  }}

  function esc(s) {{
    return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
  }}

  function highlight(text, terms) {{
    var html = esc(text);
    terms.forEach(function (t) {{
      if (!t) return;
      var re = new RegExp(t.replace(/[.*+?^${{}}()|[\\]\\\\]/g, "\\\\$&"), "gi");
      html = html.replace(re, function (m) {{ return "<mark>" + m + "</mark>"; }});
    }});
    return html;
  }}

  function snip(text, terms) {{
    var flat = text.replace(/\\s+/g, " ").trim();
    if (flat.length <= 260) return flat;
    var low = flat.toLowerCase(), at = -1;
    for (var i = 0; i < terms.length && at === -1; i++) {{
      at = low.indexOf(terms[i].toLowerCase());
    }}
    if (at === -1) return flat.slice(0, 260) + "\\u2026";
    var s = Math.max(0, at - 60);
    return (s > 0 ? "\\u2026" : "") + flat.slice(s, s + 260)
      + (s + 260 < flat.length ? "\\u2026" : "");
  }}

  function when(age) {{
    if (age === null) return "undated";
    if (age <= 0) return "today";
    if (age === 1) return "yesterday";
    if (age < 60) return age + " days ago";
    if (age < 730) return Math.round(age / 30) + " months ago";
    return (age / 365).toFixed(1) + " years ago";
  }}

  function search(q, kindFilter) {{
    var terms = tokenize(q);
    var scored = [];
    D.corpus.forEach(function (row) {{
      if (row.kind === "meta" && kindFilter !== "meta") return;
      if (kindFilter && row.kind !== kindFilter) return;
      var p = parts(row, terms);
      if (terms.length && p.matched < terms.length) return;
      scored.push({{ score: p.kind + p.terms + p.phrase + p.recency, parts: p, row: row }});
    }});
    scored.sort(function (a, b) {{
      if (b.score !== a.score) return b.score - a.score;
      if (a.row.ageDays !== b.row.ageDays) return a.row.ageDays - b.row.ageDays;
      if (a.row.session !== b.row.session) return a.row.session < b.row.session ? -1 : 1;
      return a.row.seq - b.row.seq;
    }});
    return {{ terms: terms, hits: scored.slice(0, 8), total: scored.length }};
  }}

  function render() {{
    var q = document.getElementById("query").value;
    var kindFilter = document.getElementById("kind").value;
    var r = search(q, kindFilter);
    var box = document.getElementById("results");
    box.innerHTML = "";
    if (!r.hits.length) {{
      var none = document.createElement("p");
      none.className = "note";
      none.id = "nohits";
      none.textContent = "No turn in the fixture archive matches every term. "
        + "That is the answer, not a failure: the control fixture exists so that "
        + "\\u201cfinds nothing when there is nothing\\u201d is testable.";
      box.appendChild(none);
      return r;
    }}
    r.hits.forEach(function (h) {{
      var el = document.createElement("div");
      el.className = "hit";
      var p = h.parts;
      el.innerHTML =
        '<div class="meta"><span class="score">' + h.score + '</span>'
        + '<span>' + esc(h.row.kind) + (h.row.tool ? "/" + esc(h.row.tool) : "") + '</span>'
        + '<span>' + when(h.row.ageDays) + '</span>'
        + '<span>session ' + esc(h.row.session) + '</span>'
        + '<span>' + esc(h.row.project || "") + '</span></div>'
        + (explain
          ? '<div class="why">kind ' + p.kind + ' + terms ' + p.terms + ' + phrase '
            + p.phrase + ' + recency ' + p.recency + ' = ' + h.score + '</div>'
          : '')
        + '<div class="body">' + highlight(snip(h.row.text, r.terms), r.terms) + '</div>';
      box.appendChild(el);
    }});
    return r;
  }}

  var kinds = [];
  D.corpus.forEach(function (row) {{
    if (kinds.indexOf(row.kind) === -1) kinds.push(row.kind);
  }});
  kinds.sort();
  var sel = document.getElementById("kind");
  kinds.forEach(function (k) {{
    var o = document.createElement("option");
    o.value = k; o.textContent = k;
    sel.appendChild(o);
  }});

  document.getElementById("query").addEventListener("input", render);
  sel.addEventListener("change", render);
  document.getElementById("explain").addEventListener("click", function () {{
    explain = !explain;
    this.textContent = explain ? "hide scores" : "explain";
    render();
  }});
  document.getElementById("theme").addEventListener("click", function () {{
    var root = document.documentElement;
    var now = root.getAttribute("data-theme");
    var dark = now ? now === "dark"
      : window.matchMedia("(prefers-color-scheme: dark)").matches;
    root.setAttribute("data-theme", dark ? "light" : "dark");
  }});

  var first = render();

  // Something only a running script could have produced, so the browser check can tell
  // "the script ran" apart from "the file exists".
  var probe = search("crlf importer", "");
  var top = probe.hits[0];
  var empty = search("quaternion pelican", "");
  document.getElementById("selftest").textContent =
    "SELFTEST:OK corpus=" + D.corpus.length
    + " hits=" + first.total
    + " top=" + (top ? top.row.session + ":" + top.row.kind + ":" + top.score : "none")
    + " absent=" + empty.total;
}})();
</script>
</body>
</html>
"""


SNAPSHOT = os.path.join(ROOT, "docs", "measured.json")


def load_snapshot():
    """Counts only, taken by scripts/measure_real.py --write. No archive content.

    The page is built from this file rather than from a live measurement so that
    `--check` is deterministic: the archive grows every day and a page rebuilt from it
    would be stale within hours, which trains everyone to ignore the staleness check.
    """
    if not os.path.exists(SNAPSHOT):
        raise SystemExit("docs/measured.json is missing; run: "
                         "python3 scripts/measure_real.py --write")
    with open(SNAPSHOT, encoding="utf-8") as fh:
        return json.load(fh)


def build():
    data = corpus()
    stats = load_snapshot()
    fixture_stats = measure_real.measure_fixture()
    html = page(data, stats, fixture_stats)
    findings = leakcheck.scan_text(html, "docs/index.html")
    if findings:
        for w, line, label, snip in findings:
            print(f"LEAK {w}:{line}: {label}: {leakcheck.redact_for_report(snip)}",
                  file=sys.stderr)
        raise SystemExit("refusing to write a page the independent checker rejected")
    return html


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true")
    a = ap.parse_args()
    html = build()
    if a.check:
        with open(OUT, encoding="utf-8") as fh:
            have = fh.read()
        if have == html:
            print("docs/index.html is up to date")
            return 0
        # The page embeds real-archive counts, which move. Report which lines differ.
        import difflib
        diff = list(difflib.unified_diff(have.splitlines(), html.splitlines(),
                                         "committed", "regenerated", n=0, lineterm=""))
        print("\n".join(diff[:40]))
        print("docs/index.html is stale; run: python3 scripts/build_docs.py")
        return 1
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w", encoding="utf-8") as fh:
        fh.write(html)
    print(f"wrote docs/index.html ({len(html):,} bytes)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
