"""Command line entry point.

    python3 -m sessionsearch.cli index
    python3 -m sessionsearch.cli search "crlf fixture" --explain
    python3 -m sessionsearch.cli sessions "redaction leak"
    python3 -m sessionsearch.cli show 1a2b3c4d --seq 40

There is deliberately no `--no-redact`. Anything that prints raw archive text is a feature
whose only purpose is to leak, and the moment it exists somebody's terminal scrollback has
an API key in it.
"""

from __future__ import annotations

import argparse
import datetime
import os
import re
import sys
import time

from . import archive, excerpt, indexer, parse, rank, redact, render

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _die(msg, code=2):
    print(f"session-search: {msg}", file=sys.stderr)
    raise SystemExit(code)


def _guard():
    """Refuse to run at all if the redactor has stopped redacting."""
    if not redact.self_check():
        _die("the redaction self check failed; refusing to print archive content", 3)


def parse_when(s):
    """Accept 2026-07-01, 2026-07-01T10:00, 7d, 6w, 3mo, or 'today'."""
    if not s:
        return None
    s = s.strip()
    now = time.time()
    if s == "today":
        d = datetime.date.today()
        return datetime.datetime(d.year, d.month, d.day).timestamp()
    m = re.fullmatch(r"(\d+)(d|w|mo|y)", s)
    if m:
        n = int(m.group(1))
        mult = {"d": 86400, "w": 604800, "mo": 2592000, "y": 31536000}[m.group(2)]
        return now - n * mult
    try:
        return datetime.datetime.fromisoformat(s).timestamp()
    except ValueError:
        _die(f"cannot read a date out of {s!r}")


# ------------------------------------------------------------------------- index ---

def cmd_index(args):
    path = args.index or indexer.default_index_path()
    if os.path.abspath(path).startswith(REPO_ROOT + os.sep):
        _die(f"refusing to write the index inside the repository: {path}", 4)
    sources = archive.discover(args.archive)
    wanted = set(args.source or [s.name for s in sources])
    t0 = time.time()
    con = indexer.connect(path)
    indexer.wipe(con)

    stats = parse.ParseStats()
    n_sessions = 0
    n_files = 0
    claude_ids = set()
    missing = []

    for src in sources:
        if src.name not in wanted:
            continue
        if not src.exists:
            missing.append(src)
            continue
        if src.name == "claude_prompts":
            continue
        fn = parse.parse_claude_file if src.name == "claude_code" else parse.parse_codex_file
        for f in src.files:
            n_files += 1
            try:
                meta, turns = fn(f, stats)
            except Exception as exc:                       # noqa: BLE001
                print(f"  warning: {os.path.basename(f)}: {exc}", file=sys.stderr)
                continue
            if not turns:
                continue
            if src.name == "claude_code":
                claude_ids.add(meta.session_id)
            indexer.add_session(con, meta, turns)
            n_sessions += 1
            if not args.quiet and n_files % 100 == 0:
                print(f"  {n_files} files, {n_sessions} sessions, {stats.turns} turns",
                      file=sys.stderr)
        con.commit()

    recovered = 0
    for src in sources:
        if src.name != "claude_prompts" or src.name not in wanted:
            continue
        if not src.exists:
            missing.append(src)
            continue
        n_files += 1
        for meta, turns in parse.parse_claude_history(src.root, stats, claude_ids):
            indexer.add_session(con, meta, turns)
            n_sessions += 1
            recovered += 1
        con.commit()

    elapsed = time.time() - t0
    indexer.set_meta(con, "built_at", time.time())
    indexer.set_meta(con, "build_seconds", round(elapsed, 2))
    indexer.set_meta(con, "files", n_files)
    indexer.set_meta(con, "bad_json", stats.bad_json)
    indexer.set_meta(con, "skipped_attachment", stats.skipped_attachment)
    indexer.set_meta(con, "skipped_encrypted", stats.skipped_encrypted)
    indexer.set_meta(con, "recovered_prompt_sessions", recovered)
    indexer.set_meta(con, "archive", args.archive or "(default)")
    con.commit()
    con.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    con.close()

    size = sum(os.path.getsize(path + suffix) for suffix in ("", "-wal", "-shm")
               if os.path.exists(path + suffix))
    print(f"indexed {n_sessions} sessions, {stats.turns} turns from {n_files} files")
    print(f"  kinds: " + ", ".join(f"{k}={v}" for k, v in
                                   sorted(stats.by_kind.items(), key=lambda x: -x[1])))
    print(f"  skipped: {stats.skipped_attachment} attachments,"
          f" {stats.skipped_encrypted} encrypted reasoning blobs,"
          f" {stats.bad_json} unparseable lines, {stats.skipped_empty} empty turns")
    if recovered:
        print(f"  recovered {recovered} sessions from prompt history with no transcript")
    print(f"  index: {render.safe(path)}  {size / 1e6:.1f} MB")
    print(f"  built in {elapsed:.1f}s")
    for src in missing:
        print(f"  NOTE: source {src.name} not present at {render.safe(src.root)}",
              file=sys.stderr)
    return 0


# ------------------------------------------------------------------------ search ---

def _open(args):
    path = args.index or indexer.default_index_path()
    try:
        con = indexer.connect(path, create=False)
    except FileNotFoundError:
        _die(f"no index at {render.safe(path)}; run: python3 -m sessionsearch.cli index", 5)
    if indexer.get_meta(con, "schema_version") != str(indexer.SCHEMA_VERSION):
        _die("the index was built by a different schema version; rebuild it", 5)
    return con


def _filters(args):
    return dict(
        kind=args.kind, tool=args.tool, project=args.project, source=args.source,
        session=args.session, since=parse_when(args.since), until=parse_when(args.until),
        include_meta=args.include_meta,
        sidechain=(True if args.sidechain == "only"
                   else False if args.sidechain == "never" else None))


def cmd_search(args):
    _guard()
    con = _open(args)
    terms = rank.tokenize(args.query)
    rows, sql_secs = indexer.candidates(con, terms, limit=args.scan, **_filters(args))
    t0 = time.perf_counter()
    scored = rank.rank(rows, terms)
    rank_secs = time.perf_counter() - t0

    if args.sessions:
        entries = rank.rank_sessions(scored, limit=args.limit)
        if args.json:
            print(render.dumps([{
                "score": e["score"], "hits": e["hits"],
                "session_id": e["row"]["session_id"], "source": e["row"]["source"],
                "project": render.safe(e["row"]["project"]),
                "when": render.when(e["row"]["last_ts"] or e["row"]["ts"]),
                "excerpt": render.safe(excerpt.snip(e["row"]["text"], terms)),
            } for e in entries]))
        else:
            for e in entries:
                print(render.session_hit(e, terms, args.explain))
                print()
            _footer(len(rows), len(entries), sql_secs, rank_secs, "sessions")
        return 0 if entries else 1

    shown = scored[:args.limit]
    if args.json:
        print(render.dumps([render.as_json(s, p, r, terms) for s, p, r in shown]))
    else:
        for s, p, r in shown:
            ctx = ()
            if args.context:
                ctx = indexer.neighbours(con, r["session"], r["seq"],
                                         args.context, args.context)
            print(render.hit(s, p, r, terms, ctx, args.explain))
            print()
        _footer(len(rows), len(shown), sql_secs, rank_secs, "turns")
    return 0 if shown else 1


def _footer(candidates, shown, sql_secs, rank_secs, unit):
    print(f"{shown} of {candidates} matching turns shown as {unit}"
          f"  (fts {sql_secs * 1000:.0f} ms, rank {rank_secs * 1000:.0f} ms)",
          file=sys.stderr)


def cmd_show(args):
    _guard()
    con = _open(args)
    row = con.execute(
        "SELECT rowid, session_id, source, project, title, last_ts FROM sessions"
        " WHERE session_id LIKE ? ORDER BY last_ts DESC LIMIT 1",
        (args.session + "%",)).fetchone()
    if not row:
        _die(f"no session starting {args.session!r} in the index", 1)
    print(f"session {row['session_id']}  {row['source']}"
          f"  {render.safe(row['project'])}  {render.when(row['last_ts'])}")
    if row["title"]:
        print(f"title: {render.safe(row['title'])}")
    lo = max(0, args.seq - args.span)
    turns = con.execute(
        "SELECT seq, kind, tool, text, ts FROM turns WHERE session=? AND seq BETWEEN ? AND ?"
        " ORDER BY seq", (row["rowid"], lo, args.seq + args.span)).fetchall()
    for t in turns:
        label = render.KIND_LABEL.get(t["kind"], t["kind"])
        tool = ("/" + t["tool"]) if t["tool"] else ""
        print(f"\n{t['seq']:>4} [{label}{tool}]")
        print("     " + render.safe(excerpt.context_line(t["text"], args.width)))
    return 0


def cmd_stats(args):
    con = _open(args)
    c = indexer.counts(con)
    path = args.index or indexer.default_index_path()
    size = sum(os.path.getsize(path + s) for s in ("", "-wal", "-shm")
               if os.path.exists(path + s))
    print(f"index         {render.safe(path)}")
    print(f"size          {size / 1e6:.1f} MB")
    print(f"sessions      {c['sessions']}")
    print(f"turns         {c['turns']}")
    print(f"projects      {c['projects']}")
    print(f"span          {render.when(c['first_ts'])} .. {render.when(c['last_ts'])}")
    print(f"built in      {indexer.get_meta(con, 'build_seconds')}s"
          f" from {indexer.get_meta(con, 'files')} files")
    print("by source     " + ", ".join(f"{k}={v}" for k, v in c["by_source"].items()))
    print("by kind       " + ", ".join(f"{k}={v}" for k, v in c["by_kind"].items()))
    print("top tools     " + ", ".join(f"{k}={v}" for k, v in
                                       list(c["by_tool"].items())[:10]))
    print(f"skipped       {indexer.get_meta(con, 'skipped_attachment')} attachments,"
          f" {indexer.get_meta(con, 'skipped_encrypted')} encrypted blobs,"
          f" {indexer.get_meta(con, 'bad_json')} unparseable lines")
    if args.json:
        print(render.dumps({"size_bytes": size, **{k: v for k, v in c.items()}}))
    return 0


def build_parser():
    ap = argparse.ArgumentParser(prog="session-search",
                                 description="Search every AI session you have ever run.")
    ap.add_argument("--index", help="index file (default: outside the repo, see README)")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("index", help="build the index from scratch")
    p.add_argument("--archive", help="fixture archive root instead of the real one")
    p.add_argument("--source", action="append",
                   choices=["claude_code", "codex", "claude_prompts"])
    p.add_argument("--quiet", action="store_true")
    p.set_defaults(fn=cmd_index)

    for name, helptext in (("search", "rank matching turns"),
                           ("sessions", "rank matching sessions")):
        p = sub.add_parser(name, help=helptext)
        p.add_argument("query")
        p.add_argument("--kind", action="append", choices=list(parse.KINDS))
        p.add_argument("--tool", action="append")
        p.add_argument("--project")
        p.add_argument("--source", action="append",
                       choices=["claude_code", "codex", "claude_prompts"])
        p.add_argument("--session", help="restrict to one session id prefix")
        p.add_argument("--since")
        p.add_argument("--until")
        p.add_argument("--limit", type=int, default=10)
        p.add_argument("--scan", type=int, default=4000,
                       help="how many candidate turns to score")
        p.add_argument("--context", type=int, default=1,
                       help="neighbouring turns to show either side")
        p.add_argument("--explain", action="store_true",
                       help="print the four score components")
        p.add_argument("--json", action="store_true")
        p.add_argument("--include-meta", action="store_true")
        p.add_argument("--sidechain", choices=["only", "never", "both"], default="both")
        p.set_defaults(fn=cmd_search, sessions=(name == "sessions"))

    p = sub.add_parser("show", help="print a window of one session")
    p.add_argument("session")
    p.add_argument("--seq", type=int, default=0)
    p.add_argument("--span", type=int, default=5)
    p.add_argument("--width", type=int, default=400)
    p.set_defaults(fn=cmd_show)

    p = sub.add_parser("stats", help="what is in the index")
    p.add_argument("--json", action="store_true")
    p.set_defaults(fn=cmd_stats)
    return ap


def main(argv=None):
    args = build_parser().parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
