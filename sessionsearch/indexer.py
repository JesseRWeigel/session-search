"""Build and query the SQLite FTS5 index.

Storage location. The index contains raw, unredacted transcript text, so it must never sit
inside this repository. It defaults to $XDG_DATA_HOME/session-search (or
~/.local/share/session-search) and can be moved with $SESSION_SEARCH_INDEX. `verify.sh`
asserts that the resolved default is outside the repo, and `.gitignore` covers *.db as a
second line of defence.

Why FTS5 for candidates but Python for ranking. bm25 is a good relevance score and a bad
explanation. The interesting query here is "when did I last do something like this", and
the answer wants to be defended out loud: this hit is above that one because a human typed
it, because it is three weeks old rather than three years, and because all four of your
words appear inside one sentence. So FTS5 answers "which turns contain these terms" and
`rank.py` answers "in what order", with the parts printed on request.
"""

from __future__ import annotations

import os
import sqlite3
import time

SCHEMA_VERSION = 3


def default_index_path() -> str:
    env = os.environ.get("SESSION_SEARCH_INDEX")
    if env:
        return os.path.abspath(os.path.expanduser(env))
    base = os.environ.get("XDG_DATA_HOME") or os.path.join(
        os.path.expanduser("~"), ".local", "share")
    return os.path.join(base, "session-search", "index.db")


def connect(path=None, create=True) -> sqlite3.Connection:
    path = path or default_index_path()
    if create:
        os.makedirs(os.path.dirname(path), exist_ok=True)
    elif not os.path.exists(path):
        raise FileNotFoundError(path)
    con = sqlite3.connect(path)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA journal_mode=WAL")
    con.execute("PRAGMA synchronous=NORMAL")
    return con


DDL = """
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT);

CREATE TABLE IF NOT EXISTS sessions (
  rowid       INTEGER PRIMARY KEY,
  session_id  TEXT NOT NULL,
  source      TEXT NOT NULL,
  project     TEXT NOT NULL,
  path        TEXT NOT NULL,
  title       TEXT NOT NULL DEFAULT '',
  first_ts    REAL NOT NULL DEFAULT 0,
  last_ts     REAL NOT NULL DEFAULT 0,
  turns       INTEGER NOT NULL DEFAULT 0,
  UNIQUE(source, session_id, path)
);

CREATE TABLE IF NOT EXISTS turns (
  rowid      INTEGER PRIMARY KEY,
  session    INTEGER NOT NULL REFERENCES sessions(rowid),
  seq        INTEGER NOT NULL,
  ts         REAL NOT NULL,
  kind       TEXT NOT NULL,
  tool       TEXT NOT NULL DEFAULT '',
  target     TEXT NOT NULL DEFAULT '',
  sidechain  INTEGER NOT NULL DEFAULT 0,
  truncated  INTEGER NOT NULL DEFAULT 0,
  orig_len   INTEGER NOT NULL DEFAULT 0,
  text       TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS turns_session_seq ON turns(session, seq);
CREATE INDEX IF NOT EXISTS turns_kind ON turns(kind);

CREATE VIRTUAL TABLE IF NOT EXISTS turns_fts USING fts5(
  text, target, tokenize='unicode61 remove_diacritics 2', content=''
);
"""


def init(con: sqlite3.Connection):
    con.executescript(DDL)
    con.execute("INSERT OR REPLACE INTO meta VALUES ('schema_version', ?)",
                (str(SCHEMA_VERSION),))
    con.commit()


def wipe(con: sqlite3.Connection):
    for t in ("turns_fts", "turns", "sessions", "meta"):
        con.execute(f"DROP TABLE IF EXISTS {t}")
    con.commit()
    init(con)


def add_session(con, meta, turns) -> int:
    cur = con.execute(
        "INSERT OR REPLACE INTO sessions"
        " (session_id, source, project, path, title, first_ts, last_ts, turns)"
        " VALUES (?,?,?,?,?,?,?,?)",
        (meta.session_id, meta.source, meta.project, meta.path, meta.title,
         meta.first_ts, meta.last_ts, len(turns)))
    sid = cur.lastrowid
    # Rowids are assigned explicitly rather than inferred from last_insert_rowid(), so
    # that `turns.rowid` and `turns_fts.rowid` cannot drift apart. content='' means the
    # FTS table keeps no second copy of the text, and a drift there would silently return
    # the wrong turn for every hit.
    base = con.execute("SELECT COALESCE(MAX(rowid), 0) FROM turns").fetchone()[0]
    rows = [(base + i + 1, sid, t.seq, t.ts, t.kind, t.tool, t.target,
             int(t.sidechain), int(t.truncated), t.orig_len, t.text)
            for i, t in enumerate(turns)]
    con.executemany(
        "INSERT INTO turns (rowid, session, seq, ts, kind, tool, target, sidechain,"
        " truncated, orig_len, text) VALUES (?,?,?,?,?,?,?,?,?,?,?)", rows)
    con.executemany(
        "INSERT INTO turns_fts (rowid, text, target) VALUES (?,?,?)",
        [(base + i + 1, t.text, t.target) for i, t in enumerate(turns)])
    return sid


def set_meta(con, key, value):
    con.execute("INSERT OR REPLACE INTO meta VALUES (?,?)", (key, str(value)))


def get_meta(con, key, default=None):
    row = con.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
    return row[0] if row else default


def counts(con) -> dict:
    out = {
        "sessions": con.execute("SELECT COUNT(*) FROM sessions").fetchone()[0],
        "turns": con.execute("SELECT COUNT(*) FROM turns").fetchone()[0],
        "projects": con.execute(
            "SELECT COUNT(DISTINCT project) FROM sessions").fetchone()[0],
    }
    out["by_kind"] = {r[0]: r[1] for r in con.execute(
        "SELECT kind, COUNT(*) FROM turns GROUP BY kind ORDER BY 2 DESC")}
    out["by_source"] = {r[0]: r[1] for r in con.execute(
        "SELECT source, COUNT(*) FROM sessions GROUP BY source ORDER BY 2 DESC")}
    out["by_tool"] = {r[0]: r[1] for r in con.execute(
        "SELECT tool, COUNT(*) FROM turns WHERE tool <> '' GROUP BY tool"
        " ORDER BY 2 DESC LIMIT 20")}
    row = con.execute("SELECT MIN(first_ts), MAX(last_ts) FROM sessions"
                      " WHERE first_ts > 0").fetchone()
    out["first_ts"], out["last_ts"] = (row[0] or 0.0), (row[1] or 0.0)
    return out


FTS_SPECIAL = set('"*():^{}[]')


def fts_query(terms) -> str:
    """Build an FTS5 MATCH expression that ANDs every term, quoting each one.

    Quoting matters: an unquoted term containing a hyphen or a colon is FTS5 syntax, and
    a query like `parse.py` or `sk-ant` would otherwise raise instead of searching.
    """
    parts = []
    for t in terms:
        t = t.replace('"', '""')
        parts.append(f'"{t}"')
    return " AND ".join(parts)


def candidates(con, terms, limit=4000, kind=None, tool=None, project=None,
               source=None, since=None, until=None, session=None,
               include_meta=False, sidechain=None):
    """Rows matching the filters, unranked. `terms` may be empty for a pure filter query."""
    where, args = [], []
    joins = ""
    if terms:
        joins = " JOIN turns_fts ON turns_fts.rowid = turns.rowid"
        where.append("turns_fts MATCH ?")
        args.append(fts_query(terms))
    if kind:
        where.append("turns.kind IN (%s)" % ",".join("?" * len(kind)))
        args.extend(kind)
    elif not include_meta:
        where.append("turns.kind <> 'meta'")
    if tool:
        where.append("LOWER(turns.tool) IN (%s)" % ",".join("?" * len(tool)))
        args.extend([t.lower() for t in tool])
    if project:
        where.append("sessions.project LIKE ?")
        args.append(f"%{project}%")
    if source:
        where.append("sessions.source IN (%s)" % ",".join("?" * len(source)))
        args.extend(source)
    if session:
        where.append("sessions.session_id LIKE ?")
        args.append(f"{session}%")
    if since is not None:
        where.append("turns.ts >= ?")
        args.append(since)
    if until is not None:
        where.append("turns.ts <= ?")
        args.append(until)
    if sidechain is not None:
        where.append("turns.sidechain = ?")
        args.append(int(sidechain))

    sql = ("SELECT turns.rowid AS turn_rowid, turns.session, turns.seq, turns.ts,"
           " turns.kind, turns.tool, turns.target, turns.text, turns.truncated,"
           " turns.orig_len, turns.sidechain,"
           " sessions.session_id, sessions.source, sessions.project, sessions.path,"
           " sessions.title, sessions.first_ts, sessions.last_ts"
           " FROM turns JOIN sessions ON sessions.rowid = turns.session" + joins)
    if where:
        sql += " WHERE " + " AND ".join(where)
    sql += " LIMIT ?"
    args.append(limit)
    t0 = time.perf_counter()
    rows = con.execute(sql, args).fetchall()
    return rows, (time.perf_counter() - t0)


def neighbours(con, session_rowid, seq, before=1, after=1):
    rows = con.execute(
        "SELECT seq, kind, tool, text FROM turns WHERE session=? AND seq BETWEEN ? AND ?"
        " ORDER BY seq", (session_rowid, seq - before, seq + after)).fetchall()
    return rows
