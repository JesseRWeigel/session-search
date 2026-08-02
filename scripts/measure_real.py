#!/usr/bin/env python3
"""Measure the real archive, and keep the README's numbers honest about it.

Two kinds of number live in the README and they are checked differently.

Fixture numbers are deterministic. `--check` regenerates them and demands exact equality,
so a change in the parser that alters the turn count fails the build.

Real-archive numbers are not deterministic, because the archive grows every day. Pinning
them exactly would mean a README that fails tomorrow for being true yesterday. So they
carry the date they were taken and `--check` re-measures and allows a stated drift band,
currently 40 percent, which is wide enough to survive a month of ordinary work and narrow
enough that "the index is empty" or "half the sources stopped parsing" still fails.

    python3 scripts/measure_real.py            human readable
    python3 scripts/measure_real.py --json
    python3 scripts/measure_real.py --write    rewrite the README block
    python3 scripts/measure_real.py --check    fail if the README has drifted
"""

from __future__ import annotations

import argparse
import datetime
import json
import os
import re
import statistics
import subprocess
import sys
import tempfile
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "scripts"))
sys.path.insert(0, os.path.join(ROOT, "checker"))

import leakcheck                                        # noqa: E402
import make_fixtures                                    # noqa: E402
from sessionsearch import archive, cli, indexer, rank, redact   # noqa: E402

BEGIN = "<!-- MEASURED:BEGIN -->"
END = "<!-- MEASURED:END -->"
DRIFT = 0.40

QUERIES = [
    "crlf fixture",
    "playwright chromium headless",
    "redaction leak checker",
    "sqlite fts5 index",
    "nul byte scan",
    "verify sabotage",
    "dark mode prefers-color-scheme",
    "ranking bm25",
]


def measure_real():
    path = indexer.default_index_path()
    if not os.path.exists(path):
        raise SystemExit(
            "no index at the default location. Build it first:\n"
            "    python3 -m sessionsearch.cli index\n"
            "The real-archive numbers cannot be measured without it, and reporting them "
            "as unavailable would be reporting nothing.")
    con = indexer.connect(path, create=False)
    c = indexer.counts(con)
    size = sum(os.path.getsize(path + s) for s in ("", "-wal", "-shm")
               if os.path.exists(path + s))

    raw_bytes = 0
    n_files = 0
    for src in archive.discover():
        for f in src.files:
            if os.path.isfile(f):
                raw_bytes += os.path.getsize(f)
                n_files += 1

    latencies = []
    for q in QUERIES:
        terms = rank.tokenize(q)
        t0 = time.perf_counter()
        rows, _ = indexer.candidates(con, terms, limit=4000)
        scored = rank.rank(rows, terms)
        scored[:10]
        latencies.append((time.perf_counter() - t0) * 1000.0)

    return {
        "measured_on": datetime.date.today().isoformat(),
        "sources": [s.name for s in archive.discover() if s.exists],
        "transcript_files": n_files,
        "raw_bytes": raw_bytes,
        "sessions": c["sessions"],
        "turns": c["turns"],
        "projects": c["projects"],
        "by_source": c["by_source"],
        "by_kind": c["by_kind"],
        "index_bytes": size,
        "build_seconds": float(indexer.get_meta(con, "build_seconds") or 0),
        "query_ms_median": round(statistics.median(latencies), 1),
        "query_ms_max": round(max(latencies), 1),
        "span": (datetime.date.fromtimestamp(c["first_ts"]).isoformat(),
                 datetime.date.fromtimestamp(c["last_ts"]).isoformat()),
    }


def measure_fixture():
    """Deterministic counts from the synthetic archive, plus the leak audit."""
    tmp = tempfile.mkdtemp(prefix="session-search-measure-")
    out = {}
    for variant in ("planted", "control"):
        arch = os.path.join(tmp, variant)
        make_fixtures.build(arch, variant)
        db = os.path.join(tmp, variant + ".db")
        import contextlib
        import io
        with contextlib.redirect_stdout(io.StringIO()):
            cli.main(["--index", db, "index", "--archive", arch, "--quiet"])
        con = indexer.connect(db, create=False)
        c = indexer.counts(con)
        out[variant] = {"sessions": c["sessions"], "turns": c["turns"]}
        con.close()
    out["expectations"] = len(make_fixtures.EXPECTATIONS)
    return out


def audit_real(limit=None):
    """Redact every real turn and run the independent checker over the result."""
    con = indexer.connect(indexer.default_index_path(), create=False)
    sql = "SELECT text, target FROM turns"
    if limit:
        sql += f" LIMIT {int(limit)}"
    n = 0
    findings = []
    for row in con.execute(sql):
        n += 1
        out = redact.redact(row[0]) + "\n" + redact.redact(row[1])
        findings.extend(leakcheck.scan_text(out, "turn"))
    return n, findings


def block(m):
    gb = m["raw_bytes"] / 1e9
    lines = [
        BEGIN,
        f"Measured on {m['measured_on']} against the real archive on this machine.",
        "",
        "| | |",
        "|---|---|",
        f"| sources indexed | {', '.join(m['sources'])} |",
        f"| transcript files | {m['transcript_files']:,} |",
        f"| raw transcript bytes | {gb:.2f} GB |",
        f"| sessions | {m['sessions']:,} |",
        f"| turns | {m['turns']:,} |",
        f"| distinct projects | {m['projects']:,} |",
        f"| date span | {m['span'][0]} to {m['span'][1]} |",
        f"| index size | {m['index_bytes'] / 1e6:.1f} MB |",
        f"| full rebuild | {m['build_seconds']:.1f} s |",
        f"| query latency, median of {len(QUERIES)} | {m['query_ms_median']:.1f} ms |",
        f"| query latency, worst of {len(QUERIES)} | {m['query_ms_max']:.1f} ms |",
        "",
        "Turns by kind: " + ", ".join(f"{k} {v:,}" for k, v in m["by_kind"].items()) + ".",
        "",
        "Regenerate with `python3 scripts/measure_real.py --write`.",
        END,
    ]
    return "\n".join(lines)


def read_readme():
    with open(os.path.join(ROOT, "README.md"), encoding="utf-8") as fh:
        return fh.read()


def write_block(m):
    text = read_readme()
    new = block(m)
    if BEGIN in text and END in text:
        text = re.sub(re.escape(BEGIN) + r".*?" + re.escape(END), lambda _: new,
                      text, flags=re.S)
    else:
        text = text.rstrip() + "\n\n" + new + "\n"
    with open(os.path.join(ROOT, "README.md"), "w", encoding="utf-8") as fh:
        fh.write(text)


def check(m, fx):
    text = read_readme()
    problems = []
    if BEGIN not in text or END not in text:
        return ["README has no measured-numbers block; run measure_real.py --write"]
    recorded = text[text.index(BEGIN):text.index(END)]

    def recorded_number(label):
        mm = re.search(r"\|\s*" + re.escape(label) + r"\s*\|\s*([0-9,.]+)", recorded)
        return float(mm.group(1).replace(",", "")) if mm else None

    for label, now in (("sessions", m["sessions"]), ("turns", m["turns"]),
                       ("transcript files", m["transcript_files"])):
        was = recorded_number(label)
        if was is None:
            problems.append(f"README does not record {label}")
        elif was <= 0 or abs(now - was) / max(was, 1) > DRIFT:
            problems.append(
                f"{label}: README says {was:,.0f}, the archive now has {now:,}, "
                f"which is outside the {DRIFT:.0%} drift band. "
                f"Run: python3 scripts/measure_real.py --write")

    for label, now in (("fixture sessions", fx["planted"]["sessions"]),
                       ("fixture turns", fx["planted"]["turns"]),
                       ("known answers", fx["expectations"])):
        if f"| {label} | {now} |" not in text:
            problems.append(f"README does not state {label} = {now} exactly")
    return problems


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--write", action="store_true")
    ap.add_argument("--check", action="store_true")
    ap.add_argument("--audit", action="store_true",
                    help="redact every real turn and run the independent checker")
    ap.add_argument("--audit-limit", type=int, default=0)
    a = ap.parse_args()

    if a.audit:
        n, findings = audit_real(a.audit_limit or None)
        for w, line, label, snip in findings[:40]:
            print(f"LEAK {label}: {leakcheck.redact_for_report(snip)}")
        print(f"audited {n} real turns, {len(findings)} finding(s)")
        return 1 if findings else 0

    m = measure_real()
    fx = measure_fixture()
    if a.json:
        print(json.dumps({"real": m, "fixture": fx}, indent=2))
        return 0
    if a.write:
        write_block(m)
        snapshot = os.path.join(ROOT, "docs", "measured.json")
        os.makedirs(os.path.dirname(snapshot), exist_ok=True)
        with open(snapshot, "w", encoding="utf-8") as fh:
            json.dump(m, fh, indent=2, sort_keys=True)
            fh.write("\n")
        print("README measured block and docs/measured.json rewritten")
        return 0
    if a.check:
        problems = check(m, fx)
        for p in problems:
            print("  " + p)
        print(f"README check: {len(problems)} problem(s)")
        return 1 if problems else 0
    print(block(m))
    print()
    print(f"fixture: planted {fx['planted']['sessions']} sessions / "
          f"{fx['planted']['turns']} turns, control {fx['control']['sessions']} / "
          f"{fx['control']['turns']}, {fx['expectations']} known answers")
    return 0


if __name__ == "__main__":
    sys.exit(main())
