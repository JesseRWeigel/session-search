#!/usr/bin/env python3
"""Break this tool on purpose, and refuse to draw conclusions from an attack that missed.

An unverified sabotage is a no-op with a confident write-up attached. Three times in this
workspace an attack "passed" because the attack itself did nothing: a list that was never
emptied, a field the renderer never read, a value the code path never consulted. Each time
the honest-looking conclusion was "the checks have a gap", and each time the checks were
fine and somebody weakened one that worked.

So every sabotage here is a three-step proof:

  1. The patch APPLIED. Exactly one textual replacement, and the file bytes changed.
  2. The output CHANGED. The probe is run before and after in identical conditions and
     the two outputs are compared. If they match, this script FAILS, because an attack
     that changes nothing tells you nothing about the checks.
  3. The check NOTICED. The assertion that is supposed to catch this now fails.

Only after all three does a green verify mean anything.

    python3 scripts/sabotage.py            run every sabotage
    python3 scripts/sabotage.py --list
    python3 scripts/sabotage.py --only rank-flat
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Each sabotage: a single textual edit, a probe command, and what the probe should stop
# being able to do. `guard` names the assertion in the suite that must now fail.
SABOTAGES = [
    {
        "name": "parse-drop-tool-calls",
        "why": "If tool calls were not indexed, 'which file did I edit' silently stops "
               "working while every text search still looks fine.",
        "file": "sessionsearch/parse.py",
        "old": '                        elif bt == "tool_use":',
        "new": '                        elif bt == "tool_use_NEVER":',
        "probe": ["search", "importer.py", "--kind", "tool_input", "--json"],
        "guard": "tests/test_search.py TestFilters.test_kind_filter",
    },
    {
        "name": "rank-flat-kinds",
        "why": "With every kind worth the same, sixty lines of log shouting CRLF beat "
               "the sentence you actually typed.",
        "file": "sessionsearch/rank.py",
        "old": 'KIND_POINTS = {\n    "user_request": 5,',
        "new": 'KIND_POINTS = {\n    "user_request": 1,',
        "probe": ["search", "crlf importer", "--limit", "1", "--json"],
        "guard": "tests/test_rank.py TestOrdering.test_a_request_outranks_a_shouting_log",
    },
    {
        "name": "rank-invert-recency",
        "why": "Recency is the whole point of 'when did I last do this'. Inverted, the "
               "oldest copy of an identical sentence wins.",
        "file": "sessionsearch/rank.py",
        "old": "RECENCY_BANDS = ((7, 3), (30, 2), (180, 1))",
        "new": "RECENCY_BANDS = ((7, -3), (30, -2), (180, -1))",
        "probe": ["search", "flaky websocket reconnect", "--limit", "1", "--json"],
        "guard": "tests/test_rank.py TestOrdering.test_recency_decides_between_identical_turns",
    },
    {
        "name": "redact-drop-aws-rule",
        "why": "One missing rule in the redactor is the failure this whole project is "
               "built around, and it must be the independent checker that notices.",
        "file": "sessionsearch/redact.py",
        "old": '    ("aws-access-key-id", re.compile(r"(?:AKIA|ASIA|AROA|AIDA)[0-9A-Z]{16}"), 0),',
        "new": '    ("aws-access-key-id", re.compile(r"MATCHES-NOTHING-AT-ALL-EVER"), 0),',
        "probe": ["show", "aa11bb22-0000-4000-8000-000000000003", "--seq", "1",
                  "--span", "0", "--width", "600"],
        "guard": "tests/test_leakcheck.py TestAgainstTheRealPipeline",
    },
    {
        "name": "redact-drop-private-ip-rule",
        "why": "The AWS sabotage above is caught by the redactor's own start-up self "
               "check, which is a guard rail rather than an audit. This one removes a "
               "rule the self check does not look at, so the ONLY thing that can notice "
               "is the independently written checker reading the rendered bytes.",
        "file": "sessionsearch/redact.py",
        "old": '    text, n = _PRIVATE_IP.subn(PLACEHOLDER.format("private-ip"), text)',
        "new": '    n = 0  # sabotage: the private address rule no longer runs',
        "probe": ["show", "aa11bb22-0000-4000-8000-000000000003", "--seq", "3",
                  "--span", "0", "--width", "900"],
        "guard": "tests/test_leakcheck.py "
                 "TestAgainstTheRealPipeline.test_search_output_over_every_fixture_turn_is_clean",
    },
    {
        "name": "excerpt-dump-everything",
        "why": "A result that dumps the whole turn is not a result. This is the failure "
               "mode that looks like success in a screenshot.",
        "file": "sessionsearch/excerpt.py",
        "old": "def snip(text: str, terms, width=WIDTH):",
        "new": "def snip(text: str, terms, width=WIDTH):\n    return text  # sabotage",
        "probe": ["search", "crlf", "--kind", "tool_output", "--limit", "1", "--json"],
        "guard": "tests/test_search.py TestResultShape",
    },
    {
        "name": "index-rowid-drift",
        "why": "The FTS table stores no copy of the text, so if its rowids drift from the "
               "turns table every hit returns somebody else's turn. The scores would "
               "still look plausible.",
        "file": "sessionsearch/indexer.py",
        "old": '        "INSERT INTO turns_fts (rowid, text, target) VALUES (?,?,?)",\n'
               '        [(base + i + 1, t.text, t.target) for i, t in enumerate(turns)])',
        "new": '        "INSERT INTO turns_fts (rowid, text, target) VALUES (?,?,?)",\n'
               '        [(base + i + 2, t.text, t.target) for i, t in enumerate(turns)])',
        "probe": ["search", "crlf importer", "--limit", "3", "--json"],
        "guard": "tests/test_search.py TestKnownAnswers",
    },
]


def run(cmd, cwd, env=None):
    e = dict(os.environ)
    e.update(env or {})
    p = subprocess.run(cmd, cwd=cwd, env=e, capture_output=True, text=True)
    return p.returncode, p.stdout, p.stderr


def prepare(dest):
    """A working copy of the tree, plus a fixture archive and index inside it."""
    shutil.copytree(ROOT, dest, ignore=shutil.ignore_patterns(
        ".git", "__pycache__", "*.db", "*.db-wal", "*.db-shm", "node_modules"))
    arch = os.path.join(dest, "_arch")
    rc, out, err = run([sys.executable, "scripts/make_fixtures.py", arch,
                        "--variant", "planted"], dest)
    if rc:
        raise SystemExit("could not build the fixture archive: " + err)
    return dest, arch


def build_index(tree, arch, db):
    rc, out, err = run([sys.executable, "-m", "sessionsearch.cli", "--index", db,
                        "index", "--archive", arch, "--quiet"], tree)
    if rc:
        raise SystemExit("could not build the fixture index: " + err)


def probe_output(tree, arch, db, probe):
    build_index(tree, arch, db)
    rc, out, err = run([sys.executable, "-m", "sessionsearch.cli", "--index", db] + probe,
                       tree)
    return f"exit={rc}\n{out}"


def one(sab, verbose=True):
    """Returns (ok, message). ok is False when the sabotage failed to prove itself."""
    work = tempfile.mkdtemp(prefix="session-search-sabotage-")
    try:
        tree = os.path.join(work, "tree")
        tree, arch = prepare(tree)
        db = os.path.join(work, "fixture.db")

        before = probe_output(tree, arch, db, sab["probe"])

        target = os.path.join(tree, sab["file"])
        with open(target, encoding="utf-8") as fh:
            src = fh.read()
        n = src.count(sab["old"])
        if n != 1:
            return False, (f"the patch text appears {n} times in {sab['file']}, so the "
                           f"sabotage would not have applied cleanly. An attack that did "
                           f"not apply proves nothing.")
        patched = src.replace(sab["old"], sab["new"])
        if patched == src:
            return False, f"the replacement changed nothing in {sab['file']}"
        with open(target, "w", encoding="utf-8") as fh:
            fh.write(patched)

        after = probe_output(tree, arch, db, sab["probe"])

        if after == before:
            return False, ("the output is byte identical with the sabotage in place, so "
                           "this attack is a no-op and says nothing about the checks. "
                           "Fix the attack before drawing any conclusion from it.")

        rc, out, err = run([sys.executable, "-m", "unittest", "discover", "-s", "tests",
                            "-t", "tests"], tree)
        if rc == 0:
            return False, ("the sabotage changed real output and the test suite still "
                           "passed. That is a genuine gap: " + sab["guard"])

        failures = [line for line in (err or "").splitlines()
                    if line.startswith(("FAIL:", "ERROR:"))]
        return True, (f"output changed, suite went red with {len(failures)} failing "
                      f"assertion(s), first: "
                      + (failures[0][:100] if failures else "(none named)"))
    finally:
        shutil.rmtree(work, ignore_errors=True)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--list", action="store_true")
    ap.add_argument("--only")
    a = ap.parse_args()

    if a.list:
        for s in SABOTAGES:
            print(f"{s['name']:<24} {s['file']}")
        return 0

    todo = [s for s in SABOTAGES if not a.only or s["name"] == a.only]
    if not todo:
        print(f"no sabotage named {a.only!r}")
        return 2

    bad = 0
    for s in todo:
        ok, msg = one(s)
        print(f"  {'ok  ' if ok else 'FAIL'}  {s['name']}: {msg}")
        if not ok:
            bad += 1
    print(f"sabotage: {len(todo) - bad} of {len(todo)} proved")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
