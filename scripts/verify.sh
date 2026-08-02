#!/usr/bin/env bash
# Verification for session-search.
#
# The thing this project can most plausibly get wrong is passing while leaking, so the
# security checks are the ones with negative controls attached, and several checks exist
# only to prove that another check can still go red:
#
#    3  the unit suite, with a floor on the number of assertions that actually ran
#    5  a NUL byte scan in Python, PLUS a demonstration that git grep is blind to it
#    7  every known answer found in the planted fixture archive
#    8  the same queries finding nothing in the control archive, and proof the control
#       archive is not simply empty
#   10  the whole real archive redacted and audited by the independent checker
#   11  a negative control for check 10: the same audit over UNREDACTED text must find
#       plenty, otherwise a clean report means the checker was asleep
#   14  the page loaded in a real browser at two viewports
#   15  a negative control for check 14: a deliberately broken page must fail it
#   16  seven sabotages of the parser, ranker, redactor, excerpter and index, each
#       proved to have changed real output before any conclusion is drawn
#
# Nothing here writes to the working tree, and nothing derived from the real archive is
# left behind: the real index is built into a temporary directory and deleted.
#
# Run:  bash scripts/verify.sh
set -uo pipefail
cd "$(dirname "$0")/.."
ROOT="$PWD"

pass=0
fail=0
ok()  { printf '  ok    %s\n' "$1"; pass=$((pass + 1)); }
bad() { printf '  FAIL  %s\n' "$1"; fail=$((fail + 1)); }
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
# Paths get pasted into the README, so $HOME never appears in them. The replacement tilde
# must be escaped: bash expands an unescaped ~ on the right hand side of ${x/#$HOME/~} and
# the substitution then silently does nothing.
tidy() { printf '%s' "${1/#$HOME/\~}"; }

echo "1. toolchain"
if command -v python3 >/dev/null 2>&1 && command -v node >/dev/null 2>&1; then
  if python3 - <<'PY'
import sqlite3, sys
c = sqlite3.connect(":memory:")
try:
    c.execute("create virtual table t using fts5(a)")
except Exception as exc:
    sys.exit(f"this python's sqlite3 has no FTS5: {exc}")
PY
  then ok "python3 $(python3 -V 2>&1 | cut -d' ' -f2) with FTS5, node $(node --version)"
  else bad "python3's sqlite3 is built without FTS5; the index cannot be created"; fi
else
  bad "python3 and node are both required"
fi

echo
echo "2. no third party dependencies, so nothing in this suite can skip on a missing install"
if python3 - <<'PY'
import pathlib, sys
bad = []
for p in pathlib.Path(".").rglob("*.py"):
    if any(part in {".git", "__pycache__"} for part in p.parts):
        continue
    for line in p.read_text(encoding="utf-8").splitlines():
        s = line.strip()
        if s.startswith(("import ", "from ")) and any(
                m in s for m in ("numpy", "requests", "flask", "pydantic", "rich",
                                 "click", "sqlalchemy", "whoosh", "lancedb")):
            bad.append(f"{p}: {s}")
if bad:
    print("\n".join(bad))
    sys.exit(1)
for name in ("requirements.txt", "package.json", "pyproject.toml"):
    if pathlib.Path(name).exists():
        print(f"{name} exists; this project declares no dependencies")
        sys.exit(1)
PY
then ok "standard library only"; else bad "a third party dependency crept in"; fi

echo
echo "3. unit suite"
TEST="$work/tests.txt"
if python3 -m unittest discover -s tests -t tests -v >"$TEST" 2>&1; then
  n=$(grep -cE '\.\.\. ok$' "$TEST")
  if [ "$n" -ge 70 ]; then ok "$n tests passed"
  else bad "only $n tests ran; the suite did not execute"; fi
else
  grep -E '^(FAIL|ERROR):' "$TEST" | head -10
  bad "the unit suite failed"
fi

echo
echo "4. the index never lives inside the repository"
if python3 - <<'PY'
import os, sys
sys.path.insert(0, ".")
from sessionsearch import indexer
root = os.path.abspath(".")
p = os.path.abspath(indexer.default_index_path())
if p.startswith(root + os.sep):
    sys.exit(f"the default index path is inside the repo: {p}")
home = os.path.expanduser("~")
print("default index:", p.replace(home, "~"))
PY
then
  if grep -q '^\*\.db$' .gitignore && grep -q '^\*\.db-wal$' .gitignore; then
    ok "default index is outside the repo and *.db is gitignored"
  else bad ".gitignore does not cover *.db and *.db-wal"; fi
else bad "the default index path is inside the repository"; fi

echo
echo "5. NUL byte scan, in Python, plus proof that git grep cannot do this job"
if python3 - <<'PY'
import os, subprocess, sys, tempfile
sys.path.insert(0, "checker")
import leakcheck

# Positive: a NUL followed by a credential-shaped string, assembled at run time so no
# complete pattern exists on disk.
tmp = tempfile.mkdtemp()
subprocess.run(["git", "init", "-q", tmp], check=True)
path = os.path.join(tmp, "poisoned.txt")
token = "ghp_" + "".join("abcdefghij"[(i * 7) % 10] for i in range(36))
with open(path, "wb") as fh:
    fh.write(b"ordinary text\x00" + token.encode() + b"\n")
subprocess.run(["git", "-C", tmp, "add", "-A"], check=True)

findings = leakcheck.scan_file(path)
labels = {f[2] for f in findings}
if not any("NUL" in x for x in labels):
    sys.exit("the Python scan missed the NUL byte")
if "github token" not in labels:
    sys.exit("the Python scan missed the token hidden behind the NUL byte")

# Negative: git grep -I reports nothing at all, which is the silent failure this exists
# to prevent. If a future git DID find it, that is worth knowing, so say so and fail.
out = subprocess.run(["git", "-C", tmp, "grep", "-I", "-n", "ghp_"],
                     capture_output=True, text=True)
if out.stdout.strip():
    sys.exit("git grep -I found the token; this environment no longer demonstrates the "
             "blind spot, so the claim in the README needs revisiting")

# Control: the same scan must stay quiet on a clean file.
clean = os.path.join(tmp, "clean.txt")
with open(clean, "w") as fh:
    fh.write("nothing to see here\n")
if leakcheck.scan_file(clean):
    sys.exit("the scan reported a finding in a clean file")
print("python found NUL + token; git grep -I found nothing; clean file stayed clean")
PY
then ok "NUL scan works and git grep demonstrably does not"; else bad "NUL scan check"; fi

echo
echo "6. every tracked file, scanned for credentials, home paths and NUL bytes"
SWEEP="$work/sweep.txt"
if python3 checker/leakcheck.py --tree . >"$SWEEP" 2>&1; then
  ok "$(tail -1 "$SWEEP")"
else
  head -20 "$SWEEP"
  bad "a tracked file carries something that must not be committed"
fi
if git ls-files -z | xargs -0 -r du -b 2>/dev/null | sort -rn | head -1 \
   | awk '{ exit ($1 > 1000000) ? 1 : 0 }'; then
  ok "no tracked file exceeds 1 MB"
else
  git ls-files -z | xargs -0 -r du -b | sort -rn | head -3
  bad "a tracked file is over 1 MB; check for committed build output"
fi
# The sweep above honours a per-line marker on deliberately synthetic fixture data. That
# exemption is only safe while it stays small and reviewed, so the count is pinned here
# and adding one has to be a deliberate edit to this file too.
EXPECTED_MARKERS=20
markers=$(python3 checker/leakcheck.py --tree . --count-markers | tail -1 | grep -oE '[0-9]+')
if [ "${markers:-x}" = "$EXPECTED_MARKERS" ]; then
  ok "$markers synthetic-fixture exemptions, matching the pinned count"
else
  python3 checker/leakcheck.py --tree . --count-markers | head -30
  bad "there are ${markers:-?} synthetic-fixture exemptions, pinned at $EXPECTED_MARKERS"
fi
# And a second sweep with no exemptions at all, for the things that can never be
# legitimate here: this machine's own home path, this account's name, and NUL bytes.
if python3 - <<'PY'
import os, re, sys, subprocess
sys.path.insert(0, "checker")
import leakcheck

home = os.path.expanduser("~")
user = os.path.basename(home)
patterns = [(home, "this machine's home directory"),
            (os.sep + "home" + os.sep + user, "this account's home directory")]
word = re.compile(r"(?<![A-Za-z0-9])" + re.escape(user) + r"(?![A-Za-z0-9])", re.I)

problems = []
for f in leakcheck.tracked_files("."):
    if not os.path.isfile(f):
        continue
    with open(f, "rb") as fh:
        data = fh.read()
    if b"\x00" in data:
        problems.append(f"{f}: contains a NUL byte")
    text = data.decode("utf-8", errors="replace")
    for needle, why in patterns:
        if needle in text:
            problems.append(f"{f}: contains {why}")
    # LICENSE names the copyright holder on purpose, which is the one place the account
    # name is meant to appear. Everywhere else it is a leak.
    if len(user) >= 4 and os.path.basename(f) != "LICENSE" and word.search(text):
        problems.append(f"{f}: names this account")
for p in problems:
    print("   ", p)
print(f"marker-blind sweep: {len(problems)} problem(s)")
sys.exit(1 if problems else 0)
PY
then ok "no home path, account name or NUL byte in any tracked file, no exemptions"
else bad "a tracked file carries this machine's identity"; fi

echo
echo "7. the planted fixture archive: every known answer is found, first"
if python3 - <<'PY'
import contextlib, io, json, os, sys, tempfile
sys.path.insert(0, "."); sys.path.insert(0, "scripts")
import make_fixtures
from sessionsearch import cli

tmp = tempfile.mkdtemp()
arch = os.path.join(tmp, "planted")
make_fixtures.build(arch, "planted")
db = os.path.join(tmp, "planted.db")
with contextlib.redirect_stdout(io.StringIO()):
    cli.main(["--index", db, "index", "--archive", arch, "--quiet"])

problems = []
for exp in make_fixtures.EXPECTATIONS:
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(io.StringIO()):
        code = cli.main(["--index", db, "search", exp["query"], "--json", "--limit", "3"])
    hits = json.loads(buf.getvalue() or "[]")
    if code != 0 or not hits:
        problems.append(f"{exp['query']!r} returned nothing")
        continue
    if not hits[0]["session_id"].startswith(exp["expect"]):
        problems.append(f"{exp['query']!r} top hit is {hits[0]['session_id'][:8]}, "
                        f"expected {exp['expect'][:8]}: {exp['why']}")
    elif hits[0]["kind"] != exp["kind"]:
        problems.append(f"{exp['query']!r} top hit kind is {hits[0]['kind']}, "
                        f"expected {exp['kind']}")
for p in problems:
    print("   ", p)
print(f"{len(make_fixtures.EXPECTATIONS) - len(problems)} of "
      f"{len(make_fixtures.EXPECTATIONS)} known answers found first")
sys.exit(1 if problems else 0)
PY
then ok "all known answers rank first"; else bad "a planted answer was not found"; fi

echo
echo "8. the control archive: the same queries must find nothing, and it is not empty"
if python3 - <<'PY'
import contextlib, io, json, os, sys, tempfile
sys.path.insert(0, "."); sys.path.insert(0, "scripts")
import make_fixtures
from sessionsearch import cli, indexer

tmp = tempfile.mkdtemp()
arch = os.path.join(tmp, "control")
make_fixtures.build(arch, "control")
db = os.path.join(tmp, "control.db")
with contextlib.redirect_stdout(io.StringIO()):
    cli.main(["--index", db, "index", "--archive", arch, "--quiet"])

con = indexer.connect(db, create=False)
turns = con.execute("SELECT COUNT(*) FROM turns").fetchone()[0]
if turns < 20:
    sys.exit(f"the control archive holds only {turns} turns, so finding nothing in it "
             f"would prove nothing")

problems = []
checked = 0
for exp in make_fixtures.EXPECTATIONS:
    if not exp["control"]:
        continue
    checked += 1
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(io.StringIO()):
        code = cli.main(["--index", db, "search", exp["query"], "--json"])
    hits = json.loads(buf.getvalue() or "[]")
    if hits or code == 0:
        problems.append(f"{exp['query']!r} matched {len(hits)} turn(s) in the control")
if not checked:
    sys.exit("no control expectations exist, so this check is vacuous")

# And the control archive still answers questions that ARE in it.
buf = io.StringIO()
with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(io.StringIO()):
    cli.main(["--index", db, "search", "slerp camera rig", "--json"])
if not json.loads(buf.getvalue() or "[]"):
    sys.exit("the control archive answers nothing at all, so it is not a control")

for p in problems:
    print("   ", p)
print(f"{checked} absent needles, {turns} turns in the control archive, "
      f"{len(problems)} false positives")
sys.exit(1 if problems else 0)
PY
then ok "the control archive returns nothing for absent needles"; else bad "control archive check"; fi

echo
echo "9. the checker is independent of the redactor"
if python3 - <<'PY'
import re, sys
sys.path.insert(0, "."); sys.path.insert(0, "checker")
src = open("checker/leakcheck.py", encoding="utf-8").read()
for forbidden in ("import sessionsearch", "from sessionsearch", "import redact",
                  "from redact"):
    if forbidden in src:
        sys.exit(f"checker/leakcheck.py contains {forbidden!r}")
import leakcheck
from sessionsearch import redact
a = {p.pattern for _l, p, _g in redact._RULES}
b = {p.pattern for _l, p in leakcheck.SIGNATURES}
shared = a & b
if shared:
    sys.exit(f"{len(shared)} regex(es) are shared verbatim: {sorted(shared)[:2]}")
print(f"{len(a)} redactor patterns, {len(b)} checker patterns, 0 shared")
PY
then ok "no shared imports and no shared patterns"; else bad "the checker is not independent"; fi

echo
echo "10. the whole real archive: redacted, then audited by the independent checker"
REAL_DB="$work/real.db"
BUILD="$work/build.txt"
if SESSION_SEARCH_INDEX="$REAL_DB" python3 -m sessionsearch.cli index --quiet >"$BUILD" 2>&1; then
  sed 's/^/    /' "$BUILD" | grep -E 'indexed|kinds|skipped|built' | head -4
  ok "real archive indexed"
else
  cat "$BUILD"
  bad "indexing the real archive failed"
fi
AUDIT="$work/audit.txt"
if SESSION_SEARCH_INDEX="$REAL_DB" python3 scripts/measure_real.py --audit >"$AUDIT" 2>&1; then
  ok "$(tail -1 "$AUDIT")"
else
  head -15 "$AUDIT"
  bad "the independent checker found something in redacted real output"
fi

echo
echo "11. negative control for check 10: the same audit over UNREDACTED text must fail"
export REAL_DB="$REAL_DB"
if python3 - <<'PY'
import os, sys
sys.path.insert(0, "."); sys.path.insert(0, "checker")
import leakcheck
from sessionsearch import indexer

db = os.environ["REAL_DB"]
con = indexer.connect(db, create=False)
rows = con.execute("SELECT text FROM turns LIMIT 4000").fetchall()
raw = sum(len(leakcheck.scan_text(r[0])) for r in rows)
if raw < 50:
    sys.exit(f"only {raw} findings in 4000 UNREDACTED turns; the checker is not looking "
             f"hard enough for a clean redacted report to mean anything")
print(f"{raw} findings in the first 4000 unredacted turns, 0 after redaction")
PY
then ok "the audit demonstrably fires on unredacted content"; else bad "negative control for the audit"; fi

echo
echo "12. README numbers still describe reality"
READMECHK="$work/readme.txt"
if SESSION_SEARCH_INDEX="$REAL_DB" python3 scripts/measure_real.py --check >"$READMECHK" 2>&1; then
  ok "$(tail -1 "$READMECHK")"
else
  cat "$READMECHK"
  bad "the README's numbers no longer match the archive or the fixtures"
fi

echo
echo "13. the page is freshly generated and self contained"
if python3 scripts/build_docs.py --check >"$work/docs.txt" 2>&1; then
  ok "docs/index.html matches its generator"
else
  head -8 "$work/docs.txt"
  bad "docs/index.html is stale"
fi
if grep -nE '(src|href)[[:space:]]*=[[:space:]]*"(https?:)?//|@import[[:space:]]+url|fonts\.(googleapis|gstatic)|cdn\.' docs/index.html; then
  bad "docs/index.html references something remote"
else
  ok "no remote references"
fi
if head -1 docs/index.html | grep -qi '<!doctype html>' \
   && grep -qi '<meta charset="utf-8">' docs/index.html \
   && grep -qi 'name="viewport"' docs/index.html; then
  ok "doctype, charset and viewport present"
else
  bad "docs/index.html is missing a doctype, charset or viewport"
fi

echo
echo "14. the page loaded in a real browser"
browser_ok=1
for size in "390 844" "1280 900"; do
  set -- $size
  if OUT="$(node scripts/browser_check.mjs docs/index.html "$1" "$2" 2>&1)"; then
    ok "$1x$2: $(printf '%s' "$OUT" | head -c 200)"
  else
    printf '%s\n' "$OUT" | head -8
    bad "browser check at $1x$2"
    browser_ok=0
  fi
done

echo
echo "15. negative control for check 14: a broken page must fail the browser check"
BROKEN="$work/broken.html"
python3 - "$BROKEN" <<'PY'
import sys
src = open("docs/index.html", encoding="utf-8").read()
# One unbalanced parenthesis. The file still parses as HTML and renders as text; only the
# script dies, which is exactly the failure that unit tests cannot see.
broken = src.replace('(function () {', '(function () { (', 1)
assert broken != src, "the sabotage did not apply"
open(sys.argv[1], "w", encoding="utf-8").write(broken)
PY
if [ "$browser_ok" = "1" ]; then
  if node scripts/browser_check.mjs "$BROKEN" 390 844 >"$work/broken.txt" 2>&1; then
    bad "the browser check passed a page whose script cannot parse"
  else
    ok "broken page rejected: $(grep -m1 -- '- ' "$work/broken.txt" | head -c 120)"
  fi
else
  bad "skipping the negative control because check 14 did not run cleanly"
fi

echo
echo "16. sabotages, each proved to change real output before anything is concluded"
SAB="$work/sabotage.txt"
if python3 scripts/sabotage.py >"$SAB" 2>&1; then
  sed 's/^/  /' "$SAB" | sed 's/^  //'
  ok "$(tail -1 "$SAB")"
else
  cat "$SAB"
  bad "a sabotage did not prove itself, or the suite failed to notice one"
fi

echo
echo "17. the README describes this run"
total=$((pass + fail + 1))
LINE="session-search verify: $total checks, 0 failures"
problems=0
[ -f README.md ] || { echo "    README.md is missing"; problems=1; }
grep -q '^## Status' README.md 2>/dev/null || { echo "    README has no Status section"; problems=1; }
grep -qF "$LINE" README.md 2>/dev/null || {
  echo "    README's Status section does not contain: $LINE"; problems=1; }
grep -q 'TODO' README.md 2>/dev/null && { echo "    README still contains TODO"; problems=1; }
if [ "$problems" = "0" ]; then ok "README carries this run's summary line"
else bad "README is stale"; fi

echo
if [ "$fail" -eq 0 ]; then
  echo "session-search verify: $((pass + fail)) checks, 0 failures"
  exit 0
fi
echo "session-search verify: $((pass + fail)) checks, $fail failures"
exit 1
