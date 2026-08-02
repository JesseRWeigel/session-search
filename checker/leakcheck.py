#!/usr/bin/env python3
"""An independent leak checker. It shares no code with the redactor, on purpose.

`sessionsearch/redact.py` decides what to hide. This file decides whether anything got
through. If the second job reused the first job's patterns it would inherit the first
job's bugs and report clean on output that was not: that exact failure has happened in
this workspace before, which is why `verify.sh` asserts that this file imports nothing
from `sessionsearch` and that the two do not share regex sources.

Written from the opposite direction. The redactor asks "what shapes do I know how to
mask"; this asks "what in these bytes looks like it should not be here", including a
generic Shannon-entropy sweep that knows no provider names at all, so a token from a
service invented next week still trips it.

Two jobs:

  scan text     the bytes this tool is about to show a human, or has written to a file
  scan a tree   every tracked file in the repository, including a NUL byte scan

The NUL scan is here because `git grep` and `grep -I` classify a file containing one NUL
byte as binary and skip it in silence, so a secret scan built on grep reports a clean tree
it never read. This scan is bytes-in-Python and has no such blind spot. `grep -P '\\x00'`
is not a substitute: it is unavailable in some builds and returns "no match" rather than
an error when it is.

    python3 checker/leakcheck.py FILE...          exit 1 if anything looks like a leak
    python3 checker/leakcheck.py --stdin
    python3 checker/leakcheck.py --tree .
"""

from __future__ import annotations

import argparse
import math
import os
import re
import subprocess
import sys

# Patterns written independently of the redactor's. Where the real credential format is
# case sensitive, so is the pattern: AWS key ids are uppercase by definition and a
# case-folded version fires on ordinary base64 inside any embedded image.
SIGNATURES = [
    ("openai/anthropic style key", re.compile(r"sk-[A-Za-z0-9]{20,}")),
    ("openai/anthropic style key", re.compile(r"sk-(?:ant|or|proj|svcacct)-[A-Za-z0-9_\-]{16,}")),
    ("stripe key", re.compile(r"[rs]k_(?:live|test)_[0-9A-Za-z]{16,}")),
    ("github token", re.compile(r"gh[a-z]_[A-Za-z0-9]{20,}")),
    ("github fine grained token", re.compile(r"github_pat_[0-9A-Za-z_]{30,}")),
    ("aws key id", re.compile(r"A(?:KIA|SIA|ROA|IDA)[0-9A-Z]{16}")),
    ("google api key", re.compile(r"AIza[0-9A-Za-z_\-]{30,}")),
    ("slack token", re.compile(r"xox[a-z]-[0-9A-Za-z\-]{10,}")),
    ("slack or discord webhook",
     re.compile(r"https://(?:hooks\.slack\.com/services|"
                r"discord(?:app)?\.com/api/webhooks)/\S{8,}")),
    ("huggingface token", re.compile(r"hf_[0-9A-Za-z]{25,}")),
    ("npm token", re.compile(r"npm_[0-9A-Za-z]{30,}")),
    ("gitlab token", re.compile(r"glpat-[0-9A-Za-z_\-]{16,}")),
    ("sendgrid key", re.compile(r"SG\.[0-9A-Za-z_\-]{16,}\.[0-9A-Za-z_\-]{16,}")),
    ("json web token",
     re.compile(r"eyJ[0-9A-Za-z_\-]{8,}\.[0-9A-Za-z_\-]{8,}\.[0-9A-Za-z_\-]{5,}")),
    ("private key block", re.compile(r"-----BEGIN[A-Z ]{0,30}PRIVATE KEY")),
    ("credentials in a url", re.compile(r"://[^\s/:@]{1,64}:[^\s/@]{1,128}@")),
    # The value must follow the delimiter closely. Allowing arbitrary whitespace lets the
    # pattern jump a masked value and match the NEXT assignment on the same line, which
    # reported a leak in redacted output that contained none.
    ("secret shaped assignment",
     re.compile(r"(?i)(?:password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key)"
                r"['\"]?\s{0,2}[=:]\s{0,2}['\"]?[^\s'\";,]{10,}")),
    # A real username: letters, digits, dot, dash, underscore. Not '<user>', not a
    # character class, so this file and the redactor can both talk about the pattern in
    # prose without tripping it, while an actual home directory still does.
    ("home directory path", re.compile(r"/(?:home|Users)/[a-z][a-z0-9._\-]{1,31}(?![\w.\-])")),
    ("windows home path", re.compile(r"[A-Za-z]:\\+Users\\+[A-Za-z][A-Za-z0-9._\-]{1,31}")),
    ("email address", re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9\-]+\.[A-Za-z]{2,}")),
    ("private network address",
     re.compile(r"(?<![\d.])(?:10\.\d{1,3}|192\.168|172\.(?:1[6-9]|2\d|3[01]))"
                r"\.\d{1,3}\.\d{1,3}(?![\d.])")),
    ("private hostname",
     re.compile(r"\b[a-zA-Z0-9][a-zA-Z0-9\-]{0,62}\.(?:local|lan|internal|home\.arpa)\b")),
    ("telephone number",
     re.compile(r"(?<![\d.\-])(?:\+?1[ .\-])?\(?\d{3}\)?[ .\-]\d{3}[ .\-]\d{4}(?![\d.\-])")),
]

# Some signatures need a second opinion on the match before it counts. Kept as a separate
# table so the patterns above stay readable, and so that loosening a validator is a
# visible edit rather than a quiet character-class change.
_DOTTED_IDENT = re.compile(r"\A[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)+\Z")
_CODE_CHARS = set("[]{}()<>$&|;`")


def _assignment_value_looks_secret(match: str) -> bool:
    """Reject the shapes that made this signature cry wolf on 51 881 real turns.

    All of these are code or prose ABOUT secrets rather than secrets:

        Secret: process.env.JWT_SECRET     a dotted identifier
        pass=0\\nfail=0                     an escaped newline let the value run on
        Token = slashParts[1]              an expression
        secret: environment                a bare word

    A real credential is either mixed case-and-digits or long. One character class and
    under twenty characters is a word, and words are not secrets.
    """
    _key, _sep, value = match.partition("=" if "=" in match else ":")
    value = value.strip().strip("'\"")
    if not value or "\\" in value:
        return False
    if _DOTTED_IDENT.match(value):
        return False
    if any(c in _CODE_CHARS for c in value):
        return False
    return classes(value) >= 2 or len(value) >= 20


VALIDATORS = {"secret shaped assignment": _assignment_value_looks_secret}

# Anything this long that looks random is suspect whatever service issued it.
ENTROPY_MIN_LEN = 24
ENTROPY_MIN_BITS = 3.7
TOKEN_SPLIT = re.compile(r"[^A-Za-z0-9+/=_\-]+")
HEXISH = re.compile(r"\A[0-9a-fA-F]{32,}\Z")

# Structural shapes that are long and random-looking and still cannot be a credential.
# They are STRIPPED from the token rather than excusing it, so SESSION=<timestamp> loses
# the timestamp and is then too short to report, while <timestamp><real secret> keeps the
# secret and is reported. An allowlist that excuses a whole token is how an auditor goes
# blind; removing the part you can account for is not.
NOT_A_SECRET = [
    re.compile(r"\d{4}-\d{2}-\d{2}[T_\- ]\d{2}[-:]\d{2}[-:]\d{2}"
               r"(?:[.\-]\d{1,6})?Z?"),                              # ISO 8601 timestamp
    re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}"
               r"-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"),                  # RFC 4122 uuid
    re.compile(r"\b(?:toolu|call|req|msg|rs|fc|ctc|chatcmpl)_[A-Za-z0-9]{8,}\b"),
]

# Separator handling for the entropy sweep.
#
# Run against 51 881 real turns, the sweep's entire false-positive population was
# separator-joined names: nvidia/nemotron-3-ultra-550b-a55b, this-package-does-not-exist-
# 9f3a2b, claude-worktrees-agent-ab469e5a. Each scores three character classes and full
# Shannon entropy while being ordinary readable text.
#
# What separates them from credentials is not vocabulary, it is contiguity. A credential
# is an unbroken run of random characters. So the sweep looks at the longest unbroken run
# inside a token, and only considers the token as a whole when it has at most two
# separators, which is what keeps the AWS example secret wJalrXUtnFEMI/K7…
# reportable while a five-segment path is not.
_IDENT_SPLIT = re.compile(r"[_\-/=+]")
# A directory name. Two tests, both cheap: the character set, and no two consecutive
# capitals. GraphiteDawnCache, GitHub, shell-snapshots and 40achingbrain are names.
# wJalrXUtnFEMI and K7M… are not, because base64 puts capitals next to each other and
# CamelCase does not, which is what keeps the AWS example secret reportable.
_PATH_SEGMENT = re.compile(r"\A-?[A-Za-z0-9][A-Za-z0-9._\-]*\Z")
_TWO_CAPITALS = re.compile(r"[A-Z]{2}")
MAX_SEPARATORS_FOR_WHOLE_TOKEN = 2

# The redactor's own output. Recognised so the checker does not report the mask as a leak,
# and deliberately narrow: only the exact bracketed form, never a bare word.
MASK = re.compile(r"\[redacted:[a-z\-]{3,40}\]")


def shannon(s: str) -> float:
    if not s:
        return 0.0
    counts = {}
    for c in s:
        counts[c] = counts.get(c, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def classes(s: str) -> int:
    return (any(c.islower() for c in s) + any(c.isupper() for c in s)
            + any(c.isdigit() for c in s) + any(c in "+/=_-" for c in s))


def _looks_like_path(tok: str) -> bool:
    """Long runs that are really paths are common and are not secrets by themselves.

    The test is the segments BEFORE the last one. A path is a chain of directory names and
    those are words, so /Projects/tasks/<17 hex characters> is a path. The AWS
    documentation example secret wJalrXUtnFEMI/K7… is not, because K7MDENG
    is not a word, and it stays reportable.
    """
    if "/" not in tok:
        return False
    segs = [s for s in tok.split("/") if s]
    return len(segs) >= 2 and all(_PATH_SEGMENT.match(s) and not _TWO_CAPITALS.search(s)
                                   for s in segs[:-1])


def _random_looking(tok: str) -> bool:
    """Does this unbroken run look like credential material rather than a word."""
    if len(tok) < ENTROPY_MIN_LEN:
        return False
    if HEXISH.match(tok):
        return True
    # A digit is required because a long SCREAMING_SNAKE identifier scores three character
    # classes and full Shannon entropy without being random at all.
    return (classes(tok) >= 3 and any(c.isdigit() for c in tok)
            and shannon(tok) >= ENTROPY_MIN_BITS and not _looks_like_path(tok))


def entropy_findings(text: str):
    out = []
    for raw in TOKEN_SPLIT.split(text):
        if len(raw) < ENTROPY_MIN_LEN:
            continue
        tok = raw
        for pat in NOT_A_SECRET:
            tok = pat.sub("", tok)
        parts = [p for p in _IDENT_SPLIT.split(tok) if p]
        separators = max(0, len(parts) - 1)
        label = "high entropy hex run" if HEXISH.match(tok) else "high entropy token"
        if separators <= MAX_SEPARATORS_FOR_WHOLE_TOKEN and _random_looking(tok):
            out.append((label, tok))
            continue
        longest = max(parts, key=len) if parts else ""
        if _random_looking(longest):
            out.append((label, longest))
    return out


def scan_text(text: str, where="<text>"):
    """Return a list of (where, line_no, label, matched_snippet)."""
    findings = []
    for line_no, line in enumerate(text.splitlines(), 1):
        # Masks collapse to a single character that no signature can build on: replacing
        # them with a space let the assignment pattern read across the gap and pair a key
        # name with the next line's value, and replacing them with a letter turned
        # postgres://<mask>@host into an email address.
        stripped = MASK.sub("·", line)
        for label, pat in SIGNATURES:
            for m in pat.finditer(stripped):
                validator = VALIDATORS.get(label)
                if validator and not validator(m.group(0)):
                    continue
                findings.append((where, line_no, label, m.group(0)))
        for label, tok in entropy_findings(stripped):
            findings.append((where, line_no, label, tok))
    return findings


def scan_bytes_for_nul(data: bytes):
    """Every NUL offset in these bytes. Python, not grep, for the reason in the docstring."""
    out, start = [], 0
    while True:
        i = data.find(b"\x00", start)
        if i < 0:
            return out
        out.append(i)
        start = i + 1


# A source file that TESTS a redactor has to contain things that look like secrets, and a
# tree scan that reports them is a tree scan nobody reads. A line carrying this marker is
# exempt when scanning FILES.
#
# Three properties keep this from being a hole. It never applies to rendered output, which
# is the path that matters and has no escape hatch of any kind. It never applies to NUL
# bytes. And verify.sh counts the marked lines and fails if the number changes, so adding
# one is a reviewed edit rather than a quiet one.
MARKER = "synthetic-fixture"


def scan_file(path, text_rules=True, honour_marker=True):
    with open(path, "rb") as fh:
        data = fh.read()
    findings = []
    for off in scan_bytes_for_nul(data):
        findings.append((path, 0, "NUL byte (makes this file invisible to git grep)",
                         f"offset {off}"))
    if text_rules:
        try:
            text = data.decode("utf-8", errors="replace")
        except Exception as exc:                                   # noqa: BLE001
            findings.append((path, 0, "unreadable", str(exc)))
            return findings
        lines = text.splitlines()
        for f in scan_text(text, path):
            line_no = f[1]
            if honour_marker and 1 <= line_no <= len(lines) and MARKER in lines[line_no - 1]:
                continue
            findings.append(f)
    return findings


def marked_lines(root):
    """Lines whose marker is actually suppressing a finding, so verify can count them.

    Counting every line that merely mentions the marker would include this file and the
    README, and a count that drifts for documentation edits is a count nobody maintains.
    What matters is how many findings the exemption is hiding.
    """
    out = []
    for f in tracked_files(root):
        if not os.path.isfile(f):
            continue
        try:
            with open(f, encoding="utf-8") as fh:
                lines = fh.read().splitlines()
        except (UnicodeDecodeError, OSError):
            continue
        suppressed = {n for _w, n, _l, _s in scan_file(f, honour_marker=False)}
        for n in sorted(suppressed):
            if 1 <= n <= len(lines) and MARKER in lines[n - 1]:
                out.append((f, n))
    return out


def tracked_files(root):
    out = subprocess.run(["git", "-C", root, "ls-files", "-z"],
                         capture_output=True, check=True)
    return [os.path.join(root, p) for p in out.stdout.decode().split("\0") if p]


def redact_for_report(snippet: str) -> str:
    """Report that something leaked without leaking it again in the report."""
    s = snippet.strip()
    if len(s) <= 12:
        return s
    return s[:6] + "…" + s[-4:] + f" ({len(s)} chars)"


def main(argv=None):
    ap = argparse.ArgumentParser(description="independent leak checker")
    ap.add_argument("files", nargs="*")
    ap.add_argument("--stdin", action="store_true")
    ap.add_argument("--tree", help="scan every git-tracked file under this directory")
    ap.add_argument("--quiet", action="store_true")
    ap.add_argument("--strict", action="store_true",
                    help="ignore synthetic-fixture markers")
    ap.add_argument("--count-markers", action="store_true")
    ap.add_argument("--expect-findings", type=int, default=None,
                    help="exit 0 only if exactly this many findings appear "
                         "(used by negative controls)")
    a = ap.parse_args(argv)

    findings = []
    n_scanned = 0
    if a.stdin:
        findings += scan_text(sys.stdin.read(), "<stdin>")
        n_scanned += 1
    for f in a.files:
        findings += scan_file(f, honour_marker=not a.strict)
        n_scanned += 1
    if a.tree:
        if a.count_markers:
            for path, line in marked_lines(a.tree):
                print(f"{path}:{line}")
            print(f"leakcheck: {len(marked_lines(a.tree))} marked line(s)")
            return 0
        for f in tracked_files(a.tree):
            if os.path.isfile(f):
                findings += scan_file(f, honour_marker=not a.strict)
                n_scanned += 1

    if not a.quiet:
        for where, line, label, snippet in findings:
            print(f"LEAK {where}:{line}: {label}: {redact_for_report(snippet)}")
        print(f"leakcheck: {len(findings)} finding(s) across {n_scanned} input(s)")

    if a.expect_findings is not None:
        return 0 if len(findings) == a.expect_findings else 1
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
