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
     re.compile(r"https://(?:hooks\.slack\.com|discord(?:app)?\.com/api)/\S{8,}")),
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
     re.compile(r"(?i)(?:pass(?:word|wd)?|secret|token|api[_-]?key|access[_-]?key)"
                r"['\"]?\s{0,2}[=:]\s{0,2}['\"]?[^\s'\";,)]{10,}")),
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

# Anything this long that looks random is suspect whatever service issued it.
ENTROPY_MIN_LEN = 24
ENTROPY_MIN_BITS = 3.7
TOKEN_SPLIT = re.compile(r"[^A-Za-z0-9+/=_\-]+")
HEXISH = re.compile(r"\A[0-9a-fA-F]{32,}\Z")

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

    A separate signature catches home directories, so this only decides whether the
    entropy sweep should shout. Kept independent of the redactor's version of the same
    idea: here the test is that the token contains a slash and any segment is a short
    word, which is a different question from the redactor's average-segment-length test.
    """
    if "/" not in tok:
        return False
    segs = [s for s in tok.split("/") if s]
    return len(segs) >= 2 and sum(1 for s in segs if len(s) <= 12) >= len(segs) - 1


def entropy_findings(text: str):
    out = []
    for tok in TOKEN_SPLIT.split(text):
        if len(tok) < ENTROPY_MIN_LEN:
            continue
        if HEXISH.match(tok):
            out.append(("high entropy hex run", tok))
            continue
        if classes(tok) >= 3 and shannon(tok) >= ENTROPY_MIN_BITS and not _looks_like_path(tok):
            out.append(("high entropy token", tok))
    return out


def scan_text(text: str, where="<text>"):
    """Return a list of (where, line_no, label, matched_snippet)."""
    findings = []
    for line_no, line in enumerate(text.splitlines(), 1):
        # Masks collapse to a single short token rather than to whitespace: replacing
        # them with a space let the assignment pattern read across the gap and pair a key
        # name with the next line's value.
        stripped = MASK.sub("X", line)
        for label, pat in SIGNATURES:
            for m in pat.finditer(stripped):
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


def scan_file(path, text_rules=True):
    with open(path, "rb") as fh:
        data = fh.read()
    findings = []
    for off in scan_bytes_for_nul(data):
        findings.append((path, 0, "NUL byte (makes this file invisible to git grep)",
                         f"offset {off}"))
    if text_rules:
        try:
            findings.extend(scan_text(data.decode("utf-8", errors="replace"), path))
        except Exception as exc:                                   # noqa: BLE001
            findings.append((path, 0, "unreadable", str(exc)))
    return findings


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
        findings += scan_file(f)
        n_scanned += 1
    if a.tree:
        for f in tracked_files(a.tree):
            if os.path.isfile(f):
                findings += scan_file(f)
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
