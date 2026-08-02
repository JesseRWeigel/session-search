"""Redaction applied to everything this tool shows or writes out.

The index holds raw transcript text, because you cannot search text you have destroyed.
That makes this module the only thing standing between the archive and a terminal, a
pasted excerpt, or an exported file. It is therefore applied at ONE choke point
(`sessionsearch.render`), and its output is audited by `checker/leakcheck.py`, which was
written separately and imports nothing from here. A checker that reuses the redactor's own
patterns inherits the redactor's own blind spots and will report clean on a leak.

What is redacted, and why each category is here:

  private key blocks   a PEM block is unambiguous and catastrophic
  provider tokens      the shapes agents actually paste: Anthropic, OpenAI, OpenRouter,
                       GitHub, AWS, Google, Slack, HuggingFace, npm, GitLab, SendGrid, JWT
  url credentials      user:password@host in a connection string
  assignments          KEY=value / "token": "value" where the key name says secret
  addresses            anything@anything, which covers email and user@host
  home paths           unix and windows home directories collapse to ~, including the
                       flattened -home-name-Projects form Claude uses for directory names
  username             the local account name wherever it appears as a standalone word
  private hosts        RFC1918 addresses and .local/.lan/.internal names. Loopback is
                       left alone on purpose: 127.0.0.1 is not a private fact and
                       redacting it makes real output unreadable for no gain.
  phone numbers        separator-bearing NANP shapes only
  high entropy         any 24+ character run mixing case and digits, plus any 24+ hex run
  control bytes        escaped, so one NUL cannot turn a captured output file binary and
                       make every later text audit skip it without saying so

Over-redaction is the correct failure direction here. A git SHA gets masked because it is
indistinguishable from a 40-character secret without context, and losing a SHA in an
excerpt costs less than leaking a key. Search itself is unaffected: matching happens
against the raw indexed text, redaction happens on the way to your screen.
"""

from __future__ import annotations

import os
import re

PLACEHOLDER = "[redacted:{}]"

_SECRET_KEY_WORDS = (
    r"api[_-]?key|apikey|secret[_-]?key|secret|token|password|passwd|pwd|"
    r"access[_-]?key|private[_-]?key|credential|auth[_-]?token|bearer|session[_-]?key"
)

# (label, pattern, group-to-mask). group 0 means mask the whole match.
_RULES = [
    ("private-key",
     re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----",
                re.S), 0),
    # No trailing dashes required. A pasted key is often truncated mid-block, and the
    # header alone is enough to know what follows. The independent checker found real
    # turns where the closing dashes were missing and this rule did not fire.
    ("private-key",
     re.compile(r"-----BEGIN[A-Z ]{0,30}PRIVATE KEY[\s\S]{0,25}"), 0),

    ("anthropic-key", re.compile(r"sk-ant-[A-Za-z0-9_\-]{16,}"), 0),
    ("openrouter-key", re.compile(r"sk-or-v1-[A-Za-z0-9]{24,}"), 0),
    ("openai-key", re.compile(r"sk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_\-]{20,}"), 0),
    ("github-token", re.compile(r"gh[pousr]_[A-Za-z0-9]{16,}"), 0),
    ("github-token", re.compile(r"github_pat_[A-Za-z0-9_]{20,}"), 0),
    # Case sensitive on purpose: AWS key ids are uppercase by definition, and a
    # case-insensitive version false-positives on ordinary base64.
    ("aws-access-key-id", re.compile(r"(?:AKIA|ASIA|AROA|AIDA)[0-9A-Z]{16}"), 0),
    ("google-api-key", re.compile(r"AIza[0-9A-Za-z_\-]{35}"), 0),
    ("slack-token", re.compile(r"xox[abprs]-[A-Za-z0-9\-]{10,}"), 0),
    ("slack-webhook", re.compile(r"https://hooks\.slack\.com/services/\S+"), 0),
    ("discord-webhook", re.compile(r"https://discord(?:app)?\.com/api/webhooks/\S+"), 0),
    ("huggingface-token", re.compile(r"hf_[A-Za-z0-9]{20,}"), 0),
    ("npm-token", re.compile(r"npm_[A-Za-z0-9]{28,}"), 0),
    ("gitlab-token", re.compile(r"glpat-[A-Za-z0-9_\-]{16,}"), 0),
    ("docker-token", re.compile(r"dckr_pat_[A-Za-z0-9_\-]{16,}"), 0),
    ("sendgrid-key", re.compile(r"SG\.[A-Za-z0-9_\-]{16,}\.[A-Za-z0-9_\-]{16,}"), 0),
    ("stripe-key", re.compile(r"[rs]k_(?:live|test)_[A-Za-z0-9]{16,}"), 0),
    ("jwt", re.compile(
        r"eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}"), 0),

    ("url-credentials",
     re.compile(r"(?<=://)[^\s/:@]{1,64}:[^\s/@]{1,128}(?=@)"), 0),
    ("bearer-token",
     re.compile(r"(?i)(?<=bearer )[A-Za-z0-9._\-+/=]{16,}"), 0),

    # The boundary is written as a lookaround rather than \b because the key name is
    # usually the TAIL of a longer identifier: GITHUB_TOKEN, MY_API_KEY. \b does not fire
    # between an underscore and a letter, so the \b version missed every real env var.
    ("secret-assignment",
     re.compile(r'(?i)(?<![A-Za-z0-9])(?:' + _SECRET_KEY_WORDS +
                r')(?![A-Za-z0-9])["\']?\s*[:=]\s*["\']?([^\s"\',;)]{8,})'), 1),

    ("address", re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9][A-Za-z0-9.\-]*\.[A-Za-z]{2,}"), 0),
    ("address", re.compile(r"\b[a-z_][a-z0-9_.\-]*@[a-z0-9][a-z0-9\-]{2,}\b"), 0),
]

_HOME_RULES = [
    re.compile(r"/home/[A-Za-z0-9._\-]+"),
    re.compile(r"/Users/[A-Za-z0-9._\-]+"),
    re.compile(r"[Cc]:\\+Users\\+[A-Za-z0-9._\-]+"),
    re.compile(r"/root(?=/|\b)"),
    # Claude Code names each project directory after the flattened cwd, so the archive is
    # full of strings like -home-alice-Projects-thing with no slash anywhere in them. The
    # independent checker found these surviving a redaction pass that only knew about
    # /home/, which is precisely the leak a shared-code checker would have missed.
    re.compile(r"[-_]home[-_][A-Za-z0-9._]+"),
    re.compile(r"[-_]Users[-_][A-Za-z0-9._]+"),
]


def _user_pattern():
    """The local account name, masked wherever it appears as a word.

    Path rules cover ~/, but a username also turns up bare: in a prompt, in a git author
    line, in an ssh target, in output from `whoami`. Names shorter than four characters
    are skipped because a two-letter login collides with ordinary words far too often to
    be worth it, and that trade is stated rather than hidden.
    """
    name = os.path.basename(os.path.expanduser("~")).strip()
    if len(name) < 4 or not name.replace("_", "").replace("-", "").isalnum():
        return None
    return re.compile(r"(?i)(?<![A-Za-z0-9])" + re.escape(name) + r"(?![A-Za-z0-9])")


_USER_RE = _user_pattern()

_PRIVATE_IP = re.compile(
    r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}"
    r"|192\.168\.\d{1,3}\.\d{1,3}"
    r"|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b")
_PRIVATE_HOST = re.compile(
    r"\b[A-Za-z0-9][A-Za-z0-9\-]{0,62}\.(?:local|lan|internal|home\.arpa)\b")
_PHONE = re.compile(
    r"(?<![\d.\-])(?:\+?1[ .\-])?\(?\d{3}\)?[ .\-]\d{3}[ .\-]\d{4}(?![\d.\-])")

# Control bytes are escaped rather than passed through. A single NUL in rendered output
# makes the file that captured it binary to git and to grep, and every text-based audit
# downstream then skips it in silence and reports success. Writing it as the two-character
# escape \0 keeps the information and keeps the file readable.
_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_CONTROL_NAMES = {"\x00": "\\0", "\x1b": "\\e", "\x07": "\\a", "\x08": "\\b",
                  "\x0b": "\\v", "\x0c": "\\f", "\r": "\\r"}

# 24, not 32, because the independent checker treats 24 as the length at which a random
# run becomes credential-shaped, and a redactor that masks less than its auditor reports
# guarantees a permanent backlog of findings that everyone learns to ignore. The cost is
# real and is stated in the README: long camelCase identifiers get masked too.
_RUN_MIN = 24
_HEX_RUN = re.compile(r"\b[0-9a-fA-F]{%d,}\b" % _RUN_MIN)
_B64_RUN = re.compile(r"[A-Za-z0-9+/=]{%d,}" % _RUN_MIN)
_MIXED_RUN = re.compile(r"[A-Za-z0-9+=_\-]{%d,}" % _RUN_MIN)


def _mixed_is_secretish(s: str) -> bool:
    """A long run counts as secret-shaped when it carries a digit and a letter.

    This is deliberately blunter than it needs to be, and the reason is worth stating. The
    independent checker reports any 24+ character run with three character classes, a
    digit and high Shannon entropy. If the redactor were the more permissive of the two,
    every run would produce a standing finding that nobody could clear, and a permanent
    backlog of findings is the same thing as no checker at all. So the redactor is the
    stricter side by construction: anything the checker can report, this masks first.

    The cost is real and shows up in excerpts. dejavusansmono-57e8e12… is masked,
    and so is any twenty-four character identifier with a digit in it.
    """
    return (any(c.isdigit() for c in s)
            and any(c.isalpha() for c in s))


def _b64_is_secretish(s: str) -> bool:
    """Same test, plus a guard for the slash.

    Base64 uses '/' as an alphabet character, so a run containing slashes may be a secret,
    but it is far more often a filesystem path: /tmp/build17/Assets/Cache is three classes
    and 25 characters of nothing private. Two signals separate them.

    Segment length. Base64 emits a slash about once per 64 characters, so its segments are
    long; path segments are short. The AWS documentation example secret
    wJalrXUtnFEMI/K7MDENG/... averages 13 characters between slashes, and the paths in
    this repository average under 10, so the line sits at 12.

    A leading slash. An absolute path always starts with one and base64 starts with one
    about once in 64, so a run beginning with '/' has to clear the higher bar of 20.
    """
    if not _mixed_is_secretish(s):
        return False
    segs = [x for x in s.split("/") if x]
    if len(segs) <= 1:
        return True
    if _case_churn(s) >= 0.15:
        # Base64 flips between cases every few characters; a path essentially never does.
        # This is what catches a secret that has been truncated mid-paste, where the
        # segment lengths alone look like a short path. Found by the independent checker
        # on real turns, where a 40 character key had been clipped to 29.
        return True
    mean = sum(len(x) for x in segs) / len(segs)
    return mean >= (20 if s.startswith("/") else 12)


def _case_churn(s: str) -> float:
    """Fraction of adjacent letter pairs that switch between upper and lower case."""
    flips = 0
    total = 0
    for a, b in zip(s, s[1:]):
        if a.isalpha() and b.isalpha():
            total += 1
            if a.isupper() != b.isupper():
                flips += 1
    return (flips / total) if total else 0.0


def redact(text, counts=None):
    """Return `text` with every recognised secret or personal detail masked.

    `counts` is an optional dict that accumulates label -> number of substitutions, so a
    caller can say what it removed without ever printing what it removed.
    """
    if text is None:
        return ""
    if not isinstance(text, str):
        text = str(text)

    def bump(label, n=1):
        if counts is not None and n:
            counts[label] = counts.get(label, 0) + n

    for label, pat, group in _RULES:
        def _sub(m, label=label, group=group):
            bump(label)
            if group == 0:
                return PLACEHOLDER.format(label)
            start, end = m.span(group)
            return m.group(0)[:start - m.start()] + PLACEHOLDER.format(label) + \
                m.group(0)[end - m.start():]
        text = pat.sub(_sub, text)

    for pat in _HOME_RULES:
        text, n = pat.subn("~", text)
        bump("home-path", n)

    if _USER_RE is not None:
        text, n = _USER_RE.subn(PLACEHOLDER.format("username"), text)
        bump("username", n)

    text, n = _PRIVATE_IP.subn(PLACEHOLDER.format("private-ip"), text)
    bump("private-ip", n)
    text, n = _PRIVATE_HOST.subn(PLACEHOLDER.format("private-host"), text)
    bump("private-host", n)
    text, n = _PHONE.subn(PLACEHOLDER.format("phone"), text)
    bump("phone", n)

    text, n = _HEX_RUN.subn(PLACEHOLDER.format("high-entropy"), text)
    bump("high-entropy", n)

    def _runs(test):
        def _sub(m):
            s = m.group(0)
            if test(s):
                bump("high-entropy")
                return PLACEHOLDER.format("high-entropy")
            return s
        return _sub

    text = _B64_RUN.sub(_runs(_b64_is_secretish), text)
    text = _MIXED_RUN.sub(_runs(_mixed_is_secretish), text)

    def _ctl(m):
        ch = m.group(0)
        bump("control-byte")
        return _CONTROL_NAMES.get(ch, "\\x%02x" % ord(ch))
    text = _CONTROL.sub(_ctl, text)

    return text


def redact_path(p, counts=None):
    """Paths get the same treatment; kept separate so callers read clearly."""
    return redact(p, counts)


def self_check():
    """Cheap smoke test used by the CLI at start up: the module must still redact.

    A redactor whose rules were accidentally emptied is worse than no redactor, because
    the rest of the program still behaves as though redaction happened.
    """
    key = "AKIA" + "1234567890ABCDEF"
    home = os.path.join(os.sep + "home", "someone", "x")
    out = redact(key + " " + home)
    return key not in out and home not in out
