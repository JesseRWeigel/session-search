# session-search

**[Open the live page](https://jesserweigel.github.io/session-search/)**

Search every AI coding session you have ever run. Claude Code and Codex transcripts,
indexed locally, ranked by a rule written out in plain language, and redacted before
anything reaches your screen.

Grep over the raw JSONL treats a shell command, the file it read, the traceback it printed
and the sentence you typed as the same kind of evidence. They are not, and the question you
actually have is almost never "which file contains this string". It is "when did I last do
something like this", which is a ranking problem.

```
$ python3 -m sessionsearch.cli search "crlf fixture" --explain --limit 1

[ 15] 2026-08-01 10:41  you asked  ~/Projects/thousand/projects/bus-factor
      session 15f05fff  claude_code  today  seq 3825
      why: kind 5 + terms 4 + phrase 3 + recency 3 = 15
    - [meta] Conversation compacted
    > …`.gitattributes` rule order: `* text=auto` after the CRLF override meant git would
      convert the fixture, making the regression test hollow…
    + [assistant] Now the CLI that turns captures into the page, then tests.

1 of 46 matching turns shown as turns  (fts 1 ms, rank 1 ms)
```

## What it indexes

| source | where | what |
|---|---|---|
| `claude_code` | `~/.claude/projects/**/*.jsonl` | full transcripts |
| `codex` | `~/.codex/sessions/**/*.jsonl` | full transcripts, OpenAI Codex CLI |
| `claude_prompts` | `~/.claude/history.jsonl` | prompt history for sessions whose transcript is gone |

A missing source is reported as missing, never counted as an empty one. The third source
only contributes sessions that have no transcript, so a prompt is never indexed twice.

## A turn has a kind

Every turn is classified once, at parse time, and every filter, score and excerpt keys off
that classification.

| kind | what it is |
|---|---|
| `user_request` | something you typed |
| `error` | a tool result flagged `is_error`, or one whose first 400 characters open like a traceback or a failing test run |
| `assistant_text` | prose the model wrote |
| `tool_input` | a tool call and its arguments, with the file or command it touched stored as a searchable `target` |
| `tool_output` | what the tool printed |
| `thinking` | extended thinking blocks and Codex reasoning summaries |
| `meta` | system reminders and injected commands, excluded from results unless you ask |

## The ranking rule

No learned model and no bm25. FTS5 answers "which turns contain these terms"; the score
below answers "in what order", and `--explain` prints every part of it.

```
score = kind + terms + phrase + recency

kind      user_request 5, error 4, assistant_text 3, tool_input 2,
          tool_output 1, thinking 1, meta 0
terms     2 points per DISTINCT query term present in the turn
phrase    3 if every query term occurs inside one 60 character window
recency   3 within 7 days, 2 within 30, 1 within 180, 0 beyond, 0 if undated
```

Ties break on newer first, then session id, then position in the session, so two runs over
the same index return the same order.

"Which session did I fix X in" is the `sessions` subcommand, which collapses turns into
sessions with

```
session_score = best turn score + min(5, number of other matching turns)
```

so a session that engaged with the topic repeatedly beats one that mentioned it once,
without letting a chatty session bury a direct hit.

## Results are excerpts

A turn in this archive runs to 20 000 characters. A hit shows the tightest window covering
the most distinct query terms, 260 characters of it, plus one turn either side clipped to
130 characters, plus which session it was and when. Six lines, not four hundred.

## Security

These transcripts contain API keys people pasted into prompts, tokens in tool output,
absolute paths, private hostnames and personal details. So:

- **The index is never inside this repository.** It defaults to
  `~/.local/share/session-search/index.db`, overridable with `$SESSION_SEARCH_INDEX`, and
  the CLI refuses outright to write it into the repo. `*.db` is gitignored as a second
  line of defence, and `scripts/verify.sh` asserts both.
- **Everything displayed or exported passes through one redactor**,
  `sessionsearch/redact.py`. Provider tokens, private key blocks, credentials inside URLs,
  secret-shaped assignments, email and `user@host` addresses, home directories including
  the flattened `-home-name-Projects` form Claude uses for directory names, the local
  account name, RFC1918 addresses, `.local`/`.internal` hostnames, phone numbers, any 24+
  character run that mixes letters and digits, and control bytes.
- **There is no `--no-redact` flag**, and there will not be one.
- **The audit is an independent program.** `checker/leakcheck.py` imports nothing from
  `sessionsearch`, shares no regex with it, and adds a Shannon-entropy sweep that knows no
  provider names at all. A leak check that reuses the filter's own patterns inherits the
  filter's own bugs and reports clean on output that is not.
- **NUL bytes are scanned for in Python, not with grep.** One NUL byte makes a file binary
  to `git grep`, which then skips it in silence and reports a clean tree it never read.
  Verify demonstrates this: it plants a token behind a NUL, shows the Python scan finds it
  and `git grep -I` finds nothing, and fails if either result flips.
- **The redactor escapes control bytes rather than passing them through**, so a captured
  output file cannot go binary and blind every later audit.
- **Nothing derived from the archive is committed.** Committed fixtures are synthetic, and
  credential-shaped fixture strings are templates expanded at run time
  (`sk-ant-api03-{FILL:64}`), so no complete credential pattern exists on disk.

The independent checker earned its keep during construction. It found two real leaks in
redacted output that the redactor's own tests were happy with: Claude's flattened project
directory names carry the account name with no slash anywhere in them, and a base64 secret
truncated mid-paste stopped looking like base64 by segment length. Both are fixed, both
have tests, and neither would have been found by a checker built from the redactor's own
patterns.

### What could still leak

Stated plainly, because a security section with no limits section is marketing.

- A credential shape nobody has seen. The generic entropy sweep is the backstop and it
  fires at 24 characters with three character classes and a digit. A shorter secret, or
  one made only of lowercase letters, passes both layers.
- Secrets spelled out in prose. "the password is hunter2" is caught by the assignment
  rule; "I set it to hunter two" is not, and no regex is going to catch that.
- Project and file names. Paths are shown with `$HOME` collapsed and the account name
  masked, but `~/Projects/client-acme-migration` still tells you who the client is.
- Content the redactor mangles instead of hiding. Over-redaction is the chosen failure
  direction, so long camelCase identifiers, git SHAs and build hashes come out as
  `[redacted:high-entropy]`. That costs readability and it is deliberate.
- The 20 `synthetic-fixture` exemptions in the tracked-file sweep. They apply only to files,
  never to rendered output, never to NUL bytes, and their count is pinned in `verify.sh`
  so adding one is a reviewed edit. A second sweep with no exemptions at all still covers
  this machine's home path, this account's name and NUL bytes.

## Install and use

Python 3.11 or newer with FTS5 in its `sqlite3`, which is the default build. No
dependencies, nothing to install.

```bash
python3 -m sessionsearch.cli index                       # build the index
python3 -m sessionsearch.cli search "crlf fixture"       # rank turns
python3 -m sessionsearch.cli search "leak" --explain     # show the four score parts
python3 -m sessionsearch.cli sessions "redaction"        # rank sessions
python3 -m sessionsearch.cli show 15f05fff --seq 40      # a window of one session
python3 -m sessionsearch.cli stats
```

Filters, on both `search` and `sessions`:

```
--kind user_request|error|assistant_text|tool_input|tool_output|thinking|meta
--tool Bash --tool Edit          --project thousand
--source claude_code|codex|claude_prompts
--since 7d|2026-06-01            --until 30d
--session 15f05fff               --sidechain only|never|both
--include-meta  --context N  --explain  --json  --limit N
```

## Measured

<!-- MEASURED:BEGIN -->
Measured on 2026-08-01 against the real archive on this machine.

| | |
|---|---|
| sources indexed | claude_code, codex, claude_prompts |
| transcript files | 770 |
| raw transcript bytes | 0.57 GB |
| sessions | 874 |
| turns | 51,881 |
| distinct projects | 46 |
| date span | 2026-01-27 to 2026-08-01 |
| index size | 136.7 MB |
| full rebuild | 3.7 s |
| query latency, median of 8 | 1.5 ms |
| query latency, worst of 8 | 7.8 ms |

Turns by kind: tool_input 15,049, tool_output 14,026, assistant_text 9,429, meta 5,701, user_request 3,453, thinking 3,433, error 790.

Regenerate with `python3 scripts/measure_real.py --write`.
<!-- MEASURED:END -->

The latency figures are the eight benchmark queries in `scripts/measure_real.py`, measured
end to end from FTS lookup through scoring. A deliberately broad query with filters costs
more: `search "playwright-core" --kind tool_input --tool Bash` matched 131 turns out of
52 698 and took 307 ms, because a filtered scan cannot use the FTS index alone. That is
the worst case seen so far and it is still interactive.

Those numbers move as the archive grows. `scripts/measure_real.py --check` re-measures and
fails if any of them has drifted more than 40 percent, which is wide enough to survive a
month of ordinary work and narrow enough that "the index is empty" or "a source stopped
parsing" still goes red.

The fixture numbers do not move, so they are checked exactly:

| | |
|---|---|
| fixture sessions | 8 |
| fixture turns | 31 |
| known answers | 6 |

Every turn of the real archive is redacted and re-scanned by the independent checker on
every verify run, and the count of findings is zero. The negative control in the same run
finds thousands in the same turns before redaction, which is what makes the zero mean
something.

## Verifying

```bash
bash scripts/verify.sh
```

It builds the real index into a temporary directory, audits every redacted turn, runs the
unit suite, checks that the planted fixture archive finds its needles and the control
archive finds nothing, loads the page in a real browser at 390 and 1280 pixels wide, fails
a deliberately broken copy of that page, and runs seven sabotages of the parser, ranker,
redactor, excerpter and index. Each sabotage has to be shown to have changed real output
before its result counts, because an attack that did not apply proves nothing.

## What is not indexed

- **Claude `attachment` records.** Sampled across 120 real transcripts these are harness
  injections rather than conversation: deferred tool listings, skill listings, agent
  listings, task reminders, and queued commands that reappear as ordinary user turns
  anyway. 31 633 of them in this archive, and the count is printed at index time so the
  part you are not searching is visible rather than implied.
- **Codex `reasoning.encrypted_content`.** An opaque blob with no searchable text. The
  `summary` field of the same record is indexed.
- **Turn text past 20 000 characters.** Clipped, with the original length recorded and
  shown in results.
- **Incremental updates.** A rebuild takes under four seconds, so there is no incremental
  path and no staleness to reason about.

## Status

Pasted from a real run of `bash scripts/verify.sh` on 2026-08-01.

```
1. toolchain
  ok    python3 3.12.3 with FTS5, node v24.13.0

2. no third party dependencies, so nothing in this suite can skip on a missing install
  ok    standard library only

3. unit suite
  ok    72 tests passed

4. the index never lives inside the repository
default index: ~/.local/share/session-search/index.db
  ok    default index is outside the repo and *.db is gitignored

5. NUL byte scan, in Python, plus proof that git grep cannot do this job
python found NUL + token; git grep -I found nothing; clean file stayed clean
  ok    NUL scan works and git grep demonstrably does not

6. every tracked file, scanned for credentials, home paths and NUL bytes
  ok    leakcheck: 0 finding(s) across 28 input(s)
  ok    no tracked file exceeds 1 MB
  ok    20 synthetic-fixture exemptions, matching the pinned count
marker-blind sweep: 0 problem(s)
  ok    no home path, account name or NUL byte in any tracked file, no exemptions

7. the planted fixture archive: every known answer is found, first
6 of 6 known answers found first
  ok    all known answers rank first

8. the control archive: the same queries must find nothing, and it is not empty
2 absent needles, 31 turns in the control archive, 0 false positives
  ok    the control archive returns nothing for absent needles

9. the checker is independent of the redactor
24 redactor patterns, 23 checker patterns, 0 shared
  ok    no shared imports and no shared patterns

10. the whole real archive: redacted, then audited by the independent checker
    indexed 875 sessions, 52655 turns from 770 files
      kinds: tool_input=15316, tool_output=14272, assistant_text=9525, meta=5776, thinking=3497, user_request=3461, error=808
      skipped: 31809 attachments, 2181 encrypted reasoning blobs, 0 unparseable lines, 7179 empty turns
      built in 3.2s
  ok    real archive indexed
  ok    audited 52655 real turns, 0 finding(s)

11. negative control for check 10: the same audit over UNREDACTED text must fail
5335 findings in the first 4000 unredacted turns, 0 after redaction
  ok    the audit demonstrably fires on unredacted content

12. README numbers still describe reality
  ok    README check: 0 problem(s)

13. the page is freshly generated and self contained
  ok    docs/index.html matches its generator
  ok    no remote references
  ok    doctype, charset and viewport present

14. the page loaded in a real browser
  ok    390x844: {"viewport":"390x844","browser":"chrome-headless-shell","selftest":"SELFTEST:OK corpus=31 hits=3 top=aa11bb22:user_request:13 absent=0","hits":3,"scores":[13,9,8],"scrollWidth":390,"offenders":0,"cons
  ok    1280x900: {"viewport":"1280x900","browser":"chrome-headless-shell","selftest":"SELFTEST:OK corpus=31 hits=3 top=aa11bb22:user_request:13 absent=0","hits":3,"scores":[13,9,8],"scrollWidth":1265,"offenders":0,"co

15. negative control for check 14: a broken page must fail the browser check
  ok    broken page rejected:   - the page's script never wrote its result, so it did not run: "script has not run"

16. sabotages, each proved to change real output before anything is concluded
  ok    parse-drop-tool-calls: output changed, suite went red with 6 failing assertion(s), first: FAIL: test_tool_input_carries_a_target (test_parse.TestKinds.test_tool_input_carries_a_target)
  ok    rank-flat-kinds: output changed, suite went red with 3 failing assertion(s), first: FAIL: test_kind_points_are_ordered_as_documented (test_rank.TestComponents.test_kind_points_are_orde
  ok    rank-invert-recency: output changed, suite went red with 4 failing assertion(s), first: FAIL: test_recency_bands (test_rank.TestComponents.test_recency_bands)
  ok    redact-drop-aws-rule: output changed, suite went red with 27 failing assertion(s), first: ERROR: test_rendered_output_over_the_same_data_is_clean (test_leakcheck.TestAgainstTheRealPipeline.t
  ok    redact-drop-private-ip-rule: output changed, suite went red with 3 failing assertion(s), first: FAIL: test_rendered_output_over_the_same_data_is_clean (test_leakcheck.TestAgainstTheRealPipeline.te
  ok    excerpt-dump-everything: output changed, suite went red with 4 failing assertion(s), first: FAIL: test_a_missing_term_does_not_break_excerpting (test_excerpt.TestWindow.test_a_missing_term_doe
  ok    index-rowid-drift: output changed, suite went red with 11 failing assertion(s), first: FAIL: test_date_filters (test_search.TestFilters.test_date_filters)
sabotage: 7 of 7 proved
  ok    sabotage: 7 of 7 proved

17. the README describes this run
  ok    README carries this run's summary line

session-search verify: 24 checks, 0 failures
```

## Licence

MIT. See `LICENSE`.

Part of [722 things to build](https://github.com/JesseRWeigel/722-things-to-build).
