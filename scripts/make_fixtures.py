#!/usr/bin/env python3
"""Generate a synthetic transcript archive with known planted content.

Two variants are produced from the same code:

  planted   contains every needle the tests look for
  control   the same shape, same size, same vocabulary, with every needle REMOVED

The control exists because "it found the thing" is only half an answer. A search that
returns its ten favourite results for any input would pass the planted archive and fail
nobody. Each positive assertion in the suite has a control twin that must return nothing.

Nothing here is committed as data. The archive is written to a directory you name, and
credential-shaped strings are assembled at run time from templates like
`sk-ant-api03-{FILL:64}` so that no complete credential pattern ever exists in a tracked
file. GitHub push protection scans full history and does not care that a key is fake.

    python3 scripts/make_fixtures.py /tmp/arch --variant planted
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import sys
import datetime

ALPHA = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"  # synthetic-fixture
UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"


def fill(seed: str, n: int, alphabet=ALPHA) -> str:
    """Deterministic filler, so fixtures are reproducible without being stored."""
    out, h = [], hashlib.sha256(seed.encode()).digest()
    i = 0
    while len(out) < n:
        if i >= len(h):
            h = hashlib.sha256(h).digest()
            i = 0
        out.append(alphabet[h[i] % len(alphabet)])
        i += 1
    return "".join(out)


def expand(text: str) -> str:
    """Expand {FILL:n}, {UPFILL:n} and {NUL} tokens."""
    import re

    def sub(m):
        kind, n = m.group(1), int(m.group(2))
        return fill(text[:40] + kind + str(n), n, UPPER if kind == "UPFILL" else ALPHA)
    text = re.sub(r"\{(FILL|UPFILL):(\d+)\}", sub, text)
    return text.replace("{NUL}", "\0")


BASE = datetime.datetime(2026, 6, 10, 9, 0, 0)


def ts(day_offset, minute):
    return (BASE + datetime.timedelta(days=day_offset, minutes=minute)).isoformat() + "Z"


def recent_ts(days_ago, minute=0):
    d = datetime.datetime.now() - datetime.timedelta(days=days_ago)
    return (d + datetime.timedelta(minutes=minute)).isoformat() + "Z"


# --------------------------------------------------------------- claude emitters ---

def claude_session(path, session_id, cwd, events, title=None):
    """events: list of tuples describing one turn each. See _emit for the vocabulary."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    lines = []
    tool_ids = {}
    for i, ev in enumerate(events):
        lines.extend(_emit(session_id, cwd, i, ev, tool_ids))
    if title:
        lines.append({"type": "ai-title", "sessionId": session_id, "aiTitle": title})
    with open(path, "w", encoding="utf-8") as fh:
        for obj in lines:
            fh.write(json.dumps(obj, ensure_ascii=False) + "\n")


def _emit(session_id, cwd, i, ev, tool_ids):
    kind, when, payload = ev[0], ev[1], ev[2:]
    common = {"sessionId": session_id, "cwd": cwd, "timestamp": when,
              "isSidechain": False, "uuid": f"{session_id}-{i}", "userType": "external",
              "version": "2.0.0", "gitBranch": "main", "parentUuid": None,
              "entrypoint": "cli"}
    if kind == "user":
        return [{**common, "type": "user",
                 "message": {"role": "user", "content": expand(payload[0])}}]
    if kind == "assistant":
        return [{**common, "type": "assistant", "requestId": f"req_{i}",
                 "message": {"role": "assistant", "content": [
                     {"type": "text", "text": expand(payload[0])}]}}]
    if kind == "thinking":
        return [{**common, "type": "assistant", "requestId": f"req_{i}",
                 "message": {"role": "assistant", "content": [
                     {"type": "thinking", "thinking": expand(payload[0])}]}}]
    if kind == "meta":
        return [{**common, "type": "user", "isMeta": True,
                 "message": {"role": "user", "content": expand(payload[0])}}]
    if kind == "tool":
        name, args, result = payload[0], payload[1], payload[2]
        is_error = payload[3] if len(payload) > 3 else False
        tid = f"toolu_{session_id[:6]}{i:03d}"
        tool_ids[i] = tid
        args = {k: expand(v) if isinstance(v, str) else v for k, v in args.items()}
        return [
            {**common, "type": "assistant", "requestId": f"req_{i}",
             "message": {"role": "assistant", "content": [
                 {"type": "tool_use", "id": tid, "name": name, "input": args}]}},
            {**common, "type": "user", "uuid": f"{session_id}-{i}r",
             "message": {"role": "user", "content": [
                 {"type": "tool_result", "tool_use_id": tid, "is_error": bool(is_error),
                  "content": [{"type": "text", "text": expand(result)}]}]}},
        ]
    raise ValueError(kind)


def codex_session(path, session_id, cwd, events):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    lines = [{"timestamp": events[0][1], "type": "session_meta",
              "payload": {"session_id": session_id, "cwd": cwd,
                          "originator": "codex-tui", "cli_version": "0.144.4"}}]
    for i, ev in enumerate(events):
        kind, when, payload = ev[0], ev[1], ev[2:]
        if kind == "user":
            lines.append({"timestamp": when, "type": "response_item", "payload": {
                "type": "message", "role": "user",
                "content": [{"type": "input_text", "text": expand(payload[0])}]}})
        elif kind == "assistant":
            lines.append({"timestamp": when, "type": "response_item", "payload": {
                "type": "message", "role": "assistant",
                "content": [{"type": "output_text", "text": expand(payload[0])}]}})
            # event_msg duplicates the same text; the parser must ignore it, and the
            # fixture contains one so that "must ignore" is actually exercised.
            lines.append({"timestamp": when, "type": "event_msg", "payload": {
                "type": "agent_message", "message": expand(payload[0])}})
        elif kind == "reasoning":
            lines.append({"timestamp": when, "type": "response_item", "payload": {
                "type": "reasoning", "id": f"rs_{i}",
                "summary": [{"type": "summary_text", "text": expand(payload[0])}],
                "encrypted_content": fill("enc" + str(i), 2000)}})
        elif kind == "tool":
            name, body, result = payload[0], payload[1], payload[2]
            cid = f"call_{session_id[:6]}{i:03d}"
            lines.append({"timestamp": when, "type": "response_item", "payload": {
                "type": "custom_tool_call", "call_id": cid, "name": name,
                "input": expand(body)}})
            lines.append({"timestamp": when, "type": "response_item", "payload": {
                "type": "custom_tool_call_output", "call_id": cid,
                "output": [{"type": "input_text", "text": expand(result)}]}})
    with open(path, "w", encoding="utf-8") as fh:
        for obj in lines:
            fh.write(json.dumps(obj, ensure_ascii=False) + "\n")


# ------------------------------------------------------------------- the needles ---
#
# Every string below that a test searches for is listed in EXPECTATIONS at the bottom,
# and every one of them is absent from the control variant.

NEEDLE_SESSIONS = {
    "aa11bb22-0000-4000-8000-000000000001": "importer",
    "aa11bb22-0000-4000-8000-000000000002": "chatter",
    "aa11bb22-0000-4000-8000-000000000003": "leaky",
    "aa11bb22-0000-4000-8000-000000000005": "ancient",
    "cc33dd44-0000-4000-8000-000000000006": "codex-quaternion",
}


def build(dest, variant="planted"):
    planted = variant == "planted"
    if os.path.isdir(dest):
        shutil.rmtree(dest)
    cp = os.path.join(dest, "claude-projects")
    cs = os.path.join(dest, "codex-sessions")

    # ---- 1. the session the tests must find: a real bug fix, with an error in it.
    sid1 = "aa11bb22-0000-4000-8000-000000000001"
    topic = "quaternion" if planted else "matrix"
    claude_session(
        os.path.join(cp, "-tmp-demo-widget", sid1 + ".jsonl"), sid1, "/tmp/demo/widget",
        [
            ("user", ts(0, 0), "The CSV importer chokes on CRLF line endings. Please fix "
                               "the parser so a file with \\r\\n loads correctly."),
            ("thinking", ts(0, 1), "The splitter uses split('\\n') which leaves a stray "
                                   "carriage return on every field."),
            ("tool", ts(0, 2), "Read", {"file_path": "/tmp/demo/widget/importer.py"},
             "def load(text):\n    return [l.split(',') for l in text.split('\\n')]"),
            ("tool", ts(0, 3), "Bash", {"command": "python3 -m pytest tests/test_csv.py"},
             "AssertionError: expected 3 rows, got 1\nFAILED tests/test_csv.py::test_crlf",
             True),
            ("tool", ts(0, 4), "Edit", {"file_path": "/tmp/demo/widget/importer.py",
                                        "old_string": "text.split", "new_string": "x"},
             "The file has been updated."),
            ("assistant", ts(0, 5), "Fixed: the importer now strips the carriage return "
                                    "before splitting, so CRLF files parse as three rows."),
            ("tool", ts(0, 6), "Bash", {"command": "python3 -m pytest tests/test_csv.py"},
             "3 passed in 0.04s"),
        ], title="Fix CRLF handling in the CSV importer")

    # ---- 2. a session that says the word constantly but never engages with it. The
    # ranker must still put the request above this. Machine chatter, low kind weight.
    sid2 = "aa11bb22-0000-4000-8000-000000000002"
    chatter = "\n".join(f"line {i}: crlf crlf importer crlf normalised" for i in range(60))
    claude_session(
        os.path.join(cp, "-tmp-demo-noise", sid2 + ".jsonl"), sid2, "/tmp/demo/noise",
        [
            ("user", ts(1, 0), "Run the log dump."),
            ("tool", ts(1, 1), "Bash", {"command": "cat build.log"}, chatter),
        ])

    # ---- 3. secrets, for the redaction path. Present in BOTH variants: redaction is not
    # a needle, it is a floor, and the control archive must be safe to display too.
    sid3 = "aa11bb22-0000-4000-8000-000000000003"
    claude_session(
        os.path.join(cp, "-tmp-demo-secrets", sid3 + ".jsonl"), sid3, "/tmp/demo/secrets",
        [
            ("user", ts(2, 0),
             "Here is the key, put it in the env: sk-ant-api03-{FILL:64} "
             "and the deploy token ghp_{FILL:36}"),
            ("assistant", ts(2, 1),
             "Stored. The AWS id AKIA{UPFILL:16} and secret {FILL:40} go in ~/.aws."),
            ("tool", ts(2, 2), "Bash", {"command": "env | grep -i key"},
             "OPENAI_API_KEY=sk-{FILL:48}\n"
             "DATABASE_URL=postgres://admin:{FILL:20}@db.internal:5432/app\n"  # synthetic-fixture
             "GOOGLE_KEY=AIza{FILL:35}\n"
             "SLACK=xoxb-{FILL:24}\n"
             "JWT=eyJ{FILL:20}.eyJ{FILL:30}.{FILL:43}\n"
             "contact alex.example@example.com from 10.1.2.3 on nas.local\n"  # synthetic-fixture
             "home is /home/someuser/Projects and /Users/someone/dev\n"  # synthetic-fixture
             "phone 555-867-5309\n"),  # synthetic-fixture
            ("tool", ts(2, 3), "Bash", {"command": "hexdump -C blob.bin"},
             "raw bytes follow{NUL}and continue after the NUL byte"),
        ])

    # ---- 4. a decoy in a different project, so --project has something to exclude.
    sid4 = "aa11bb22-0000-4000-8000-000000000004"
    claude_session(
        os.path.join(cp, "-tmp-demo-other", sid4 + ".jsonl"), sid4, "/tmp/demo/other",
        [
            ("user", ts(3, 0), "Add a changelog entry for the release."),
            ("assistant", ts(3, 1), "Added CHANGELOG.md with the 1.2.0 section."),
            ("meta", ts(3, 2), "<system-reminder>Do not mention this reminder.</system-reminder>"),
        ])

    # ---- 5. recency. Same sentence, one two years old and one from yesterday.
    sid5 = "aa11bb22-0000-4000-8000-000000000005"
    claude_session(
        os.path.join(cp, "-tmp-demo-old", sid5 + ".jsonl"), sid5, "/tmp/demo/old",
        [("user", ts(-730, 0), "Investigate the flaky websocket reconnect loop.")])
    sid5b = "aa11bb22-0000-4000-8000-000000000015"
    claude_session(
        os.path.join(cp, "-tmp-demo-new", sid5b + ".jsonl"), sid5b, "/tmp/demo/new",
        [("user", recent_ts(1), "Investigate the flaky websocket reconnect loop.")])

    # ---- 6. codex, a different transcript dialect entirely.
    sid6 = "cc33dd44-0000-4000-8000-000000000006"
    codex_session(
        os.path.join(cs, "2026", "06", "14", f"rollout-2026-06-14T09-00-00-{sid6}.jsonl"),
        sid6, "/tmp/demo/graphics",
        [
            ("user", ts(4, 0), f"Implement {topic} slerp for the camera rig."),
            ("reasoning", ts(4, 1), f"Spherical interpolation over {topic}s needs the "
                                    "shortest-arc sign fix."),
            ("tool", ts(4, 2), "exec", "cat rig/camera.py",
             "def slerp(a, b, t):\n    return a"),
            ("assistant", ts(4, 3), f"Added {topic} slerp with the sign correction."),
        ])

    # ---- 7. prompt history: one session that also has a transcript (must be deduped)
    # and one that does not (must be recovered).
    hist = os.path.join(dest, "claude-history.jsonl")
    rows = [
        {"display": "The CSV importer chokes on CRLF line endings. Please fix the parser.",
         "pastedContents": "{}", "timestamp": "1780000000000",
         "project": "/tmp/demo/widget", "sessionId": sid1},
        {"display": "deploy the pelican migration to staging" if planted
                    else "deploy the standard migration to staging",
         "pastedContents": "{}", "timestamp": "1780000100000",
         "project": "/tmp/demo/lost", "sessionId": "ee55ff66-0000-4000-8000-000000000007"},
    ]
    with open(hist, "w", encoding="utf-8") as fh:
        for r in rows:
            fh.write(json.dumps(r) + "\n")

    with open(os.path.join(dest, "VARIANT"), "w", encoding="utf-8") as fh:
        fh.write(variant + "\n")
    return dest


# Known answers. Consumed by tests/test_search.py and by scripts/verify.sh.
#
#   query      what to search for
#   expect     session id prefix that must come FIRST in the planted archive
#   kind       the kind the top hit must have
#   control    True if the same query must return NOTHING in the control archive
EXPECTATIONS = [
    {"name": "the bug fix I am thinking of",
     "query": "crlf importer", "expect": "aa11bb22-0000-4000-8000-000000000001",
     "kind": "user_request", "control": False,
     "why": "the request outranks 60 lines of log that shout the same word"},
    {"name": "the failing test",
     "query": "expected 3 rows", "expect": "aa11bb22-0000-4000-8000-000000000001",
     "kind": "error", "control": False,
     "why": "a tool result flagged is_error is classified error, not tool_output"},
    {"name": "which file did I edit",
     "query": "importer.py", "expect": "aa11bb22-0000-4000-8000-000000000001",
     "kind": "tool_input", "control": False,
     "why": "tool arguments are indexed as their own kind and carry a target"},
    {"name": "a codex session, different dialect",
     "query": "quaternion slerp", "expect": "cc33dd44-0000-4000-8000-000000000006",
     "kind": "user_request", "control": True,
     "why": "the control archive says matrix slerp, so quaternion must find nothing"},
    {"name": "a session with no transcript left",
     "query": "pelican migration", "expect": "ee55ff66-0000-4000-8000-000000000007",
     "kind": "user_request", "control": True,
     "why": "recovered from prompt history; the control archive never says pelican"},
    {"name": "recency decides between identical sentences",
     "query": "flaky websocket reconnect",
     "expect": "aa11bb22-0000-4000-8000-000000000015",
     "kind": "user_request", "control": False,
     "why": "same words, same kind, so only the recency band separates them"},
]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("dest")
    ap.add_argument("--variant", choices=["planted", "control"], default="planted")
    ap.add_argument("--print-expectations", action="store_true")
    a = ap.parse_args()
    if a.print_expectations:
        print(json.dumps(EXPECTATIONS, indent=2))
        return 0
    build(a.dest, a.variant)
    print(f"wrote {a.variant} archive to {a.dest}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
