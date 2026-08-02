"""The one place transcript content becomes visible.

Every string that leaves this program on its way to a terminal, a file, or a clipboard
passes through `safe()` here. Concentrating it means the audit question is answerable:
`checker/leakcheck.py` reads the rendered bytes, and `verify.sh` checks that no other
module prints a `text` or `target` field directly.
"""

from __future__ import annotations

import datetime
import json

from . import excerpt, redact

KIND_LABEL = {
    "user_request": "you asked",
    "assistant_text": "assistant",
    "tool_input": "tool call",
    "tool_output": "tool out",
    "error": "ERROR",
    "thinking": "thinking",
    "meta": "meta",
}


def safe(text, counts=None):
    return redact.redact(text, counts)


def when(ts):
    if not ts:
        return "undated"
    return datetime.datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M")


def ago(ts, now=None):
    if not ts:
        return "?"
    now = now or datetime.datetime.now().timestamp()
    d = max(0.0, (now - ts) / 86400.0)
    if d < 1:
        return "today"
    if d < 2:
        return "yesterday"
    if d < 60:
        return f"{int(d)}d ago"
    if d < 730:
        return f"{int(d / 30)}mo ago"
    return f"{d / 365:.1f}y ago"


def hit(score, parts, row, terms, context_rows=(), explain=False, counts=None):
    """Render one search hit as a short block. Never more than six lines."""
    head = (f"[{score:>3}] {when(row['ts'])}  {KIND_LABEL.get(row['kind'], row['kind'])}"
            f"{('/' + row['tool']) if row['tool'] else ''}"
            f"  {safe(row['project'], counts) or '(no project)'}")
    lines = [head]
    sid = row["session_id"]
    lines.append(f"      session {sid[:8]}  {row['source']}  {ago(row['ts'])}"
                 + (f"  seq {row['seq']}" if row["seq"] is not None else ""))
    if explain:
        p = parts
        lines.append(f"      why: kind {p['kind']} + terms {p['terms']}"
                     f" + phrase {p['phrase']} + recency {p['recency']} = {score}")
    if row["target"]:
        lines.append(f"      target: {safe(excerpt.context_line(row['target'], 100), counts)}")
    for c in context_rows:
        if c["seq"] == row["seq"]:
            body = excerpt.snip(row["text"], terms)
            lines.append("    > " + safe(body, counts))
        else:
            marker = "-" if c["seq"] < row["seq"] else "+"
            label = KIND_LABEL.get(c["kind"], c["kind"])
            lines.append(f"    {marker} [{label}] "
                         + safe(excerpt.context_line(c["text"]), counts))
    if not context_rows:
        lines.append("    > " + safe(excerpt.snip(row["text"], terms), counts))
    if row["truncated"]:
        lines.append(f"      (turn was {row['orig_len']} chars, indexed to the limit)")
    return "\n".join(lines)


def session_hit(entry, terms, explain=False, counts=None):
    row = entry["row"]
    title = safe(row["title"], counts) if row["title"] else ""
    lines = [f"[{entry['score']:>3}] {when(row['last_ts'] or row['ts'])}"
             f"  {safe(row['project'], counts) or '(no project)'}"
             f"  {row['source']}  session {row['session_id'][:8]}"]
    if title:
        lines.append(f"      title: {title}")
    lines.append(f"      {entry['hits']} matching turn(s)"
                 + (f"; best hit scored {entry['best']}" if explain else ""))
    if explain:
        p = entry["parts"]
        lines.append(f"      why: best {entry['best']} (kind {p['kind']} + terms"
                     f" {p['terms']} + phrase {p['phrase']} + recency {p['recency']})"
                     f" + {entry['extra']} for repeat mentions = {entry['score']}")
    lines.append(f"      [{KIND_LABEL.get(row['kind'], row['kind'])}] "
                 + safe(excerpt.snip(row["text"], terms), counts))
    return "\n".join(lines)


def as_json(score, parts, row, terms, counts=None):
    """Machine readable output. Redacted exactly like the human readable form."""
    return {
        "score": score,
        "parts": parts,
        "session_id": row["session_id"],
        "source": row["source"],
        "project": safe(row["project"], counts),
        "kind": row["kind"],
        "tool": row["tool"],
        "target": safe(row["target"], counts),
        "ts": row["ts"],
        "when": when(row["ts"]),
        "seq": row["seq"],
        "excerpt": safe(excerpt.snip(row["text"], terms), counts),
        "transcript": safe(row["path"], counts),
    }


def dumps(obj):
    return json.dumps(obj, ensure_ascii=False, indent=2)
