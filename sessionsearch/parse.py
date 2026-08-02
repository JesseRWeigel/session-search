"""Flatten transcript JSONL into typed turns.

The whole point of this project is that a transcript is not a flat blob of text. A tool
call's arguments, the file that tool read, an error it printed, and the sentence the human
typed are four different kinds of evidence, and a search that treats them alike answers
"when did I last do this" badly. So parsing assigns every turn one KIND, and everything
downstream (filters, ranking, excerpting) keys off it.

Kinds, in the order they matter for ranking:

  user_request    something the human typed
  error           a tool result flagged is_error, or one whose first lines look like a
                  traceback or a failing test run (heuristic, see ERROR_SIGNAL)
  assistant_text  prose the model produced
  tool_input      a tool call plus its arguments
  tool_output     what the tool returned
  thinking        extended-thinking blocks and Codex reasoning summaries
  meta            system reminders, injected commands, developer prompts, hooks

Deliberately not indexed, each for a reason worth stating:

  * Claude `attachment` records. Sampled across 120 real transcripts these are harness
    injections rather than conversation: deferred tool listings, skill listings, agent
    listings, task reminders, structured tool output, and queued commands that reappear
    as ordinary user turns anyway. Counted in stats as `skipped_attachment`, so the
    number you are not searching is visible instead of implied.
  * Codex `reasoning.encrypted_content`. An opaque base64 blob, ~2 KB per turn, with no
    searchable text in it. The `summary` field of the same record IS indexed.
  * Codex `event_msg` records, which duplicate `response_item` records one for one.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field

KINDS = ("user_request", "error", "assistant_text", "tool_input",
         "tool_output", "thinking", "meta")

# A tool result that carries no is_error flag can still obviously be a failure. This is a
# heuristic and it is stated as one: it fires on the first 400 characters only, so a log
# that merely mentions the word error further down is not reclassified.
ERROR_SIGNAL = re.compile(
    r"(^|\n)\s*(Traceback \(most recent call last\)"
    r"|[A-Za-z_.]*(Error|Exception)\s*:"
    r"|error\[E\d+\]"
    r"|fatal:"
    r"|FAIL(ED)?\b"
    r"|npm ERR!"
    r"|command not found"
    r"|Permission denied"
    r"|exit (code )?[1-9]\d*)")

MAX_TEXT = int(os.environ.get("SESSION_SEARCH_MAX_TEXT", "20000"))

# Tool arguments worth putting in the `target` column, most specific first. `target` is
# what makes "which session did I edit parse.py in" a filter rather than a text search.
TARGET_KEYS = ("file_path", "notebook_path", "path", "command", "url", "pattern",
               "query", "prompt", "description", "skill", "content")


@dataclass
class Turn:
    source: str            # claude_code | codex | claude_prompts
    session_id: str
    project: str           # cwd with $HOME collapsed, e.g. ~/Projects/idle-abyss
    path: str              # transcript file it came from
    seq: int               # 0-based position within the session, in file order
    ts: float              # epoch seconds, 0.0 if the record carried no timestamp
    kind: str
    tool: str = ""
    target: str = ""
    text: str = ""
    sidechain: bool = False
    truncated: bool = False
    orig_len: int = 0


@dataclass
class SessionMeta:
    source: str
    session_id: str
    project: str
    path: str
    title: str = ""
    first_ts: float = 0.0
    last_ts: float = 0.0
    turns: int = 0


@dataclass
class ParseStats:
    records: int = 0
    turns: int = 0
    bad_json: int = 0
    skipped_attachment: int = 0
    skipped_encrypted: int = 0
    skipped_empty: int = 0
    by_kind: dict = field(default_factory=dict)

    def bump(self, kind):
        self.by_kind[kind] = self.by_kind.get(kind, 0) + 1


def collapse_home(p: str) -> str:
    home = os.path.expanduser("~")
    if p and (p == home or p.startswith(home + os.sep)):
        return "~" + p[len(home):]
    return p


def _iso_to_epoch(s) -> float:
    if not s:
        return 0.0
    if isinstance(s, (int, float)):
        v = float(s)
        return v / 1000.0 if v > 1e11 else v
    s = str(s).strip()
    if s.isdigit():
        v = float(s)
        return v / 1000.0 if v > 1e11 else v
    try:
        import datetime
        return datetime.datetime.fromisoformat(s.replace("Z", "+00:00")).timestamp()
    except Exception:
        return 0.0


def _clip(text: str):
    text = text.replace("\r\n", "\n").strip()
    n = len(text)
    if n > MAX_TEXT:
        return text[:MAX_TEXT], True, n
    return text, False, n


def _blocks_text(content) -> str:
    """Concatenate the text of a content value that may be a str, a list, or nested."""
    if content is None:
        return ""
    if isinstance(content, str):
        return content
    if isinstance(content, dict):
        if "text" in content and isinstance(content["text"], str):
            return content["text"]
        return ""
    if isinstance(content, list):
        parts = []
        for b in content:
            t = _blocks_text(b)
            if t:
                parts.append(t)
        return "\n".join(parts)
    return ""


def _target_of(args) -> str:
    if not isinstance(args, dict):
        return str(args)[:200] if args else ""
    for k in TARGET_KEYS:
        v = args.get(k)
        if isinstance(v, str) and v.strip():
            return v.strip()[:400]
    for v in args.values():
        if isinstance(v, str) and v.strip():
            return v.strip()[:400]
    return ""


def _decode_project_dir(name: str) -> str:
    """Best effort recovery of a project path from Claude's flattened directory name.

    Claude replaces path separators with '-', which is lossy because '-' also occurs in
    real directory names. This is only ever a fallback: when any record in the file
    carries `cwd`, that wins.
    """
    if not name.startswith("-"):
        return name
    return collapse_home("/" + name[1:].replace("-", "/"))


def _kind_for_result(text: str, is_error: bool) -> str:
    if is_error:
        return "error"
    if ERROR_SIGNAL.search(text[:400]):
        return "error"
    return "tool_output"


def parse_claude_file(path: str, stats: ParseStats):
    """Yield (SessionMeta, [Turn]) for one Claude Code transcript."""
    session_id = os.path.splitext(os.path.basename(path))[0]
    project = _decode_project_dir(os.path.basename(os.path.dirname(path)))
    meta = SessionMeta("claude_code", session_id, project, path)
    turns = []
    tool_by_id = {}
    seq = 0

    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            stats.records += 1
            try:
                rec = json.loads(line)
            except Exception:
                stats.bad_json += 1
                continue
            if not isinstance(rec, dict):
                stats.bad_json += 1
                continue

            if rec.get("sessionId"):
                meta.session_id = rec["sessionId"]
            if rec.get("cwd"):
                project = collapse_home(rec["cwd"])
                meta.project = project
            ts = _iso_to_epoch(rec.get("timestamp"))
            if ts:
                meta.first_ts = ts if not meta.first_ts else min(meta.first_ts, ts)
                meta.last_ts = max(meta.last_ts, ts)

            rtype = rec.get("type")
            if rtype == "ai-title" and rec.get("aiTitle"):
                meta.title = str(rec["aiTitle"])[:200]
                continue
            if rtype == "attachment":
                stats.skipped_attachment += 1
                continue
            if rtype not in ("user", "assistant", "system"):
                continue

            sidechain = bool(rec.get("isSidechain"))
            msg = rec.get("message")
            emitted = []

            if rtype == "system":
                text = _blocks_text(rec.get("content"))
                if text:
                    emitted.append(("meta", "", "", text))
            elif isinstance(msg, dict):
                content = msg.get("content")
                is_meta = bool(rec.get("isMeta"))
                if isinstance(content, str):
                    kind = "meta" if is_meta else (
                        "user_request" if rtype == "user" else "assistant_text")
                    emitted.append((kind, "", "", content))
                elif isinstance(content, list):
                    for b in content:
                        if not isinstance(b, dict):
                            continue
                        bt = b.get("type")
                        if bt == "text":
                            kind = "meta" if is_meta else (
                                "user_request" if rtype == "user" else "assistant_text")
                            emitted.append((kind, "", "", b.get("text") or ""))
                        elif bt == "thinking":
                            emitted.append(
                                ("thinking", "", "", b.get("thinking") or b.get("text") or ""))
                        elif bt == "tool_use":
                            name = b.get("name") or ""
                            args = b.get("input")
                            tool_by_id[b.get("id")] = name
                            body = _target_of(args)
                            try:
                                pretty = json.dumps(args, ensure_ascii=False)
                            except Exception:
                                pretty = str(args)
                            emitted.append(("tool_input", name, body,
                                            name + " " + pretty))
                        elif bt == "tool_result":
                            name = tool_by_id.get(b.get("tool_use_id"), "")
                            text = _blocks_text(b.get("content"))
                            kind = _kind_for_result(text, bool(b.get("is_error")))
                            emitted.append((kind, name, "", text))

            for kind, tool, target, text in emitted:
                text, trunc, orig = _clip(text or "")
                if not text:
                    stats.skipped_empty += 1
                    continue
                turns.append(Turn("claude_code", meta.session_id, project, path, seq, ts,
                                  kind, tool, target, text, sidechain, trunc, orig))
                seq += 1
                stats.turns += 1
                stats.bump(kind)

    meta.turns = len(turns)
    return meta, turns


# --------------------------------------------------------------------------- codex ---

_CODEX_META_ROLES = {"developer", "system", "tool"}


def parse_codex_file(path: str, stats: ParseStats):
    """Yield (SessionMeta, [Turn]) for one Codex CLI rollout file."""
    session_id = os.path.splitext(os.path.basename(path))[0]
    meta = SessionMeta("codex", session_id, "", path)
    project = ""
    turns = []
    call_by_id = {}
    seq = 0

    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            stats.records += 1
            try:
                rec = json.loads(line)
            except Exception:
                stats.bad_json += 1
                continue
            if not isinstance(rec, dict):
                stats.bad_json += 1
                continue

            ts = _iso_to_epoch(rec.get("timestamp"))
            if ts:
                meta.first_ts = ts if not meta.first_ts else min(meta.first_ts, ts)
                meta.last_ts = max(meta.last_ts, ts)

            rtype = rec.get("type")
            payload = rec.get("payload")
            if not isinstance(payload, dict):
                continue

            if rtype == "session_meta":
                if payload.get("session_id"):
                    meta.session_id = payload["session_id"]
                if payload.get("cwd"):
                    project = collapse_home(payload["cwd"])
                    meta.project = project
                continue
            if rtype != "response_item":
                # event_msg duplicates response_item; turn_context and world_state carry
                # no conversation text.
                continue

            ptype = payload.get("type")
            emitted = []

            if ptype == "message":
                role = payload.get("role") or ""
                text = _blocks_text(payload.get("content"))
                if role in _CODEX_META_ROLES:
                    emitted.append(("meta", "", "", text))
                elif role == "user":
                    emitted.append(("user_request", "", "", text))
                else:
                    emitted.append(("assistant_text", "", "", text))
            elif ptype == "reasoning":
                if payload.get("encrypted_content"):
                    stats.skipped_encrypted += 1
                text = _blocks_text(payload.get("summary"))
                if text:
                    emitted.append(("thinking", "", "", text))
            elif ptype in ("custom_tool_call", "function_call"):
                name = payload.get("name") or ""
                raw = payload.get("input")
                if raw is None:
                    raw = payload.get("arguments")
                if isinstance(raw, str):
                    body = raw
                    try:
                        body_target = _target_of(json.loads(raw))
                    except Exception:
                        body_target = raw.strip()[:400]
                else:
                    body = json.dumps(raw, ensure_ascii=False)
                    body_target = _target_of(raw)
                call_by_id[payload.get("call_id")] = name
                emitted.append(("tool_input", name, body_target, name + " " + body))
            elif ptype in ("custom_tool_call_output", "function_call_output"):
                name = call_by_id.get(payload.get("call_id"), "")
                text = _blocks_text(payload.get("output"))
                emitted.append((_kind_for_result(text, False), name, "", text))

            for kind, tool, target, text in emitted:
                text, trunc, orig = _clip(text or "")
                if not text:
                    stats.skipped_empty += 1
                    continue
                turns.append(Turn("codex", meta.session_id, project or meta.project, path,
                                  seq, ts, kind, tool, target, text, False, trunc, orig))
                seq += 1
                stats.turns += 1
                stats.bump(kind)

    meta.turns = len(turns)
    meta.project = project or meta.project
    for t in turns:
        t.session_id = meta.session_id
        t.project = meta.project
    return meta, turns


# ------------------------------------------------------------------ prompt history ---

def parse_claude_history(path: str, stats: ParseStats, skip_sessions=()):
    """Yield (SessionMeta, [Turn]) per session found in ~/.claude/history.jsonl.

    Sessions already covered by a full transcript are skipped, otherwise every prompt
    would be indexed twice and a duplicate would outrank a unique hit for no reason.
    """
    grouped = {}
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            stats.records += 1
            try:
                rec = json.loads(line)
            except Exception:
                stats.bad_json += 1
                continue
            sid = rec.get("sessionId") or ""
            if not sid or sid in skip_sessions:
                continue
            grouped.setdefault(sid, []).append(rec)

    for sid, recs in sorted(grouped.items()):
        project = collapse_home(recs[0].get("project") or "")
        meta = SessionMeta("claude_prompts", sid, project, path)
        turns = []
        for seq, rec in enumerate(recs):
            ts = _iso_to_epoch(rec.get("timestamp"))
            if ts:
                meta.first_ts = ts if not meta.first_ts else min(meta.first_ts, ts)
                meta.last_ts = max(meta.last_ts, ts)
            text, trunc, orig = _clip(rec.get("display") or "")
            if not text:
                stats.skipped_empty += 1
                continue
            turns.append(Turn("claude_prompts", sid, project, path, seq, ts,
                              "user_request", "", "", text, False, trunc, orig))
            stats.turns += 1
            stats.bump("user_request")
        meta.turns = len(turns)
        if turns:
            yield meta, turns
