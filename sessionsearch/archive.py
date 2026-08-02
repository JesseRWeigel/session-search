"""Where transcripts live, and how a fixture archive stands in for the real one.

Three sources are supported. Each is optional; a missing source is reported as missing
rather than quietly contributing zero turns, because "found nothing" and "did not look"
are different answers and collapsing them is how an index silently goes stale.

  claude_code     ~/.claude/projects/**/*.jsonl        full transcripts
  codex           ~/.codex/sessions/**/*.jsonl         full transcripts (OpenAI Codex CLI)
  claude_prompts  ~/.claude/history.jsonl              prompt history, no assistant turns

A fixture archive is any directory laid out like this, with any part absent:

  <root>/claude-projects/<project-dir>/<session>.jsonl
  <root>/codex-sessions/**/rollout-*.jsonl
  <root>/claude-history.jsonl
"""

from __future__ import annotations

import glob
import os
from dataclasses import dataclass, field


@dataclass
class Source:
    name: str          # claude_code | codex | claude_prompts
    root: str          # directory or file
    exists: bool
    files: list = field(default_factory=list)


def _jsonl(root: str) -> list:
    return sorted(glob.glob(os.path.join(root, "**", "*.jsonl"), recursive=True))


def default_roots() -> dict:
    home = os.path.expanduser("~")
    return {
        "claude_code": os.environ.get(
            "SESSION_SEARCH_CLAUDE_ROOT", os.path.join(home, ".claude", "projects")),
        "codex": os.environ.get(
            "SESSION_SEARCH_CODEX_ROOT", os.path.join(home, ".codex", "sessions")),
        "claude_prompts": os.environ.get(
            "SESSION_SEARCH_CLAUDE_HISTORY", os.path.join(home, ".claude", "history.jsonl")),
    }


def fixture_roots(root: str) -> dict:
    return {
        "claude_code": os.path.join(root, "claude-projects"),
        "codex": os.path.join(root, "codex-sessions"),
        "claude_prompts": os.path.join(root, "claude-history.jsonl"),
    }


def discover(archive: str = None) -> list:
    """Return the sources to index, in a deterministic order."""
    roots = fixture_roots(archive) if archive else default_roots()
    out = []
    for name in ("claude_code", "codex", "claude_prompts"):
        root = roots[name]
        if name == "claude_prompts":
            ok = os.path.isfile(root)
            out.append(Source(name, root, ok, [root] if ok else []))
        else:
            ok = os.path.isdir(root)
            out.append(Source(name, root, ok, _jsonl(root) if ok else []))
    return out
