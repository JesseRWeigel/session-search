"""Shared setup: build both fixture archives once and index them into a temp directory."""

from __future__ import annotations

import os
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "scripts"))

import make_fixtures                                   # noqa: E402
from sessionsearch import cli, indexer                 # noqa: E402

_state = {}


def build():
    """Returns dict with archive paths and index paths for both variants."""
    if _state:
        return _state
    import contextlib
    import io
    tmp = tempfile.mkdtemp(prefix="session-search-tests-")
    for variant in ("planted", "control"):
        arch = os.path.join(tmp, variant)
        make_fixtures.build(arch, variant)
        db = os.path.join(tmp, variant + ".db")
        with contextlib.redirect_stdout(io.StringIO()):
            cli.main(["--index", db, "index", "--archive", arch, "--quiet"])
        _state[variant] = {"archive": arch, "index": db}
    _state["tmp"] = tmp
    return _state


def con(variant="planted"):
    return indexer.connect(build()[variant]["index"], create=False)


def index_path(variant="planted"):
    return build()[variant]["index"]


def archive_path(variant="planted"):
    return build()[variant]["archive"]


EXPECTATIONS = make_fixtures.EXPECTATIONS


def read(path):
    with open(path, encoding="utf-8") as fh:
        return fh.read()
