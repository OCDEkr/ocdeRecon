"""Parser plugin contract (PROJECT.md §6).

A parser is a small, pure component: raw output in, normalized ScanResult out.
No DB access, no UI — core persists the result, which then becomes available to
the workflow query layer.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from pentui.core.models import ScanResult


@dataclass(slots=True)
class ParseContext:
    """Everything a parser needs to interpret one scan's output."""

    raw_stdout: str
    raw_stderr: str
    artifact_path: str | None  # e.g. the nmap XML file, if the tool wrote one
    scan_id: int
    project_id: int


def read_output(path: str | None) -> str:
    """Read a scan's captured stdout log, or ``""`` if missing/unreadable.

    Tools without an artifact (e.g. runfinger) are parsed from their stdout,
    which the runner tees to ``<scan_dir>/stdout.log``; this loads it back so the
    parser's ``ParseContext.raw_stdout`` is populated rather than empty.
    """
    if not path:
        return ""
    try:
        return Path(path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


class Parser(Protocol):
    name: str  # must match a manifest's output.parser

    def parse(self, ctx: ParseContext) -> ScanResult: ...
