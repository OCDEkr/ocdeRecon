"""Parser plugin contract (PROJECT.md §6).

A parser is a small, pure component: raw output in, normalized ScanResult out.
No DB access, no UI — core persists the result, which then becomes available to
the workflow query layer.
"""

from __future__ import annotations

from dataclasses import dataclass
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


class Parser(Protocol):
    name: str  # must match a manifest's output.parser

    def parse(self, ctx: ParseContext) -> ScanResult: ...
