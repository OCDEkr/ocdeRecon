"""Output parsers: raw tool output -> normalized ScanResult (PROJECT.md §6).

Parsers register by name; a manifest's ``output.parser`` selects one. A parser is
any callable ``(ParseContext) -> ScanResult``.
"""

from __future__ import annotations

from collections.abc import Callable

from pentui.core.models import ScanResult
from pentui.parsers import nmap_xml, runfinger
from pentui.parsers.base import ParseContext

ParseFn = Callable[[ParseContext], ScanResult]

_PARSERS: dict[str, ParseFn] = {
    nmap_xml.name: nmap_xml.parse,
    runfinger.name: runfinger.parse,
}


def get_parser(name: str) -> ParseFn | None:
    return _PARSERS.get(name)
