"""Parser for sublist3r subdomain enumeration output (PROJECT.md §6).

sublist3r (run with ``-o <file>``) writes one discovered subdomain per line.
Each becomes a Host so a downstream step can scan it (e.g. nmap over the
materialised ``targets``). Sublist3r yields names, not IPs, so these are
hostname-keyed "pseudo-hosts" (``ip`` holds the hostname); a later nmap scan
resolves and records the real-IP host alongside. Reads the artifact file (clean,
one-per-line) rather than stdout (which carries a banner). Lines that aren't
plausible hostnames are ignored.
"""

from __future__ import annotations

import re
from pathlib import Path

from pentui.core.models import Host, ScanResult
from pentui.parsers.base import ParseContext

name = "sublist3r"

# A conservative hostname: dot-separated labels of letters/digits/hyphen.
_HOSTNAME = re.compile(r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?:\.[A-Za-z0-9-]{1,63})+$")


def parse(ctx: ParseContext) -> ScanResult:
    text = ""
    if ctx.artifact_path:
        try:
            text = Path(ctx.artifact_path).read_text(encoding="utf-8", errors="replace")
        except OSError:
            text = ""
    if not text:
        text = ctx.raw_stdout

    seen: dict[str, Host] = {}
    for raw in text.splitlines():
        host = raw.strip().rstrip(".").lower()
        if host and host not in seen and _HOSTNAME.match(host):
            seen[host] = Host(ip=host, hostname=host)
    return ScanResult(hosts=list(seen.values()))
