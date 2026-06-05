"""Nmap XML parser (PROJECT.md §6, §13).

Phase 2. Parses nmap's ``-oX`` XML into normalized hosts/ports/services, and maps
NSE script output into low-fidelity findings (severity ``info``/``unknown`` for
the PoC; richer severity normalization is a later phase).
"""

from __future__ import annotations

name = "nmap_xml"

# TODO(phase-2): def parse(ctx: ParseContext) -> ScanResult — read ctx.artifact_path
# (XML), build Host/Port/Service objects, and convert NSE script results to Findings.
