"""Parser for Responder's RunFinger SMB-signing fingerprint output (PROJECT.md §6).

RunFinger probes hosts for SMB signing (and null sessions). Hosts where signing
is **not required** are NTLM-relay targets, so this records each host's signing
state on ``Host.smb_signing`` ("required" | "disabled"). The query layer can then
select ``smb_signing_in: ["disabled"]`` and materialise an ``ip_list`` to feed a
relay tool's target file (``ntlmrelayx -tf``).

RunFinger's output varies by version; this handles the common single-line forms,
e.g.::

    ['192.168.1.10', Os:'Windows ...', Signing:'False', Null Session:'True']
    192.168.1.10, Signing: True

and the multi-line form (an IP line followed by a ``SMB signing:`` line). Lines
that can't be interpreted are ignored, so partial/garbled output still yields
whatever hosts were understood.
"""

from __future__ import annotations

import re

from pentui.core.models import Host, ScanResult
from pentui.parsers.base import ParseContext

name = "runfinger"

_IP = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")
_SIGNING = re.compile(
    r"signing[\s:'\"=]*?(true|false|required|not\s*required|enabled|disabled|on|off|yes|no)",
    re.IGNORECASE,
)

# Tokens meaning signing is enforced (no relay) vs. not enforced (relay target).
_REQUIRED = {"true", "required", "enabled", "on", "yes"}
_NOT_REQUIRED = {"false", "not required", "notrequired", "disabled", "off", "no"}


def _classify(token: str) -> str | None:
    normalized = " ".join(token.lower().split())
    if normalized in _REQUIRED:
        return "required"
    if normalized in _NOT_REQUIRED:
        return "disabled"
    return None


def parse(ctx: ParseContext) -> ScanResult:
    signing: dict[str, str] = {}
    current_ip: str | None = None
    for line in ctx.raw_stdout.splitlines():
        ip_match = _IP.search(line)
        if ip_match:
            current_ip = ip_match.group(1)
        sign_match = _SIGNING.search(line)
        if sign_match:
            state = _classify(sign_match.group(1))
            target_ip = ip_match.group(1) if ip_match else current_ip
            if state and target_ip:
                signing[target_ip] = state
    hosts = [Host(ip=ip, smb_signing=state) for ip, state in signing.items()]
    return ScanResult(hosts=hosts)
