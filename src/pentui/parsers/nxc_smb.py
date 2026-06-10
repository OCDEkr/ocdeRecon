"""Parser for NetExec (nxc) SMB output — the unsigned-host signing sweep (§6).

``nxc smb <targets>`` prints one banner line per host even unauthenticated, and
that line carries the SMB signing state, hostname, domain and SMBv1 flag, e.g.::

    SMB  10.0.0.10  445  DC01  [*] Windows Server 2019 ... (name:DC01) (signing:True) (SMBv1:False)
    SMB  10.0.0.21  445  WS01  [*] Windows 10 ... (name:WS01) (signing:False) (SMBv1:True)

Hosts where signing is **not required** (``signing:False``) are NTLM-relay
targets, so this records each host's signing state on ``Host.smb_signing``
("required" | "disabled") — the same vocabulary ``runfinger`` uses, so the query
layer's ``smb_signing_in: ["disabled"]`` selects relay targets regardless of which
tool produced the data. SMBv1 being enabled is recorded as a LOW finding.

nxc emits ANSI colour codes, which are stripped first. Output format varies by nxc
version; tune the regexes against your install if a line isn't recognised. Lines
without an IP + signing token are ignored, so partial output still yields whatever
hosts were understood.
"""

from __future__ import annotations

import re

from pentui.core.models import Finding, Host, ScanResult, Severity
from pentui.parsers.base import ParseContext

name = "nxc_smb"

_ANSI = re.compile(r"\x1b\[[0-9;]*m")
_IP = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")
_NAME = re.compile(r"\(name:([^)]*)\)", re.IGNORECASE)
_SIGNING = re.compile(r"\(signing:\s*(true|false)\)", re.IGNORECASE)
_SMBV1 = re.compile(r"\(smbv1:\s*(true|false)\)", re.IGNORECASE)


def parse(ctx: ParseContext) -> ScanResult:
    hosts: dict[str, Host] = {}
    findings: list[Finding] = []
    for raw in ctx.raw_stdout.splitlines():
        line = _ANSI.sub("", raw)
        ip_match = _IP.search(line)
        sign_match = _SIGNING.search(line)
        # A signing token on a host line is the whole point; without it (and an IP)
        # there's nothing to record.
        if not ip_match or not sign_match:
            continue
        ip = ip_match.group(1)
        # signing:True = signing required (no relay); signing:False = disabled.
        signing = "required" if sign_match.group(1).lower() == "true" else "disabled"
        name_match = _NAME.search(line)
        hostname = name_match.group(1).strip() if name_match else None
        hosts[ip] = Host(ip=ip, hostname=hostname or None, smb_signing=signing)

        smbv1_match = _SMBV1.search(line)
        if smbv1_match and smbv1_match.group(1).lower() == "true":
            findings.append(
                Finding(
                    source_tool="nxc",
                    severity=Severity.LOW,
                    title="SMBv1 enabled",
                    host_ip=ip,
                )
            )
    return ScanResult(hosts=list(hosts.values()), findings=findings)
