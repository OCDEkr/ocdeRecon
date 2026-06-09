"""Parser for NetExec (nxc) LDAP output — domain-controller discovery (§6).

A host answering LDAP (tcp/389) is an Active Directory domain controller, and
nxc's identification line carries its hostname and domain, e.g.::

    LDAP  10.0.0.10  389  DC01  [*] Windows Server 2019 ... (name:DC01) (domain:corp.local)

This tags each such host ``is_dc=True`` (with its hostname) so downstream AD
steps can select ``is_dc: true``, and records the domain as an info Finding.
Lines without an identification banner are ignored. nxc may emit ANSI colour
codes, which are stripped first. Output format varies by nxc version; tune the
regexes against your install if a line isn't recognised.
"""

from __future__ import annotations

import re

from pentui.core.models import Finding, Host, ScanResult, Severity
from pentui.parsers.base import ParseContext

name = "nxc_ldap"

_ANSI = re.compile(r"\x1b\[[0-9;]*m")
_IP = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")
_NAME = re.compile(r"\(name:([^)]*)\)", re.IGNORECASE)
_DOMAIN = re.compile(r"\(domain:([^)]*)\)", re.IGNORECASE)


def parse(ctx: ParseContext) -> ScanResult:
    hosts: dict[str, Host] = {}
    findings: list[Finding] = []
    for raw in ctx.raw_stdout.splitlines():
        line = _ANSI.sub("", raw)
        name_match = _NAME.search(line)
        ip_match = _IP.search(line)
        # An identification banner (it has a (name:...)) on an LDAP responder = DC.
        if not name_match or not ip_match:
            continue
        ip = ip_match.group(1)
        hostname = name_match.group(1).strip() or None
        hosts[ip] = Host(ip=ip, hostname=hostname, is_dc=True)
        domain_match = _DOMAIN.search(line)
        domain = domain_match.group(1).strip() if domain_match else None
        title = f"Domain controller ({domain})" if domain else "Domain controller"
        findings.append(Finding(source_tool="nxc", severity=Severity.INFO, title=title, host_ip=ip))
    return ScanResult(hosts=list(hosts.values()), findings=findings)
