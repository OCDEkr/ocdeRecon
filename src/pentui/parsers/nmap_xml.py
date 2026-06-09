"""Nmap XML parser (PROJECT.md §6, §13).

Parses nmap's ``-oX`` output into normalized hosts/ports/services, and maps NSE
script output (host- and port-level ``<script>`` elements) into low-fidelity
findings (severity ``info`` for the PoC; richer severity normalization is a later
phase). Tolerant of missing elements — partial/interrupted scans still parse.
"""

from __future__ import annotations

from xml.etree import ElementTree as ET

from pentui.core.models import Finding, Host, Port, ScanResult, Service, Severity
from pentui.parsers.base import ParseContext

name = "nmap_xml"


def _host_ip(host_el: ET.Element) -> str | None:
    addrs = host_el.findall("address")
    for addr in addrs:
        if addr.get("addrtype") in ("ipv4", "ipv6"):
            return addr.get("addr")
    return addrs[0].get("addr") if addrs else None


def _hostname(host_el: ET.Element) -> str | None:
    el = host_el.find("hostnames/hostname")
    return el.get("name") if el is not None else None


def _service(port_el: ET.Element) -> Service | None:
    svc = port_el.find("service")
    if svc is None:
        return None
    cpe = svc.find("cpe")
    return Service(
        name=svc.get("name"),
        product=svc.get("product"),
        version=svc.get("version"),
        extrainfo=svc.get("extrainfo"),
        cpe=cpe.text if cpe is not None else None,
    )


def _script_findings(
    parent: ET.Element, ip: str | None, *, port_label: str | None
) -> list[Finding]:
    findings: list[Finding] = []
    for script in parent.findall("script"):
        script_id = script.get("id") or "script"
        title = f"{script_id} on {port_label}" if port_label else script_id
        findings.append(
            Finding(
                source_tool="nmap",
                severity=Severity.INFO,
                title=title,
                detail=script.get("output"),
                host_ip=ip,
            )
        )
    return findings


def parse(ctx: ParseContext) -> ScanResult:
    if not ctx.artifact_path:
        return ScanResult()
    try:
        tree = ET.parse(ctx.artifact_path)
    except (OSError, ET.ParseError):
        return ScanResult()
    root = tree.getroot()

    hosts: list[Host] = []
    findings: list[Finding] = []

    for host_el in root.findall("host"):
        ip = _host_ip(host_el)
        if ip is None:
            continue
        status = host_el.find("status")
        host = Host(
            ip=ip,
            hostname=_hostname(host_el),
            state=status.get("state", "up") if status is not None else "up",
        )
        for port_el in host_el.findall("ports/port"):
            portid = port_el.get("portid")
            if portid is None:
                continue
            state_el = port_el.find("state")
            protocol = port_el.get("protocol", "tcp")
            host.ports.append(
                Port(
                    number=int(portid),
                    protocol=protocol,
                    state=state_el.get("state", "open") if state_el is not None else "open",
                    reason=state_el.get("reason") if state_el is not None else None,
                    service=_service(port_el),
                )
            )
            findings.extend(_script_findings(port_el, ip, port_label=f"{portid}/{protocol}"))
        hosts.append(host)

        hostscript = host_el.find("hostscript")
        if hostscript is not None:
            findings.extend(_script_findings(hostscript, ip, port_label=None))

    return ScanResult(hosts=hosts, findings=findings)
