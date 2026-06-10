"""Parser for Nessus ``.nessus`` (nessus_v2 XML) exports (PROJECT.md §6).

Turns a Nessus scan export into the unified model: each ``ReportHost`` becomes a
Host (IP from ``host-ip``, hostname from ``host-fqdn``/netbios), each
``ReportItem`` with a real port becomes a Port (+service), and each item with a
severity becomes a Finding with a **real** severity mapped from Nessus's numeric
``severity`` (0–4). Tolerant of missing elements.
"""

from __future__ import annotations

from xml.etree import ElementTree as ET

from pentui.core.models import Finding, Host, Port, ScanResult, Service, Severity
from pentui.parsers.base import ParseContext

name = "nessus"

# Nessus numeric severity (0 Info .. 4 Critical) -> our Severity.
_SEVERITY = {
    0: Severity.INFO,
    1: Severity.LOW,
    2: Severity.MEDIUM,
    3: Severity.HIGH,
    4: Severity.CRITICAL,
}


def _host_props(report_host: ET.Element) -> dict[str, str]:
    props: dict[str, str] = {}
    for tag in report_host.findall("HostProperties/tag"):
        key = tag.get("name")
        if key and tag.text:
            props[key] = tag.text
    return props


def _text(item: ET.Element, *tags: str) -> str | None:
    for tag in tags:
        el = item.find(tag)
        if el is not None and el.text and el.text.strip():
            return el.text.strip()
    return None


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

    for report_host in root.findall("./Report/ReportHost"):
        name_attr = report_host.get("name") or ""
        props = _host_props(report_host)
        ip = props.get("host-ip") or name_attr
        if not ip:
            continue
        hostname = props.get("host-fqdn") or props.get("netbios-name")
        if hostname is None and name_attr and name_attr != ip:
            hostname = name_attr
        host = Host(ip=ip, hostname=hostname)

        seen_ports: set[tuple[int, str]] = set()
        for item in report_host.findall("ReportItem"):
            protocol = item.get("protocol", "tcp")
            try:
                port_no = int(item.get("port", "0"))
            except ValueError:
                port_no = 0
            if port_no > 0 and (port_no, protocol) not in seen_ports:
                seen_ports.add((port_no, protocol))
                svc_name = item.get("svc_name")
                host.ports.append(
                    Port(
                        number=port_no,
                        protocol=protocol,
                        state="open",
                        service=Service(name=svc_name) if svc_name else None,
                    )
                )
            try:
                severity = int(item.get("severity", "0"))
            except ValueError:
                severity = 0
            if severity >= 1:
                title = item.get("pluginName") or f"Nessus plugin {item.get('pluginID', '?')}"
                findings.append(
                    Finding(
                        source_tool="nessus",
                        severity=_SEVERITY.get(severity, Severity.UNKNOWN),
                        title=title,
                        detail=_text(item, "synopsis", "description", "plugin_output"),
                        host_ip=ip,
                    )
                )
        hosts.append(host)

    return ScanResult(hosts=hosts, findings=findings)
