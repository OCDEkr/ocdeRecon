"""Merge a parser's normalized ScanResult into an engagement DB (PROJECT.md §8).

Hosts are deduped by IP within the project; ports/services are enriched in place;
NSE-derived findings are linked back to their host via the transient
``Finding.host_ip`` the parser set.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass

from pentui.core.models import ScanResult
from pentui.persistence.repositories import (
    FindingRepository,
    HostRepository,
    PortRepository,
    ServiceRepository,
)


@dataclass(slots=True)
class MergeSummary:
    hosts: int = 0
    open_ports: int = 0
    services: int = 0
    findings: int = 0


def merge_scan_result(
    conn: sqlite3.Connection,
    project_id: int,
    scan_id: int | None,
    result: ScanResult,
) -> MergeSummary:
    hosts = HostRepository(conn)
    ports = PortRepository(conn)
    services = ServiceRepository(conn)
    findings = FindingRepository(conn)

    summary = MergeSummary()
    host_ids: dict[str, int] = {}

    for host in result.hosts:
        host_id = hosts.upsert(project_id, host)
        host_ids[host.ip] = host_id
        summary.hosts += 1
        for port in host.ports:
            port_id = ports.upsert(host_id, scan_id, port)
            if port.state == "open":
                summary.open_ports += 1
            if port.service is not None:
                services.upsert(port_id, port.service)
                summary.services += 1

    for finding in result.findings:
        finding.project_id = project_id
        finding.scan_id = scan_id
        finding.host_id = host_ids.get(finding.host_ip) if finding.host_ip else None
        findings.create(finding)
        summary.findings += 1

    return summary
