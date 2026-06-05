"""Data-handoff query layer (PROJECT.md §7.2).

A small, SAFE, non-arbitrary selector over the unified model (no raw SQL, no
eval). A workflow step uses it to pick its inputs from upstream results — e.g.
"hosts with open ports 80/443 -> gowitness target URLs". Because every tool fills
the same Host/Port/Service/Finding model, any upstream tool can feed any
downstream one.

`where` conditions (combined with AND): ``host_state``, ``port_open_in``,
``service_name_in``, ``has_finding_severity``, ``hostname_matches``.
`as` materializers: ``targets`` (hostname or IP), ``target_urls`` (host+port ->
http(s) URL), ``ip_list`` (IP only).
"""

from __future__ import annotations

import re
import sqlite3
from enum import StrEnum

from pydantic import BaseModel, Field

from pentui.core.models import Host, Severity
from pentui.persistence.repositories import (
    FindingRepository,
    HostRepository,
    PortRepository,
)

#: Ports that imply TLS when building URLs.
_HTTPS_PORTS = {443, 8443}


class Materializer(StrEnum):
    TARGETS = "targets"
    TARGET_URLS = "target_urls"
    IP_LIST = "ip_list"


class WhereSpec(BaseModel):
    host_state: str | None = None
    port_open_in: list[int] = Field(default_factory=list)
    service_name_in: list[str] = Field(default_factory=list)
    has_finding_severity: Severity | None = None
    hostname_matches: str | None = None


class QuerySpec(BaseModel):
    from_: str = Field(default="hosts", alias="from")
    where: WhereSpec = Field(default_factory=WhereSpec)
    as_: Materializer = Field(default=Materializer.TARGETS, alias="as")

    model_config = {"populate_by_name": True}


def _open_ports(host: Host, numbers: list[int]) -> list[int]:
    wanted = set(numbers)
    return [
        p.number
        for p in host.ports
        if p.state == "open" and (not wanted or p.number in wanted)
    ]


def _matches(host: Host, where: WhereSpec, host_findings: set[Severity]) -> bool:
    if where.host_state is not None and host.state != where.host_state:
        return False
    if where.port_open_in and not _open_ports(host, where.port_open_in):
        return False
    if where.service_name_in:
        names = {p.service.name for p in host.ports if p.service and p.service.name}
        if names.isdisjoint(where.service_name_in):
            return False
    if where.has_finding_severity is not None and where.has_finding_severity not in host_findings:
        return False
    return not (
        where.hostname_matches is not None
        and (not host.hostname or not re.search(where.hostname_matches, host.hostname))
    )


def run_query(conn: sqlite3.Connection, project_id: int, query: QuerySpec) -> list[str]:
    """Evaluate ``query`` against the engagement DB, returning materialized targets."""
    if query.from_ != "hosts":
        raise ValueError(f"unsupported query source: {query.from_!r}")

    hosts = HostRepository(conn).list_for_project(project_id)
    ports_repo = PortRepository(conn)
    for host in hosts:
        assert host.id is not None
        host.ports = ports_repo.list_for_host(host.id)

    findings_by_host: dict[int | None, set[Severity]] = {}
    if query.where.has_finding_severity is not None:
        for finding in FindingRepository(conn).list_for_project(project_id):
            findings_by_host.setdefault(finding.host_id, set()).add(finding.severity)

    selected = [h for h in hosts if _matches(h, query.where, findings_by_host.get(h.id, set()))]
    return _materialize(selected, query)


def _materialize(hosts: list[Host], query: QuerySpec) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()

    def add(value: str) -> None:
        if value not in seen:
            seen.add(value)
            out.append(value)

    for host in hosts:
        if query.as_ is Materializer.IP_LIST:
            add(host.ip)
        elif query.as_ is Materializer.TARGETS:
            add(host.hostname or host.ip)
        else:  # TARGET_URLS
            authority = host.hostname or host.ip
            for number in _open_ports(host, query.where.port_open_in):
                scheme = "https" if number in _HTTPS_PORTS else "http"
                add(f"{scheme}://{authority}:{number}")
    return out
