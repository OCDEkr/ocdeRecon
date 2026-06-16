"""Report generation from the engagement DB (PROJECT.md §12).

Gathers the engagement into a ``ReportData`` snapshot, then renders Markdown/HTML
(Jinja2, HTML self-contained), JSON (full dump), or CSV (host:port:service
inventory). Reports include scope, the activity window, the scans/commands run,
and workflow runs + steps for traceability.
"""

from __future__ import annotations

import csv
import io
import json
import sqlite3
import xml.etree.ElementTree as ET
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from pentui.core.models import (
    Finding,
    Host,
    Project,
    Scan,
    ScopeKind,
    Severity,
    StepRun,
    WorkflowRun,
)
from pentui.persistence.repositories import (
    FindingRepository,
    HostRepository,
    PortRepository,
    ProjectRepository,
    ScanRepository,
    ScopeRuleRepository,
    StepRunRepository,
    TargetRepository,
    WorkflowRunRepository,
)

_TEMPLATES = Path(__file__).resolve().parent / "templates"


class ReportFormat(StrEnum):
    MARKDOWN = "markdown"
    HTML = "html"
    JSON = "json"
    CSV = "csv"
    XML = "xml"

    @property
    def extension(self) -> str:
        return {
            "markdown": "md",
            "html": "html",
            "json": "json",
            "csv": "csv",
            "xml": "xml",
        }[self.value]


@dataclass(slots=True)
class WorkflowRunReport:
    run: WorkflowRun
    steps: list[StepRun]


@dataclass(slots=True)
class ReportData:
    project: Project
    generated_at: str
    includes: list[str]
    excludes: list[str]
    targets: list[str]
    hosts: list[Host]
    findings: list[Finding]
    scans: list[Scan]
    workflow_runs: list[WorkflowRunReport]
    date_start: str | None = None
    date_end: str | None = None

    @property
    def open_port_count(self) -> int:
        return sum(1 for h in self.hosts for p in h.ports if p.state == "open")


def gather_report(conn: sqlite3.Connection, project_id: int) -> ReportData:
    project = ProjectRepository(conn).get(project_id)
    if project is None:
        raise ValueError(f"no project {project_id}")

    rules = ScopeRuleRepository(conn).list_for_project(project_id)
    targets = [t.value for t in TargetRepository(conn).list_for_project(project_id)]

    hosts = HostRepository(conn).list_for_project(project_id)
    ports_repo = PortRepository(conn)
    ip_by_id: dict[int | None, str] = {}
    for host in hosts:
        assert host.id is not None
        host.ports = ports_repo.list_for_host(host.id)
        ip_by_id[host.id] = host.ip

    findings = FindingRepository(conn).list_for_project(project_id)
    for finding in findings:
        finding.host_ip = ip_by_id.get(finding.host_id)

    scans = sorted(
        ScanRepository(conn).list_recent(project_id, limit=1000), key=lambda s: s.id or 0
    )
    starts = [s.started_at for s in scans if s.started_at]
    ends = [s.finished_at for s in scans if s.finished_at]

    step_repo = StepRunRepository(conn)
    workflow_runs = [
        WorkflowRunReport(run=run, steps=step_repo.list_for_run(run.id or 0))
        for run in reversed(WorkflowRunRepository(conn).list_recent(project_id, limit=1000))
    ]

    return ReportData(
        project=project,
        generated_at=datetime.now().isoformat(timespec="seconds"),
        includes=[r.value for r in rules if r.kind is ScopeKind.INCLUDE],
        excludes=[r.value for r in rules if r.kind is ScopeKind.EXCLUDE],
        targets=targets,
        hosts=hosts,
        findings=findings,
        scans=scans,
        workflow_runs=workflow_runs,
        date_start=str(min(starts)) if starts else None,
        date_end=str(max(ends)) if ends else None,
    )


@dataclass(slots=True)
class ScanToolStats:
    """Per-tool scan counts: total plus a breakdown by status."""

    tool: str
    total: int
    by_status: dict[str, int] = field(default_factory=dict)


@dataclass(slots=True)
class EngagementStats:
    """Aggregates derived from a ``ReportData`` snapshot.

    UI-free; the single source of truth shared by the stats screen and the XML
    export so the on-screen numbers and the exported numbers can never drift.
    """

    hosts: int
    hosts_up: int
    open_ports: int
    services: int
    findings: int
    scans: int
    workflow_runs: int
    findings_by_severity: list[tuple[str, int]]  # ordered critical→…→unknown, zeros dropped
    findings_by_tool: list[tuple[str, int]]  # desc by count
    top_ports: list[tuple[int, str, int]]  # (number, protocol, host_count), desc
    top_services: list[tuple[str, int]]  # (service name, count), desc
    smb_signing: list[tuple[str, int]]  # (state, count) — required/disabled/unknown
    domain_controllers: list[tuple[str, str | None]]  # (ip, hostname)
    scans_by_tool: list[ScanToolStats]

    @property
    def is_empty(self) -> bool:
        return not (self.hosts or self.findings or self.scans or self.workflow_runs)


# Severity buckets shown highest-first; mirrors core.models.Severity.
_SEVERITY_ORDER = [
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.INFO,
    Severity.UNKNOWN,
]


def compute_stats(data: ReportData) -> EngagementStats:
    """Derive aggregate counts from a gathered ``ReportData`` (no DB access)."""
    hosts_up = sum(1 for h in data.hosts if h.state == "up")
    services = sum(1 for h in data.hosts for p in h.ports if p.service is not None)

    sev_counts = Counter(f.severity for f in data.findings)
    findings_by_severity = [
        (sev.value, sev_counts[sev]) for sev in _SEVERITY_ORDER if sev_counts[sev]
    ]

    tool_counts = Counter(f.source_tool for f in data.findings)
    findings_by_tool = tool_counts.most_common()

    port_counts: Counter[tuple[int, str]] = Counter()
    service_counts: Counter[str] = Counter()
    for host in data.hosts:
        for port in host.ports:
            if port.state == "open":
                port_counts[(port.number, port.protocol)] += 1
            if port.service is not None and port.service.name:
                service_counts[port.service.name] += 1
    top_ports = [(num, proto, count) for (num, proto), count in port_counts.most_common()]
    top_services = service_counts.most_common()

    signing_counts: Counter[str] = Counter(h.smb_signing or "unknown" for h in data.hosts)
    smb_signing = sorted(signing_counts.items(), key=lambda kv: (-kv[1], kv[0]))

    domain_controllers = [(h.ip, h.hostname) for h in data.hosts if h.is_dc]

    by_tool: dict[str, Counter[str]] = {}
    for scan in data.scans:
        by_tool.setdefault(scan.tool, Counter())[scan.status.value] += 1
    scans_by_tool = [
        ScanToolStats(tool=tool, total=sum(statuses.values()), by_status=dict(statuses))
        for tool, statuses in sorted(by_tool.items(), key=lambda kv: (-sum(kv[1].values()), kv[0]))
    ]

    return EngagementStats(
        hosts=len(data.hosts),
        hosts_up=hosts_up,
        open_ports=data.open_port_count,
        services=services,
        findings=len(data.findings),
        scans=len(data.scans),
        workflow_runs=len(data.workflow_runs),
        findings_by_severity=findings_by_severity,
        findings_by_tool=findings_by_tool,
        top_ports=top_ports,
        top_services=top_services,
        smb_signing=smb_signing,
        domain_controllers=domain_controllers,
        scans_by_tool=scans_by_tool,
    )


def _render_template(name: str, data: ReportData, *, autoescape: bool) -> str:
    env = Environment(
        loader=FileSystemLoader(str(_TEMPLATES)),
        autoescape=select_autoescape(["html"]) if autoescape else False,
        trim_blocks=False,
        lstrip_blocks=False,
    )
    template = env.get_template(name)
    return template.render(**_template_context(data))


def _template_context(data: ReportData) -> dict[str, object]:
    return {
        "project": data.project,
        "generated_at": data.generated_at,
        "includes": data.includes,
        "excludes": data.excludes,
        "targets": data.targets,
        "hosts": data.hosts,
        "findings": data.findings,
        "scans": data.scans,
        "workflow_runs": data.workflow_runs,
        "date_start": data.date_start,
        "date_end": data.date_end,
        "open_port_count": data.open_port_count,
    }


def render_markdown(data: ReportData) -> str:
    return _render_template("report.md.j2", data, autoescape=False)


def render_html(data: ReportData) -> str:
    return _render_template("report.html.j2", data, autoescape=True)


def render_json(data: ReportData) -> str:
    payload = {
        "project": data.project.model_dump(mode="json"),
        "generated_at": data.generated_at,
        "scope": {"include": data.includes, "exclude": data.excludes},
        "targets": data.targets,
        "activity_window": {"start": data.date_start, "end": data.date_end},
        "hosts": [h.model_dump(mode="json") for h in data.hosts],
        "findings": [
            f.model_dump(mode="json", exclude={"host_ip"}) | {"host_ip": f.host_ip}
            for f in data.findings
        ],
        "scans": [s.model_dump(mode="json") for s in data.scans],
        "workflow_runs": [
            {
                "run": wr.run.model_dump(mode="json"),
                "steps": [st.model_dump(mode="json") for st in wr.steps],
            }
            for wr in data.workflow_runs
        ],
    }
    return json.dumps(payload, indent=2)


def render_csv(data: ReportData) -> str:
    """Host:port:service inventory — one row per port (hosts without ports get one row)."""
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(
        [
            "ip",
            "hostname",
            "state",
            "port",
            "protocol",
            "port_state",
            "service",
            "product",
            "version",
        ]
    )
    for host in data.hosts:
        if not host.ports:
            writer.writerow([host.ip, host.hostname or "", host.state, "", "", "", "", "", ""])
            continue
        for port in host.ports:
            svc = port.service
            writer.writerow(
                [
                    host.ip,
                    host.hostname or "",
                    host.state,
                    port.number,
                    port.protocol,
                    port.state,
                    svc.name if svc else "",
                    svc.product if svc else "",
                    svc.version if svc else "",
                ]
            )
    return buf.getvalue()


def _set_attrs(elem: ET.Element, **attrs: object) -> None:
    """Set only the attributes whose value is not None/empty (keeps XML clean)."""
    for key, value in attrs.items():
        if value is None or value == "":
            continue
        if isinstance(value, bool):
            value = "true" if value else "false"
        elem.set(key, str(value))


def render_xml(data: ReportData) -> str:
    """Full data + computed stats as machine-readable XML for external dashboards."""
    stats = compute_stats(data)
    root = ET.Element("pentui_export", version="1", generated_at=data.generated_at)

    eng = ET.SubElement(root, "engagement")
    _set_attrs(eng, name=data.project.name, client=data.project.client)
    scope = ET.SubElement(eng, "scope")
    for value in data.includes:
        ET.SubElement(scope, "include").text = value
    for value in data.excludes:
        ET.SubElement(scope, "exclude").text = value
    targets_el = ET.SubElement(eng, "targets")
    for value in data.targets:
        ET.SubElement(targets_el, "target").text = value
    activity = ET.SubElement(eng, "activity")
    _set_attrs(activity, start=data.date_start, end=data.date_end)

    stats_el = ET.SubElement(root, "stats")
    totals = ET.SubElement(stats_el, "totals")
    _set_attrs(
        totals,
        hosts=stats.hosts,
        hosts_up=stats.hosts_up,
        open_ports=stats.open_ports,
        services=stats.services,
        findings=stats.findings,
        scans=stats.scans,
        workflow_runs=stats.workflow_runs,
    )
    sev_el = ET.SubElement(stats_el, "findings_by_severity")
    for level, count in stats.findings_by_severity:
        ET.SubElement(sev_el, "severity", level=level, count=str(count))
    ftool_el = ET.SubElement(stats_el, "findings_by_tool")
    for name, count in stats.findings_by_tool:
        ET.SubElement(ftool_el, "tool", name=name, count=str(count))
    ports_el = ET.SubElement(stats_el, "top_ports")
    for number, protocol, host_count in stats.top_ports:
        ET.SubElement(
            ports_el, "port", number=str(number), protocol=protocol, host_count=str(host_count)
        )
    svc_el = ET.SubElement(stats_el, "top_services")
    for name, count in stats.top_services:
        ET.SubElement(svc_el, "service", name=name, count=str(count))
    signing_el = ET.SubElement(stats_el, "smb_signing")
    for value, count in stats.smb_signing:
        ET.SubElement(signing_el, "state", value=value, count=str(count))
    dc_el = ET.SubElement(stats_el, "domain_controllers", count=str(len(stats.domain_controllers)))
    for ip, hostname in stats.domain_controllers:
        host_dc = ET.SubElement(dc_el, "host")
        _set_attrs(host_dc, ip=ip, hostname=hostname)
    stool_el = ET.SubElement(stats_el, "scans_by_tool")
    for entry in stats.scans_by_tool:
        tool_el = ET.SubElement(stool_el, "tool", name=entry.tool, total=str(entry.total))
        for status, count in entry.by_status.items():
            tool_el.set(status, str(count))

    hosts_el = ET.SubElement(root, "hosts")
    for host in data.hosts:
        host_el = ET.SubElement(hosts_el, "host")
        _set_attrs(
            host_el,
            ip=host.ip,
            hostname=host.hostname,
            state=host.state,
            smb_signing=host.smb_signing,
            is_dc=host.is_dc,
        )
        for port in host.ports:
            port_el = ET.SubElement(host_el, "port")
            _set_attrs(
                port_el,
                number=port.number,
                protocol=port.protocol,
                state=port.state,
                reason=port.reason,
            )
            if port.service is not None:
                svc = port.service
                svc_node = ET.SubElement(port_el, "service")
                _set_attrs(
                    svc_node,
                    name=svc.name,
                    product=svc.product,
                    version=svc.version,
                    cpe=svc.cpe,
                )

    findings_el = ET.SubElement(root, "findings")
    for finding in data.findings:
        f_el = ET.SubElement(findings_el, "finding")
        _set_attrs(
            f_el,
            host_ip=finding.host_ip,
            severity=finding.severity.value,
            source_tool=finding.source_tool,
            title=finding.title,
            created_at=finding.created_at,
        )
        if finding.detail:
            ET.SubElement(f_el, "detail").text = finding.detail

    scans_el = ET.SubElement(root, "scans")
    for scan in data.scans:
        scan_el = ET.SubElement(scans_el, "scan")
        _set_attrs(
            scan_el,
            id=scan.id,
            tool=scan.tool,
            profile=scan.profile,
            status=scan.status.value,
            exit_code=scan.exit_code,
            started_at=scan.started_at,
            finished_at=scan.finished_at,
        )

    ET.indent(root)
    body = ET.tostring(root, encoding="unicode")
    return '<?xml version="1.0" encoding="utf-8"?>\n' + body + "\n"


_RENDERERS = {
    ReportFormat.MARKDOWN: render_markdown,
    ReportFormat.HTML: render_html,
    ReportFormat.JSON: render_json,
    ReportFormat.CSV: render_csv,
    ReportFormat.XML: render_xml,
}


def export(
    conn: sqlite3.Connection, project_id: int, fmt: ReportFormat, out_path: str | Path
) -> Path:
    """Gather and write a report in ``fmt`` to ``out_path``. Returns the path."""
    data = gather_report(conn, project_id)
    text = _RENDERERS[fmt](data)
    path = Path(out_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path
