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
from dataclasses import dataclass
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

    @property
    def extension(self) -> str:
        return {"markdown": "md", "html": "html", "json": "json", "csv": "csv"}[self.value]


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


_RENDERERS = {
    ReportFormat.MARKDOWN: render_markdown,
    ReportFormat.HTML: render_html,
    ReportFormat.JSON: render_json,
    ReportFormat.CSV: render_csv,
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
