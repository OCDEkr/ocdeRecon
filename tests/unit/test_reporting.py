"""Report gathering and export tests (Markdown/HTML/JSON/CSV)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from pentui.core.models import (
    GateState,
    Project,
    Scan,
    ScanStatus,
    ScopeKind,
    StepRun,
    WorkflowRun,
    WorkflowStatus,
)
from pentui.parsers.base import ParseContext
from pentui.parsers.nmap_xml import parse
from pentui.persistence import db
from pentui.persistence.repositories import (
    ProjectRepository,
    ScanRepository,
    ScopeRuleRepository,
    StepRunRepository,
    TargetRepository,
    WorkflowRunRepository,
)
from pentui.persistence.store import merge_scan_result
from pentui.reporting.exporter import ReportFormat, export, gather_report

FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "sample_nmap.xml"


@pytest.fixture
def conn(tmp_path):
    conn = db.init_db(tmp_path / "e.db")
    project = ProjectRepository(conn).create(Project(name="Acme Q3", client="Acme Corp"))
    pid = project.id
    ScopeRuleRepository(conn).create(pid, "10.0.0.0/24", ScopeKind.INCLUDE)
    TargetRepository(conn).create(pid, "10.0.0.0/24")

    scan = ScanRepository(conn).create(Scan(project_id=pid, tool="nmap", profile="Service scan"))
    scan.status = ScanStatus.DONE
    scan.exit_code = 0
    scan.command_str = "nmap -sV -sC -oX out.xml 10.0.0.0/24"
    ScanRepository(conn).update(scan)
    merge_scan_result(conn, pid, scan.id, parse(ParseContext("", "", str(FIXTURE), scan.id, pid)))

    run = WorkflowRunRepository(conn).create(
        WorkflowRun(project_id=pid, workflow_name="web-recon", status=WorkflowStatus.DONE)
    )
    StepRunRepository(conn).create(
        StepRun(workflow_run_id=run.id, step_id="discover", tool="nmap",
                status=ScanStatus.DONE, gate_state=GateState.AUTO)
    )
    return conn


def test_gather_report_counts(conn):
    data = gather_report(conn, 1)
    assert data.project.name == "Acme Q3"
    assert len(data.hosts) == 3
    assert data.open_port_count == 3
    assert len(data.findings) == 2
    assert data.includes == ["10.0.0.0/24"]
    assert len(data.workflow_runs) == 1
    assert data.workflow_runs[0].steps[0].step_id == "discover"


def test_export_markdown(conn, tmp_path):
    path = export(conn, 1, ReportFormat.MARKDOWN, tmp_path / "r.md")
    text = path.read_text()
    assert "Engagement Report — Acme Q3" in text
    assert "10.0.0.1" in text
    assert "web-recon" in text


def test_export_html(conn, tmp_path):
    text = export(conn, 1, ReportFormat.HTML, tmp_path / "r.html").read_text()
    assert "<!DOCTYPE html>" in text
    assert "10.0.0.1" in text


def test_export_json(conn, tmp_path):
    payload = json.loads(export(conn, 1, ReportFormat.JSON, tmp_path / "r.json").read_text())
    assert payload["project"]["name"] == "Acme Q3"
    assert payload["scope"]["include"] == ["10.0.0.0/24"]
    assert {h["ip"] for h in payload["hosts"]} == {"10.0.0.1", "10.0.0.2", "10.0.0.3"}
    assert len(payload["findings"]) == 2
    assert payload["workflow_runs"][0]["run"]["workflow_name"] == "web-recon"


def test_export_csv(conn, tmp_path):
    lines = export(conn, 1, ReportFormat.CSV, tmp_path / "r.csv").read_text().splitlines()
    assert lines[0] == "ip,hostname,state,port,protocol,port_state,service,product,version"
    rows = [line for line in lines if line.startswith("10.0.0.1,")]
    assert any(",22," in r and "ssh" in r for r in rows)
