"""Report gathering and export tests (Markdown/HTML/JSON/CSV/XML)."""

from __future__ import annotations

import json
import xml.etree.ElementTree as ET
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
from pentui.reporting.exporter import (
    ReportFormat,
    compute_stats,
    export,
    gather_report,
)

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
        StepRun(
            workflow_run_id=run.id,
            step_id="discover",
            tool="nmap",
            status=ScanStatus.DONE,
            gate_state=GateState.AUTO,
        )
    )
    return conn


@pytest.fixture
def conn_empty(tmp_path):
    conn = db.init_db(tmp_path / "empty.db")
    ProjectRepository(conn).create(Project(name="Empty", client=None))
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


def test_compute_stats(conn):
    stats = compute_stats(gather_report(conn, 1))
    assert stats.hosts == 3
    assert stats.open_ports == 3
    assert stats.findings == 2
    assert stats.scans == 1
    assert stats.workflow_runs == 1
    assert not stats.is_empty
    # one nmap scan, done
    assert len(stats.scans_by_tool) == 1
    entry = stats.scans_by_tool[0]
    assert entry.tool == "nmap"
    assert entry.total == 1
    assert entry.by_status.get("done") == 1
    # severity buckets only include non-zero counts and sum to the finding total
    assert sum(n for _, n in stats.findings_by_severity) == 2


def test_compute_stats_empty(conn_empty):
    stats = compute_stats(gather_report(conn_empty, 1))
    assert stats.is_empty
    assert stats.hosts == 0


def test_export_xml(conn, tmp_path):
    path = export(conn, 1, ReportFormat.XML, tmp_path / "r.xml")
    root = ET.parse(path).getroot()
    assert root.tag == "pentui_export"
    assert root.get("version") == "1"
    totals = root.find("stats/totals")
    assert totals is not None
    assert totals.get("hosts") == "3"
    assert totals.get("open_ports") == "3"
    ips = {h.get("ip") for h in root.findall("hosts/host")}
    assert ips == {"10.0.0.1", "10.0.0.2", "10.0.0.3"}
    assert len(root.findall("findings/finding")) == 2
    assert root.find("scans/scan").get("tool") == "nmap"
