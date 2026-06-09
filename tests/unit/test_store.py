"""Tests for repositories, result merge, and the engagement bridge."""

from __future__ import annotations

from pathlib import Path

from pentui.config import AppConfig
from pentui.core.models import Scan, ScanStatus
from pentui.parsers.base import ParseContext
from pentui.parsers.nmap_xml import parse
from pentui.persistence import db
from pentui.persistence.engagement import open_engagement
from pentui.persistence.repositories import (
    FindingRepository,
    HostRepository,
    PortRepository,
    ScanRepository,
)
from pentui.persistence.store import merge_scan_result

FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "sample_nmap.xml"


def _result():
    return parse(ParseContext("", "", str(FIXTURE), scan_id=1, project_id=1))


def test_open_engagement_creates_default_project(tmp_path):
    config = AppConfig(data_dir=tmp_path / "d", config_dir=tmp_path / "c")
    eng = open_engagement(config)
    assert eng.project_id == 1
    # Re-opening reuses the same project rather than creating another.
    eng2 = open_engagement(config)
    assert eng2.project_id == 1


def test_merge_populates_unified_model(tmp_path):
    conn = db.init_db(tmp_path / "e.db")
    project_id = 1
    conn.execute("INSERT INTO project (id, name) VALUES (1, 'p');")
    conn.commit()

    summary = merge_scan_result(conn, project_id, scan_id=None, result=_result())
    assert summary.hosts == 3
    assert summary.open_ports == 3  # 22, 443 (.1) + 80 (.2); 8080 is closed
    assert summary.services == 3  # ssh, https, http
    assert summary.findings == 2  # ssh-hostkey + smb-os-discovery

    hosts = {h.ip: h for h in HostRepository(conn).list_for_project(project_id)}
    gw = hosts["10.0.0.1"]
    ports = {p.number: p for p in PortRepository(conn).list_for_host(gw.id)}
    assert ports[22].service.product == "OpenSSH"
    assert ports[8080].service is None

    findings = FindingRepository(conn).list_for_project(project_id)
    assert {f.host_id for f in findings} == {gw.id}


def test_merge_is_idempotent_and_enriches(tmp_path):
    conn = db.init_db(tmp_path / "e.db")
    conn.execute("INSERT INTO project (id, name) VALUES (1, 'p');")
    conn.commit()

    merge_scan_result(conn, 1, None, _result())
    merge_scan_result(conn, 1, None, _result())  # second scan, same data

    # No duplicate hosts/ports thanks to dedupe constraints.
    assert conn.execute("SELECT COUNT(*) AS c FROM host;").fetchone()["c"] == 3
    assert conn.execute("SELECT COUNT(*) AS c FROM port;").fetchone()["c"] == 4


def test_scan_repository_lifecycle(tmp_path):
    conn = db.init_db(tmp_path / "e.db")
    conn.execute("INSERT INTO project (id, name) VALUES (1, 'p');")
    conn.commit()
    repo = ScanRepository(conn)

    scan = repo.create(Scan(project_id=1, tool="nmap", profile="Quick", args=["-F"]))
    assert scan.id is not None

    scan.status = ScanStatus.DONE
    scan.exit_code = 0
    repo.update(scan)
    row = conn.execute("SELECT status, exit_code FROM scan WHERE id = ?;", (scan.id,)).fetchone()
    assert row["status"] == "done"
    assert row["exit_code"] == 0
