"""Model validation + persistence round-trip tests."""

from __future__ import annotations

from pentui.core.models import (
    Finding,
    Host,
    Port,
    Project,
    ScanStatus,
    Service,
    Severity,
)
from pentui.persistence import db
from pentui.persistence.repositories import ProjectRepository


def test_nested_host_model():
    host = Host(
        ip="10.0.0.5",
        ports=[Port(number=443, service=Service(name="https", product="nginx"))],
    )
    assert host.state == "up"
    assert host.ports[0].number == 443
    assert host.ports[0].service.name == "https"


def test_enum_defaults():
    assert Finding(source_tool="nmap", title="x").severity is Severity.UNKNOWN
    assert ScanStatus("running") is ScanStatus.RUNNING


def test_project_repository_round_trip(tmp_path):
    conn = db.init_db(tmp_path / "engagement.db")
    repo = ProjectRepository(conn)

    created = repo.create(Project(name="Acme Q3", client="Acme Corp"))
    assert created.id is not None
    assert created.created_at is not None

    fetched = repo.get(created.id)
    assert fetched is not None
    assert fetched.name == "Acme Q3"
    assert fetched.client == "Acme Corp"
    assert [p.id for p in repo.list()] == [created.id]
