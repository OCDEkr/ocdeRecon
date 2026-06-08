"""Tests for the data-handoff query layer."""

from __future__ import annotations

import pytest

from pentui.core.models import Finding, Host, Port, Service, Severity
from pentui.core.query import (
    Materializer,
    QuerySpec,
    WhereSpec,
    group_by_subnet,
    run_query,
)
from pentui.persistence import db
from pentui.persistence.repositories import (
    FindingRepository,
    HostRepository,
    PortRepository,
    ServiceRepository,
)


@pytest.fixture
def conn(tmp_path):
    conn = db.init_db(tmp_path / "e.db")
    conn.execute("INSERT INTO project (id, name) VALUES (1, 'p');")
    conn.commit()

    hosts = HostRepository(conn)
    ports = PortRepository(conn)
    services = ServiceRepository(conn)

    a = hosts.upsert(1, Host(ip="10.0.0.1", hostname="web1"))
    for number, name in [(80, "http"), (443, "https"), (22, "ssh")]:
        pid = ports.upsert(a, None, Port(number=number, state="open"))
        services.upsert(pid, Service(name=name))

    b = hosts.upsert(1, Host(ip="10.0.0.2"))
    pid = ports.upsert(b, None, Port(number=445, state="open"))
    services.upsert(pid, Service(name="microsoft-ds"))

    hosts.upsert(1, Host(ip="10.0.0.3", state="down"))

    FindingRepository(conn).create(
        Finding(project_id=1, host_id=b, source_tool="nmap",
                severity=Severity.HIGH, title="smb vuln")
    )
    return conn


def _q(**kwargs) -> QuerySpec:
    as_ = kwargs.pop("as_", Materializer.TARGETS)
    return QuerySpec(where=WhereSpec(**kwargs), **{"as": as_})


def test_port_open_in_selects_matching_hosts(conn):
    assert run_query(conn, 1, _q(port_open_in=[80, 443])) == ["web1"]


def test_target_urls_materializer(conn):
    urls = run_query(conn, 1, _q(port_open_in=[80, 443], as_=Materializer.TARGET_URLS))
    assert urls == ["http://web1:80", "https://web1:443"]


def test_ip_list_materializer(conn):
    assert run_query(conn, 1, _q(port_open_in=[80], as_=Materializer.IP_LIST)) == ["10.0.0.1"]


def test_service_name_in(conn):
    assert run_query(conn, 1, _q(service_name_in=["microsoft-ds"])) == ["10.0.0.2"]


def test_host_state_filter(conn):
    assert run_query(conn, 1, _q(host_state="down")) == ["10.0.0.3"]


def test_has_finding_severity(conn):
    assert run_query(conn, 1, _q(has_finding_severity=Severity.HIGH)) == ["10.0.0.2"]
    assert run_query(conn, 1, _q(has_finding_severity=Severity.CRITICAL)) == []


def test_hostname_matches(conn):
    assert run_query(conn, 1, _q(hostname_matches=r"^web")) == ["web1"]
    assert run_query(conn, 1, _q(hostname_matches=r"nope")) == []


def test_empty_where_returns_all_as_targets(conn):
    # hostname-or-ip for every host, deduped, in ip order
    assert run_query(conn, 1, _q()) == ["web1", "10.0.0.2", "10.0.0.3"]


def test_group_by_subnet():
    hosts = [Host(ip="10.0.1.5"), Host(ip="10.0.1.6"), Host(ip="10.0.2.7"), Host(ip="bad")]
    groups = dict(group_by_subnet(hosts, 24))
    assert set(groups) == {"10.0.1.0/24", "10.0.2.0/24"}  # non-IP host skipped
    assert [h.ip for h in groups["10.0.1.0/24"]] == ["10.0.1.5", "10.0.1.6"]
    assert [h.ip for h in groups["10.0.2.0/24"]] == ["10.0.2.7"]


def test_query_alias_parsing():
    spec = QuerySpec.model_validate(
        {"from": "hosts", "where": {"port_open_in": [80]}, "as": "target_urls"}
    )
    assert spec.from_ == "hosts"
    assert spec.as_ is Materializer.TARGET_URLS
