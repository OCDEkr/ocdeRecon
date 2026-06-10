"""Tests for the Nessus (.nessus / nessus_v2) parser."""

from __future__ import annotations

from pathlib import Path

from pentui.core.models import Severity
from pentui.parsers.base import ParseContext
from pentui.parsers.nessus import parse

SAMPLE_NESSUS = """<?xml version="1.0" ?>
<NessusClientData_v2>
  <Report name="pentui">
    <ReportHost name="10.0.0.50">
      <HostProperties>
        <tag name="host-ip">10.0.0.50</tag>
        <tag name="host-fqdn">web.corp.local</tag>
      </HostProperties>
      <ReportItem port="443" svc_name="www" protocol="tcp" severity="3"
                  pluginID="100" pluginName="TLS weak ciphers">
        <risk_factor>High</risk_factor>
        <synopsis>Weak TLS configuration.</synopsis>
        <description>The server supports weak ciphers.</description>
      </ReportItem>
      <ReportItem port="0" svc_name="general" protocol="tcp" severity="0"
                  pluginID="19506" pluginName="Scan info">
        <description>informational</description>
      </ReportItem>
    </ReportHost>
  </Report>
</NessusClientData_v2>
"""


def _ctx(path: Path) -> ParseContext:
    return ParseContext(
        raw_stdout="", raw_stderr="", artifact_path=str(path), scan_id=1, project_id=1
    )


def test_parses_hosts_ports_and_findings(tmp_path):
    f = tmp_path / "scan.nessus"
    f.write_text(SAMPLE_NESSUS)
    result = parse(_ctx(f))

    assert len(result.hosts) == 1
    host = result.hosts[0]
    assert host.ip == "10.0.0.50"
    assert host.hostname == "web.corp.local"
    # only the real port (443); the severity-0 port-0 item is not a port
    assert [(p.number, p.protocol) for p in host.ports] == [(443, "tcp")]
    assert host.ports[0].service.name == "www"

    # one finding, with a real mapped severity and the synopsis as detail
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.severity is Severity.HIGH
    assert finding.title == "TLS weak ciphers"
    assert finding.detail == "Weak TLS configuration."
    assert finding.source_tool == "nessus"
    assert finding.host_ip == "10.0.0.50"


def test_missing_or_bad_artifact_is_empty(tmp_path):
    assert (
        parse(
            ParseContext(raw_stdout="", raw_stderr="", artifact_path=None, scan_id=1, project_id=1)
        ).hosts
        == []
    )
    bad = tmp_path / "bad.nessus"
    bad.write_text("<not-nessus>")
    assert parse(_ctx(bad)).hosts == []
