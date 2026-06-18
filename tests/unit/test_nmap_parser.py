"""Tests for the nmap XML parser."""

from __future__ import annotations

from pathlib import Path

from pentui.core.models import Severity
from pentui.parsers import get_parser
from pentui.parsers.base import ParseContext
from pentui.parsers.nmap_xml import parse

FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "sample_nmap.xml"


def _ctx(artifact: str | None) -> ParseContext:
    return ParseContext(
        raw_stdout="", raw_stderr="", artifact_path=artifact, scan_id=1, project_id=1
    )


def test_registry_resolves_nmap_xml():
    assert get_parser("nmap_xml") is parse
    assert get_parser("nope") is None


def test_parses_hosts_ports_services():
    result = parse(_ctx(str(FIXTURE)))
    hosts = {h.ip: h for h in result.hosts}
    assert set(hosts) == {"10.0.0.1", "10.0.0.2", "10.0.0.3"}

    gw = hosts["10.0.0.1"]
    assert gw.hostname == "gw.example"
    assert gw.state == "up"

    ports = {p.number: p for p in gw.ports}
    assert set(ports) == {22, 443, 8080}
    assert ports[22].service.name == "ssh"
    assert ports[22].service.product == "OpenSSH"
    assert ports[22].service.version == "8.2p1"
    assert ports[22].service.cpe == "cpe:/a:openbsd:openssh:8.2p1"
    assert ports[8080].state == "closed"
    assert ports[8080].service is None

    # down host has no ports
    assert hosts["10.0.0.3"].ports == []


def test_nse_scripts_become_findings():
    result = parse(_ctx(str(FIXTURE)))
    titles = {f.title: f for f in result.findings}
    assert "ssh-hostkey on 22/tcp" in titles
    assert "smb-os-discovery" in titles  # host-level script, no port label
    finding = titles["ssh-hostkey on 22/tcp"]
    assert finding.source_tool == "nmap"
    assert finding.severity is Severity.INFO
    assert finding.host_ip == "10.0.0.1"
    assert finding.detail == "2048 aa:bb:cc"


def test_vuln_script_severity_is_normalized(tmp_path):
    # A port-level vuln script that reports VULNERABLE is raised above info.
    xml = tmp_path / "vuln.xml"
    xml.write_text(
        '<?xml version="1.0"?>\n'
        '<nmaprun><host><status state="up"/>'
        '<address addr="10.0.0.9" addrtype="ipv4"/>'
        '<ports><port protocol="tcp" portid="445"><state state="open"/>'
        '<script id="smb-vuln-ms17-010" output="State: VULNERABLE"/>'
        "</port></ports></host></nmaprun>\n"
    )
    result = parse(_ctx(str(xml)))
    finding = next(f for f in result.findings if "smb-vuln-ms17-010" in f.title)
    assert finding.severity is Severity.CRITICAL
    assert finding.host_ip == "10.0.0.9"


def test_missing_or_bad_artifact_returns_empty():
    assert parse(_ctx(None)).hosts == []
    assert parse(_ctx("/nonexistent/file.xml")).hosts == []
