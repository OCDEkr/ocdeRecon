"""Tests for the NetExec LDAP (domain-controller) parser."""

from __future__ import annotations

from pentui.parsers.base import ParseContext
from pentui.parsers.nxc_ldap import parse


def _ctx(stdout: str) -> ParseContext:
    return ParseContext(
        raw_stdout=stdout, raw_stderr="", artifact_path=None, scan_id=1, project_id=1
    )


def test_tags_dc_with_hostname_and_domain():
    out = (
        "LDAP  10.0.0.10  389  DC01  [*] Windows Server 2019 Build 17763 "
        "(name:DC01) (domain:corp.local) (signing:True)\n"
    )
    result = parse(_ctx(out))
    assert len(result.hosts) == 1
    host = result.hosts[0]
    assert host.ip == "10.0.0.10" and host.hostname == "DC01" and host.is_dc is True
    assert result.findings[0].host_ip == "10.0.0.10"
    assert "corp.local" in result.findings[0].title


def test_strips_ansi_colour_codes():
    out = "\x1b[1;34mLDAP\x1b[0m 10.0.0.20 389 AD2 [*] Win (name:AD2) (domain:lab.local)\n"
    result = parse(_ctx(out))
    assert result.hosts[0].ip == "10.0.0.20" and result.hosts[0].is_dc is True


def test_ignores_lines_without_identification_banner():
    out = "LDAP  10.0.0.30  389  [-] connection refused\nSMB  10.0.0.31  445  [*] no name here\n"
    # second line has no (name:...) -> not a DC identification
    assert parse(_ctx(out)).hosts == []
