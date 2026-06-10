"""Tests for the NetExec (nxc) SMB signing-sweep parser."""

from __future__ import annotations

from pentui.parsers.base import ParseContext
from pentui.parsers.nxc_smb import parse


def _ctx(stdout: str) -> ParseContext:
    return ParseContext(
        raw_stdout=stdout, raw_stderr="", artifact_path=None, scan_id=1, project_id=1
    )


def test_maps_signing_true_false_to_required_disabled():
    out = (
        "SMB  10.0.0.10  445  DC01  [*] Windows Server 2019 Build 17763 x64 "
        "(name:DC01) (domain:corp.local) (signing:True) (SMBv1:False)\n"
        "SMB  10.0.0.21  445  WS01  [*] Windows 10 / Server 2019 Build 19041 x64 "
        "(name:WS01) (domain:corp.local) (signing:False) (SMBv1:True)\n"
    )
    result = parse(_ctx(out))
    signing = {h.ip: h.smb_signing for h in result.hosts}
    assert signing == {"10.0.0.10": "required", "10.0.0.21": "disabled"}


def test_captures_hostname():
    out = "SMB  10.0.0.10  445  DC01  [*] Windows (name:DC01) (domain:corp.local) (signing:True)\n"
    host = parse(_ctx(out)).hosts[0]
    assert host.hostname == "DC01"


def test_strips_ansi_colour_codes():
    out = (
        "\x1b[1mSMB\x1b[0m  10.0.0.7  445  HOST  [*] Windows "
        "(name:HOST) (signing:\x1b[31mFalse\x1b[0m)\n"
    )
    # ANSI mid-token would break the regex if not stripped first.
    result = parse(_ctx(out))
    assert {h.ip: h.smb_signing for h in result.hosts} == {"10.0.0.7": "disabled"}


def test_smbv1_enabled_emits_low_finding():
    out = "SMB  10.0.0.21  445  WS01  [*] Windows (name:WS01) (signing:False) (SMBv1:True)\n"
    result = parse(_ctx(out))
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.title == "SMBv1 enabled"
    assert finding.host_ip == "10.0.0.21"
    assert finding.severity.value == "low"


def test_no_smbv1_finding_when_disabled():
    out = "SMB  10.0.0.10  445  DC01  [*] Windows (name:DC01) (signing:True) (SMBv1:False)\n"
    assert parse(_ctx(out)).findings == []


def test_ignores_lines_without_signing_token():
    out = "SMB  10.0.0.99  445  HOST  [-] Error: connection refused\nRunning nxc against 1 target\n"
    assert parse(_ctx(out)).hosts == []
