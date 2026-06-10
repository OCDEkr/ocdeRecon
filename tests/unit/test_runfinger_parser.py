"""Tests for the RunFinger SMB-signing parser."""

from __future__ import annotations

from pentui.parsers.base import ParseContext
from pentui.parsers.runfinger import parse


def _ctx(stdout: str) -> ParseContext:
    return ParseContext(
        raw_stdout=stdout, raw_stderr="", artifact_path=None, scan_id=1, project_id=1
    )


def test_parses_bracketed_form():
    out = (
        "['192.168.1.10', Os:'Windows 10', Domain:'CORP', Signing:'False', Null Session:'True']\n"
        "['192.168.1.11', Os:'Windows Server 2019', Domain:'CORP', Signing:'True']\n"
    )
    result = parse(_ctx(out))
    signing = {h.ip: h.smb_signing for h in result.hosts}
    assert signing == {"192.168.1.10": "disabled", "192.168.1.11": "required"}


def test_parses_plain_inline_form():
    result = parse(_ctx("192.168.1.20, Signing: True\n192.168.1.21, Signing: False\n"))
    signing = {h.ip: h.smb_signing for h in result.hosts}
    assert signing == {"192.168.1.20": "required", "192.168.1.21": "disabled"}


def test_parses_multiline_form():
    out = "Retrieving information for 10.0.0.5...\nSMB signing: False\nNull Sessions: True\n"
    result = parse(_ctx(out))
    assert {h.ip: h.smb_signing for h in result.hosts} == {"10.0.0.5": "disabled"}


def test_ignores_uninterpretable_lines():
    out = "Starting RunFinger...\nVulnerable to MS17-010: NO\nDone.\n"
    assert parse(_ctx(out)).hosts == []
