"""Tests for the sublist3r subdomain parser."""

from __future__ import annotations

from pathlib import Path

from pentui.parsers.base import ParseContext
from pentui.parsers.sublist3r import parse


def test_reads_subdomains_from_artifact_file(tmp_path: Path):
    out = tmp_path / "subdomains.txt"
    out.write_text("www.example.com\nmail.example.com\nwww.example.com\n")  # dup ignored
    ctx = ParseContext(
        raw_stdout="banner noise", raw_stderr="", artifact_path=str(out), scan_id=1, project_id=1
    )
    result = parse(ctx)
    # pseudo-hosts: ip == hostname so a downstream nmap can target them
    assert [(h.ip, h.hostname) for h in result.hosts] == [
        ("www.example.com", "www.example.com"),
        ("mail.example.com", "mail.example.com"),
    ]


def test_falls_back_to_stdout_and_filters_junk():
    ctx = ParseContext(
        raw_stdout="api.example.com\n[-] not a host\n   \nhttp://x\n",
        raw_stderr="",
        artifact_path=None,
        scan_id=1,
        project_id=1,
    )
    result = parse(ctx)
    assert [h.ip for h in result.hosts] == ["api.example.com"]
