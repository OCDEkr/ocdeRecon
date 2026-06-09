"""Scan output paths: per-engagement, per-tool, under a configurable root."""

from __future__ import annotations

from pathlib import Path

from pentui.config import AppConfig


def _config(tmp_path: Path) -> AppConfig:
    config = AppConfig(data_dir=tmp_path / "data", config_dir=tmp_path / "config")
    config.ensure_dirs()
    return config


def test_scan_dir_default_groups_by_engagement_and_tool(tmp_path):
    config = _config(tmp_path)
    nmap = config.scan_dir("acme", 7, tool="nmap")
    masscan = config.scan_dir("acme", 7, tool="masscan")
    assert nmap == config.engagement_dir("acme") / "scans" / "nmap" / "7"
    assert masscan == config.engagement_dir("acme") / "scans" / "masscan" / "7"
    assert nmap != masscan


def test_scan_dir_without_tool_is_flat(tmp_path):
    config = _config(tmp_path)
    assert config.scan_dir("acme", 7) == config.engagement_dir("acme") / "scans" / "7"


def test_output_root_matches_the_pentests_layout(tmp_path):
    config = _config(tmp_path)
    config.set_output_root("/home/op/pentests")
    # <root>/<engagement>/scans/<tool>/<scan_id> — the same tool differs by engagement.
    assert config.scan_dir("engagement1", 3, tool="nmap") == Path(
        "/home/op/pentests/engagement1/scans/nmap/3"
    )
    assert config.scan_dir("engagement2", 7, tool="nmap") == Path(
        "/home/op/pentests/engagement2/scans/nmap/7"
    )
    # Different tools keep their own folders under the same engagement.
    assert config.scan_dir("engagement1", 3, tool="gowitness") == Path(
        "/home/op/pentests/engagement1/scans/gowitness/3"
    )


def test_output_root_expands_user(tmp_path):
    config = _config(tmp_path)
    config.set_output_root("~/pentests")
    assert config.scan_dir("acme", 1, tool="nmap") == (
        Path.home() / "pentests" / "acme" / "scans" / "nmap" / "1"
    )


def test_set_and_clear_output_root_round_trips(tmp_path):
    config = _config(tmp_path)
    assert config.output_root() is None
    config.set_output_root("  /data/pentests  ")  # trimmed
    assert config.output_root() == Path("/data/pentests")
    config.set_output_root("")  # cleared -> back to default
    assert config.output_root() is None
    assert config.scan_dir("acme", 1, tool="nmap") == (
        config.engagement_dir("acme") / "scans" / "nmap" / "1"
    )


def test_malformed_output_root_ignored(tmp_path):
    config = _config(tmp_path)
    config.save_settings({"output_root": 123})
    assert config.output_root() is None
