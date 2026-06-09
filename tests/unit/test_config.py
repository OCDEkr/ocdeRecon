"""Per-tool, per-engagement scan output paths and overrides."""

from __future__ import annotations

from pathlib import Path

from pentui.config import AppConfig


def _config(tmp_path: Path) -> AppConfig:
    config = AppConfig(data_dir=tmp_path / "data", config_dir=tmp_path / "config")
    config.ensure_dirs()
    return config


def test_scan_dir_groups_by_tool_per_engagement(tmp_path):
    config = _config(tmp_path)
    nmap = config.scan_dir("acme", 7, tool="nmap")
    masscan = config.scan_dir("acme", 7, tool="masscan")
    # Each tool gets its own folder under the engagement; different tools,
    # different dirs (even with the same scan id).
    assert nmap == config.engagement_dir("acme") / "scans" / "nmap" / "7"
    assert masscan == config.engagement_dir("acme") / "scans" / "masscan" / "7"
    assert nmap != masscan


def test_scan_dir_without_tool_is_flat(tmp_path):
    config = _config(tmp_path)
    assert config.scan_dir("acme", 7) == config.engagement_dir("acme") / "scans" / "7"


def test_tool_output_override_relocates_per_engagement(tmp_path):
    config = _config(tmp_path)
    config.set_tool_output_dir("nmap", "/mnt/evidence/nmap")
    # Overridden tool: rooted at the custom base, still namespaced per engagement.
    assert config.scan_dir("acme", 7, tool="nmap") == Path("/mnt/evidence/nmap/acme/7")
    assert config.scan_dir("globex", 9, tool="nmap") == Path("/mnt/evidence/nmap/globex/9")
    # A tool without an override keeps the default per-tool layout.
    assert config.scan_dir("acme", 7, tool="masscan") == (
        config.engagement_dir("acme") / "scans" / "masscan" / "7"
    )


def test_override_expands_user(tmp_path):
    config = _config(tmp_path)
    config.set_tool_output_dir("gowitness", "~/shots")
    assert config.scan_dir("acme", 1, tool="gowitness") == Path.home() / "shots" / "acme" / "1"


def test_set_and_clear_override_round_trips(tmp_path):
    config = _config(tmp_path)
    config.set_tool_output_dir("nmap", "/data/nmap")
    assert config.tool_output_dirs() == {"nmap": "/data/nmap"}
    # Whitespace is trimmed; blank clears the entry.
    config.set_tool_output_dir("masscan", "  /data/masscan  ")
    assert config.tool_output_dirs()["masscan"] == "/data/masscan"
    config.set_tool_output_dir("nmap", "")
    assert "nmap" not in config.tool_output_dirs()
    config.set_tool_output_dir("masscan", None)
    assert config.tool_output_dirs() == {}


def test_malformed_settings_ignored(tmp_path):
    config = _config(tmp_path)
    config.save_settings({"tool_output_dirs": {"nmap": 123, "ok": "/data/ok", "blank": ""}})
    # Non-string and empty values are dropped; valid ones survive.
    assert config.tool_output_dirs() == {"ok": "/data/ok"}
