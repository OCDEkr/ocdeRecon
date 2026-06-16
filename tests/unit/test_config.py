"""Scan output paths: per-engagement, per-tool, under a configurable root."""

from __future__ import annotations

from pathlib import Path

from pentui.config import AppConfig, target_slug


def _config(tmp_path: Path) -> AppConfig:
    config = AppConfig(data_dir=tmp_path / "data", config_dir=tmp_path / "config")
    config.ensure_dirs()
    return config


def test_target_slug_makes_filesystem_safe_labels():
    assert target_slug(["192.168.10.0/24"]) == "192.168.10.0_24"
    assert target_slug(["10.0.0.5"]) == "10.0.0.5"
    assert target_slug(["example.com"]) == "example.com"
    # several targets collapse to "first_and_N_more" so the name stays bounded
    assert target_slug(["10.0.0.0/24", "10.0.1.0/24", "10.0.2.0/24"]) == "10.0.0.0_24_and_2_more"
    # no targets -> empty, so the caller falls back to the scan id
    assert target_slug([]) == ""
    assert target_slug(["   "]) == ""


def test_scan_dir_leaf_names_folder_after_target(tmp_path):
    config = _config(tmp_path)
    leaf = target_slug(["192.168.10.0/24"])
    assert config.scan_dir("acme", 7, tool="nmap", leaf=leaf) == (
        config.engagement_dir("acme") / "scans" / "nmap" / "192.168.10.0_24"
    )


def test_scan_dir_leaf_collision_is_disambiguated_with_scan_id(tmp_path):
    config = _config(tmp_path)
    first = config.scan_dir("acme", 7, tool="nmap", leaf="192.168.10.0_24")
    first.mkdir(parents=True)  # a prior run already owns the clean name
    second = config.scan_dir("acme", 8, tool="nmap", leaf="192.168.10.0_24")
    assert second.name == "192.168.10.0_24-8"
    assert second != first


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


def test_engagement_exclude_file_lives_under_the_engagement_dir(tmp_path):
    config = _config(tmp_path)
    assert config.engagement_exclude_file("acme") == config.engagement_dir("acme") / "excludes.txt"


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


def test_output_root_override_wins_over_global_and_default(tmp_path):
    config = _config(tmp_path)
    config.set_output_root("/global/pentests")
    # A per-engagement override takes precedence over the global setting.
    assert config.scan_dir(
        "acme", 5, tool="nmap", output_root_override=Path("/eng/acme-out")
    ) == Path("/eng/acme-out/acme/scans/nmap/5")
    # None falls back to the global root (existing behavior).
    assert config.scan_dir("acme", 5, tool="nmap", output_root_override=None) == Path(
        "/global/pentests/acme/scans/nmap/5"
    )


def test_output_root_override_without_global_or_setting(tmp_path):
    config = _config(tmp_path)
    # No global output_root set: the override is the only root in play.
    assert config.scan_dir("acme", 1, tool="nmap", output_root_override=Path("/just/here")) == Path(
        "/just/here/acme/scans/nmap/1"
    )
