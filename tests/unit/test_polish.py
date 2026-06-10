"""Unit tests for Phase 6 polish: theme cycling, tool availability, settings."""

from __future__ import annotations

import sys

from pentui.config import AppConfig
from pentui.core.manifest import ToolManifest
from pentui.core.registry import tool_available
from pentui.tui.themes import DEFAULT_THEME, flip_mode, flip_palette, resolve_theme


def test_default_theme_is_dark_standard():
    assert DEFAULT_THEME == "pentui-dark"
    assert resolve_theme("dark", "standard") == "pentui-dark"


def test_resolve_theme_covers_both_axes():
    assert resolve_theme("light", "standard") == "pentui-light"
    assert resolve_theme("dark", "cb") == "pentui-dark-cb"
    assert resolve_theme("light", "cb") == "pentui-light-cb"


def test_flip_helpers_toggle():
    assert flip_mode("dark") == "light"
    assert flip_mode("light") == "dark"
    assert flip_palette("standard") == "cb"
    assert flip_palette("cb") == "standard"


def test_tool_available_detects_present_and_missing():
    present = ToolManifest(name="py", binary=sys.executable)
    missing = ToolManifest(name="nope", binary="pentui-definitely-missing-xyz")
    assert tool_available(present) is True
    assert tool_available(missing) is False


def test_settings_round_trip(tmp_path):
    config = AppConfig(data_dir=tmp_path / "d", config_dir=tmp_path / "c")
    assert config.load_settings() == {}
    config.save_settings({"theme_mode": "light"})
    assert config.load_settings()["theme_mode"] == "light"


def test_theme_settings_defaults_and_round_trip(tmp_path):
    config = AppConfig(data_dir=tmp_path / "d", config_dir=tmp_path / "c")
    assert config.theme_mode() == "dark"  # default
    assert config.palette() == "standard"  # default
    config.set_theme_mode("light")
    config.set_palette("cb")
    assert config.theme_mode() == "light"
    assert config.palette() == "cb"
    config.set_theme_mode("dark")
    assert config.theme_mode() == "dark"
