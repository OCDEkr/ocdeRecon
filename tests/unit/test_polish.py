"""Unit tests for Phase 6 polish: theme cycling, tool availability, settings."""

from __future__ import annotations

import sys

from pentui.config import AppConfig
from pentui.core.manifest import ToolManifest
from pentui.core.registry import tool_available
from pentui.tui.themes import COLORBLIND_THEME, DEFAULT_THEME, next_theme


def test_next_theme_cycles():
    assert next_theme(DEFAULT_THEME) == COLORBLIND_THEME
    assert next_theme(COLORBLIND_THEME) == DEFAULT_THEME


def test_tool_available_detects_present_and_missing():
    present = ToolManifest(name="py", binary=sys.executable)
    missing = ToolManifest(name="nope", binary="pentui-definitely-missing-xyz")
    assert tool_available(present) is True
    assert tool_available(missing) is False


def test_settings_round_trip(tmp_path):
    config = AppConfig(data_dir=tmp_path / "d", config_dir=tmp_path / "c")
    assert config.load_settings() == {}
    config.save_settings({"theme": COLORBLIND_THEME})
    assert config.load_settings()["theme"] == COLORBLIND_THEME
