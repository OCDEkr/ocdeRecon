"""Color themes (PROJECT.md §14).

Two independent axes:

* **mode** — ``dark`` (the default) or ``light``. F2 flips this.
* **palette** — ``standard`` (blue-and-white) or ``cb``, a colour-blind-safe
  Okabe-Ito accent palette that stays distinguishable across the common forms of
  colour-vision deficiency. Toggled from the Settings screen.

The two axes give four registered themes; :func:`resolve_theme` maps a
(mode, palette) pair to the registered theme name.
"""

from __future__ import annotations

from typing import Any, Literal

from textual.app import App
from textual.theme import Theme

ThemeMode = Literal["dark", "light"]
Palette = Literal["standard", "cb"]

DEFAULT_MODE: ThemeMode = "dark"
DEFAULT_PALETTE: Palette = "standard"

#: Registered theme name for each (mode, palette) pair.
_THEME_NAMES: dict[tuple[ThemeMode, Palette], str] = {
    ("dark", "standard"): "pentui-dark",
    ("light", "standard"): "pentui-light",
    ("dark", "cb"): "pentui-dark-cb",
    ("light", "cb"): "pentui-light-cb",
}

DEFAULT_THEME = _THEME_NAMES[(DEFAULT_MODE, DEFAULT_PALETTE)]

# --------------------------------------------------------------------------- #
# Standard blue-and-white palette
# --------------------------------------------------------------------------- #
PENTUI_DARK = Theme(
    name="pentui-dark",
    primary="#3b82f6",
    secondary="#60a5fa",
    accent="#38bdf8",
    foreground="#e2e8f0",
    background="#0f172a",
    surface="#1e293b",
    panel="#334155",
    success="#22c55e",
    warning="#f59e0b",
    error="#ef4444",
    dark=True,
)

PENTUI_LIGHT = Theme(
    name="pentui-light",
    primary="#1d4ed8",
    secondary="#2563eb",
    accent="#3b82f6",
    foreground="#0f172a",
    background="#ffffff",
    surface="#f1f5f9",
    panel="#e2e8f0",
    success="#15803d",
    warning="#b45309",
    error="#b91c1c",
    dark=False,
)

# --------------------------------------------------------------------------- #
# Okabe-Ito colour-blind-safe palette
# --------------------------------------------------------------------------- #
PENTUI_DARK_CB = Theme(
    name="pentui-dark-cb",
    primary="#56B4E9",  # sky blue (brighter for dark bg)
    secondary="#56B4E9",
    accent="#E69F00",  # orange
    foreground="#f0f0f0",
    background="#0f172a",
    surface="#1e293b",
    panel="#334155",
    success="#009E73",  # bluish green
    warning="#E69F00",  # orange
    error="#D55E00",  # vermillion
    dark=True,
)

PENTUI_LIGHT_CB = Theme(
    name="pentui-light-cb",
    primary="#0072B2",  # blue
    secondary="#56B4E9",  # sky blue
    accent="#E69F00",  # orange
    foreground="#000000",
    background="#ffffff",
    surface="#f0f0f0",
    panel="#e0e0e0",
    success="#009E73",  # bluish green
    warning="#E69F00",  # orange
    error="#D55E00",  # vermillion
    dark=False,
)

_THEMES = (PENTUI_DARK, PENTUI_LIGHT, PENTUI_DARK_CB, PENTUI_LIGHT_CB)


def register_themes(app: App[Any]) -> None:
    for theme in _THEMES:
        app.register_theme(theme)


def resolve_theme(mode: ThemeMode, palette: Palette) -> str:
    """Registered theme name for a (mode, palette) pair."""
    return _THEME_NAMES[(mode, palette)]


def flip_mode(mode: ThemeMode) -> ThemeMode:
    return "light" if mode == "dark" else "dark"


def flip_palette(palette: Palette) -> Palette:
    return "cb" if palette == "standard" else "standard"
