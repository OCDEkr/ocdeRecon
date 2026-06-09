"""Color themes (PROJECT.md §14).

Default ``pentui`` is a blue-and-white light theme. ``pentui-cb`` is an optional
colour-blind-safe palette using the Okabe-Ito qualitative colours, which stay
distinguishable across the common forms of colour-vision deficiency.
"""

from __future__ import annotations

from typing import Any

from textual.app import App
from textual.theme import Theme

DEFAULT_THEME = "pentui"
COLORBLIND_THEME = "pentui-cb"

PENTUI = Theme(
    name=DEFAULT_THEME,
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

# Okabe-Ito colour-blind-safe palette.
PENTUI_CB = Theme(
    name=COLORBLIND_THEME,
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


def register_themes(app: App[Any]) -> None:
    app.register_theme(PENTUI)
    app.register_theme(PENTUI_CB)


def next_theme(current: str) -> str:
    return COLORBLIND_THEME if current == DEFAULT_THEME else DEFAULT_THEME
