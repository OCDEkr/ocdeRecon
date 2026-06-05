"""Tool-agnostic engine.

IMPORTANT: nothing in ``pentui.core`` (or ``pentui.persistence``) may import
``textual``. The TUI depends on core; core never depends on the TUI. This keeps
the engine testable headless and reusable for future CLI / remote-agent modes.
"""
