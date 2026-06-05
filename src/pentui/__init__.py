"""pentui — a TUI for wrapping and automating offensive-security CLI tools.

See PROJECT.md for the full specification. The package is layered:

- ``pentui.core``         tool-agnostic engine (no Textual imports)
- ``pentui.parsers``      tool output -> normalized ScanResult
- ``pentui.persistence``  SQLite-per-engagement storage
- ``pentui.reporting``    Markdown/HTML/JSON/CSV exporters
- ``pentui.tui``          Textual UI (depends on core; core never depends on it)
"""

__version__ = "0.0.1"
